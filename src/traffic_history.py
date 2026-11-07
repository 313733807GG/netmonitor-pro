# -*- coding: utf-8 -*-
"""Persistent, low-overhead traffic attribution for NetMonitor.

Mihomo exposes cumulative byte counters for every active connection.  The UI
poller converts those counters to deltas and hands only non-zero deltas to this
module.  A dedicated writer thread aggregates them into minute and hour
buckets so the GUI thread never waits for SQLite I/O.
"""

from __future__ import annotations

import csv
import hashlib
import os
import queue
import re
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path


DEFAULT_MINUTE_RETENTION_DAYS = 30
DEFAULT_SUMMARY_RETENTION_DAYS = 365
DEFAULT_ANOMALY_MIB = 100

_MULTIPLIER_PATTERNS = (
    re.compile(r"(?<![\d.])(\d+(?:\.\d+)?)\s*倍(?:消耗|流量)?", re.IGNORECASE),
    re.compile(r"(?:倍率|ratio)\s*[:=：]?\s*(\d+(?:\.\d+)?)", re.IGNORECASE),
    re.compile(r"(?:×|x)\s*(\d+(?:\.\d+)?)", re.IGNORECASE),
    re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)\s*(?:×|x)(?!\w)", re.IGNORECASE),
)


def parse_traffic_multiplier(*labels):
    """Return an explicit traffic multiplier found in a group/node label.

    The final node label should be passed first because a leaf node's explicit
    multiplier is more specific than a parent policy-group label.  Values are
    bounded to reject corrupt labels while still supporting low-multiplier
    nodes such as ``0.2 倍``.
    """

    for label in labels:
        text = str(label or "")
        for index, pattern in enumerate(_MULTIPLIER_PATTERNS):
            match = pattern.search(text)
            if not match:
                continue
            try:
                value = float(match.group(1))
            except (TypeError, ValueError):
                continue
            # Bare x-notation is convenient ("香港 x2") but architecture
            # labels such as x64 must never become a 64x billing estimate.
            if index >= 2 and value > 20:
                continue
            if 0.01 <= value <= 100:
                return value
    return 1.0


def estimated_billed_bytes(actual_bytes, route_kind, multiplier):
    """Estimate provider quota consumption; DIRECT/REJECT consume no node quota."""

    if str(route_kind or "").lower() != "proxy":
        return 0.0
    return max(float(actual_bytes or 0), 0.0) * max(float(multiplier or 1), 0.0)


def default_history_directory():
    override = os.environ.get("NETMONITOR_HISTORY_DIR")
    if override:
        return os.path.abspath(os.path.expandvars(override))
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = os.path.join(os.path.expanduser("~"), "AppData", "Local")
    return os.path.join(base, "NetMonitorPro", "traffic-history")


def _clean_text(value, limit=2048):
    text = str(value or "").replace("\x00", "")
    return text[:limit]


def _safe_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(value):
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _dimension_key(sample):
    fields = (
        sample["process_pid"], sample["process_name"], sample["process_path"],
        f"{sample['process_start_time']:.6f}", sample["traffic_role"],
        sample["source_ip"], sample["destination_host"], sample["destination_ip"],
        sample["destination_port"], sample["network"], sample["rule"],
        sample["rule_payload"], sample["route_kind"], sample["route_group"],
        sample["exit_node"], f"{sample['multiplier']:.6f}", sample["chain"],
    )
    payload = "\x1f".join(map(str, fields)).encode("utf-8", "surrogatepass")
    return hashlib.sha256(payload).hexdigest()


def normalize_sample(sample, observed_at=None):
    """Normalize an application sample into the stable on-disk schema."""

    route_kind = _clean_text(sample.get("route_kind", "unknown"), 16).lower()
    if route_kind not in ("proxy", "direct", "reject", "unknown"):
        route_kind = "unknown"
    upload = max(_safe_int(sample.get("upload_bytes")), 0)
    download = max(_safe_int(sample.get("download_bytes")), 0)
    multiplier = max(float(sample.get("multiplier") or 1.0), 0.0)
    traffic_role = _clean_text(sample.get("traffic_role", "user"), 32).lower()
    if traffic_role not in ("user", "health_check"):
        traffic_role = "user"
    owner_confidence = _clean_text(
        sample.get("owner_confidence", "unknown"), 16,
    ).lower()
    if owner_confidence not in ("high", "medium", "low", "unknown"):
        owner_confidence = "unknown"
    normalized = {
        "observed_at": int(observed_at if observed_at is not None else time.time()),
        "connection_id": _clean_text(sample.get("connection_id"), 128),
        "process_pid": max(_safe_int(sample.get("process_pid")), 0),
        "process_name": _clean_text(sample.get("process_name"), 512),
        "process_path": _clean_text(sample.get("process_path")),
        "process_start_time": max(_safe_float(sample.get("process_start_time")), 0.0),
        "source_ip": _clean_text(sample.get("source_ip"), 128),
        "source_port": max(_safe_int(sample.get("source_port")), 0),
        "destination_host": _clean_text(sample.get("destination_host"), 1024),
        "destination_ip": _clean_text(sample.get("destination_ip"), 128),
        "destination_port": max(_safe_int(sample.get("destination_port")), 0),
        "network": _clean_text(sample.get("network"), 32).lower(),
        "rule": _clean_text(sample.get("rule"), 512),
        "rule_payload": _clean_text(sample.get("rule_payload"), 1024),
        "route_kind": route_kind,
        "route_group": _clean_text(sample.get("route_group"), 1024),
        "exit_node": _clean_text(sample.get("exit_node"), 1024),
        "multiplier": multiplier,
        "chain": _clean_text(sample.get("chain")),
        "owner_source": _clean_text(sample.get("owner_source", "unknown"), 64),
        "owner_confidence": owner_confidence,
        "traffic_role": traffic_role,
        "upload_bytes": upload,
        "download_bytes": download,
    }
    normalized["estimated_billed_bytes"] = estimated_billed_bytes(
        upload + download, route_kind, multiplier,
    )
    normalized["dimension_key"] = _dimension_key(normalized)
    return normalized


class TrafficHistoryStore:
    """Background SQLite writer for minute/hour attribution and anomaly events."""

    SCHEMA_VERSION = 2
    WRITE_INTERVAL = 10.0
    MAX_PENDING_RECORDS = 10000

    def __init__(
        self,
        db_path=None,
        minute_retention_days=DEFAULT_MINUTE_RETENTION_DAYS,
        summary_retention_days=DEFAULT_SUMMARY_RETENTION_DAYS,
        anomaly_mib=DEFAULT_ANOMALY_MIB,
        write_interval=WRITE_INTERVAL,
    ):
        directory = default_history_directory() if db_path is None else os.path.dirname(os.path.abspath(db_path))
        self.directory = directory
        self.db_path = db_path or os.path.join(directory, "traffic_history.sqlite3")
        self.minute_retention_days = max(int(minute_retention_days), 1)
        self.summary_retention_days = max(int(summary_retention_days), self.minute_retention_days)
        self.anomaly_bytes = max(float(anomaly_mib), 1.0) * (1 << 20)
        self.write_interval = max(float(write_interval), 0.01)
        self.status = "starting"
        self.last_error = ""
        self.dropped_batches = 0
        self._items = queue.Queue(maxsize=512)
        self._ready = threading.Event()
        self._state_lock = threading.Lock()
        self._closed = False
        self._paused = False
        self._thread = threading.Thread(
            target=self._writer_main,
            name="NetMonitorTrafficHistory",
            daemon=True,
        )
        self._thread.start()
        # Schema creation is normally a few milliseconds.  Waiting briefly
        # makes startup status and tests deterministic without tying future I/O
        # to the GUI thread.
        self._ready.wait(2.0)

    @property
    def running(self):
        return self.status == "running" and not self._closed

    @property
    def paused(self):
        return self._paused

    def record(self, samples, observed_at=None):
        with self._state_lock:
            if self._closed or self._paused or self.status == "error" or not samples:
                return False
        stamp = observed_at if observed_at is not None else time.time()
        normalized = []
        try:
            for sample in samples:
                row = normalize_sample(sample, stamp)
                if row["upload_bytes"] or row["download_bytes"]:
                    normalized.append(row)
        except Exception as exc:
            self.last_error = f"样本格式错误: {exc}"
            return False
        with self._state_lock:
            if self._closed or self._paused or self.status == "error":
                return False
            if not normalized:
                return True
            try:
                self._items.put_nowait(("records", normalized))
                return True
            except queue.Full:
                self.dropped_batches += 1
                self.last_error = "写入队列已满，已丢弃一个采样批次"
                return False

    def pause(self, timeout=5.0):
        with self._state_lock:
            if self._closed or self.status == "error":
                return False
            if self._paused:
                return True
            self._paused = True
        if self.flush(timeout):
            return True
        with self._state_lock:
            self.last_error = "已停止新入账，但暂停前队列未能全部确认落盘"
        return False

    def resume(self):
        with self._state_lock:
            if self._closed or self.status == "error":
                return False
            self._paused = False
            return True

    def flush(self, timeout=5.0):
        if self._closed or self.status == "error":
            return False
        marker = threading.Event()
        try:
            self._items.put(("flush", marker), timeout=max(timeout, 0.1))
        except queue.Full:
            return False
        return marker.wait(timeout)

    def close(self, timeout=8.0):
        if self._closed:
            return
        self.flush(min(timeout / 2, 4.0))
        self._closed = True
        try:
            self._items.put(("stop", None), timeout=1.0)
        except queue.Full:
            pass
        self._thread.join(timeout)

    def export_csv(self, hours=24):
        """Export traffic buckets plus matching anomalies and return both paths.

        Requests inside the minute-retention window use the minute ledger.  A
        longer request automatically switches to the compact hourly ledger so
        up to a year of history remains practical to export.
        """

        self.flush(5.0)
        if not os.path.isfile(self.db_path):
            raise RuntimeError(self.last_error or "流量账本尚未建立")
        Path(self.directory).mkdir(parents=True, exist_ok=True)
        suffix = time.strftime("%Y%m%d_%H%M%S")
        requested_hours = max(float(hours), 1.0)
        use_hourly = requested_hours > self.minute_retention_days * 24
        table = "traffic_hour" if use_hourly else "traffic_minute"
        resolution = "hour" if use_hourly else "minute"
        span = (f"{int(requested_hours / 24)}d"
                if requested_hours >= 48 else f"{int(requested_hours)}h")
        detail_path = os.path.join(
            self.directory, f"traffic_{span}_{resolution}_{suffix}.csv",
        )
        alert_path = os.path.join(
            self.directory, f"traffic_alerts_{span}_{suffix}.csv",
        )
        cutoff = int(time.time() - requested_hours * 3600)
        with closing(sqlite3.connect(
            f"file:{self.db_path}?mode=ro", uri=True, timeout=10,
        )) as conn:
            self._write_query_csv(
                conn,
                detail_path,
                f"""
                SELECT datetime(bucket_start, 'unixepoch', 'localtime') AS period,
                       process_pid, process_name, process_path,
                       source_port, process_start_time,
                       CASE WHEN process_start_time > 0
                            THEN datetime(process_start_time, 'unixepoch', 'localtime')
                            ELSE '' END AS process_started,
                       owner_source, owner_confidence, traffic_role,
                       destination_host, destination_ip, destination_port, network,
                       rule, rule_payload, route_kind, route_group, exit_node,
                       multiplier, upload_bytes, download_bytes,
                       ROUND((upload_bytes + download_bytes) / 1048576.0, 3) AS actual_mib,
                       ROUND(estimated_billed_bytes / 1048576.0, 3) AS billed_mib,
                       sample_count,
                       datetime(first_seen, 'unixepoch', 'localtime') AS first_seen,
                       datetime(last_seen, 'unixepoch', 'localtime') AS last_seen,
                       chain
                  FROM {table}
                 WHERE bucket_start >= ?
                 ORDER BY bucket_start DESC, estimated_billed_bytes DESC,
                          upload_bytes + download_bytes DESC
                """,
                (cutoff,),
            )
            self._write_query_csv(
                conn,
                alert_path,
                """
                SELECT datetime(bucket_start, 'unixepoch', 'localtime') AS minute,
                       process_pid, process_name, process_path,
                       source_port, process_start_time,
                       CASE WHEN process_start_time > 0
                            THEN datetime(process_start_time, 'unixepoch', 'localtime')
                            ELSE '' END AS process_started,
                       owner_source, owner_confidence, traffic_role,
                       destination_host, destination_ip, destination_port,
                       rule, rule_payload, route_group, exit_node, multiplier,
                       ROUND((upload_bytes + download_bytes) / 1048576.0, 3) AS actual_mib,
                       ROUND(estimated_billed_bytes / 1048576.0, 3) AS billed_mib,
                       ROUND(threshold_bytes / 1048576.0, 3) AS threshold_mib,
                       datetime(first_seen, 'unixepoch', 'localtime') AS first_seen,
                       datetime(last_seen, 'unixepoch', 'localtime') AS last_seen,
                       chain
                  FROM traffic_alerts
                 WHERE bucket_start >= ?
                 ORDER BY bucket_start DESC, estimated_billed_bytes DESC
                """,
                (cutoff,),
            )
        return detail_path, alert_path

    @staticmethod
    def _write_query_csv(conn, path, sql, params):
        cursor = conn.execute(sql, params)
        with open(path, "w", newline="", encoding="utf-8-sig") as stream:
            writer = csv.writer(stream)
            writer.writerow([column[0] for column in cursor.description])
            writer.writerows(cursor)

    def _writer_main(self):
        conn = None
        try:
            Path(self.directory).mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=15)
            conn.execute("PRAGMA busy_timeout=15000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA wal_autocheckpoint=1000")
            self._init_schema(conn)
            self._cleanup(conn)
            self.status = "running"
            self._ready.set()
            pending = []
            write_after = None

            def write_pending():
                nonlocal pending, write_after
                if pending:
                    self._write_records(conn, pending)
                    pending = []
                write_after = None

            while True:
                timeout = None if write_after is None else max(0.0, write_after - time.monotonic())
                try:
                    action, payload = self._items.get(timeout=timeout)
                except queue.Empty:
                    write_pending()
                    continue
                try:
                    if action == "stop":
                        write_pending()
                        break
                    if action == "flush":
                        write_pending()
                        conn.commit()
                        payload.set()
                        continue
                    if action == "records":
                        pending.extend(payload)
                        if write_after is None:
                            write_after = time.monotonic() + self.write_interval
                        if (len(pending) >= self.MAX_PENDING_RECORDS
                                or time.monotonic() >= write_after):
                            write_pending()
                finally:
                    self._items.task_done()
        except Exception as exc:
            self.status = "error"
            self.last_error = str(exc)
            self._ready.set()
        finally:
            if conn is not None:
                try:
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
            if self.status != "error":
                self.status = "closed"

    def _init_schema(self, conn):
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS traffic_minute (
                bucket_start INTEGER NOT NULL,
                dimension_key TEXT NOT NULL,
                connection_id TEXT NOT NULL,
                process_pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                process_path TEXT NOT NULL,
                process_start_time REAL NOT NULL DEFAULT 0,
                source_ip TEXT NOT NULL,
                source_port INTEGER NOT NULL DEFAULT 0,
                destination_host TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER NOT NULL,
                network TEXT NOT NULL,
                rule TEXT NOT NULL,
                rule_payload TEXT NOT NULL,
                route_kind TEXT NOT NULL,
                route_group TEXT NOT NULL,
                exit_node TEXT NOT NULL,
                multiplier REAL NOT NULL,
                chain TEXT NOT NULL,
                owner_source TEXT NOT NULL DEFAULT 'unknown',
                owner_confidence TEXT NOT NULL DEFAULT 'unknown',
                traffic_role TEXT NOT NULL DEFAULT 'user',
                upload_bytes INTEGER NOT NULL,
                download_bytes INTEGER NOT NULL,
                estimated_billed_bytes REAL NOT NULL,
                sample_count INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (bucket_start, dimension_key)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS traffic_hour (
                bucket_start INTEGER NOT NULL,
                dimension_key TEXT NOT NULL,
                process_pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                process_path TEXT NOT NULL,
                process_start_time REAL NOT NULL DEFAULT 0,
                source_port INTEGER NOT NULL DEFAULT 0,
                destination_host TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER NOT NULL,
                network TEXT NOT NULL,
                rule TEXT NOT NULL,
                rule_payload TEXT NOT NULL,
                route_kind TEXT NOT NULL,
                route_group TEXT NOT NULL,
                exit_node TEXT NOT NULL,
                multiplier REAL NOT NULL,
                chain TEXT NOT NULL,
                owner_source TEXT NOT NULL DEFAULT 'unknown',
                owner_confidence TEXT NOT NULL DEFAULT 'unknown',
                traffic_role TEXT NOT NULL DEFAULT 'user',
                upload_bytes INTEGER NOT NULL,
                download_bytes INTEGER NOT NULL,
                estimated_billed_bytes REAL NOT NULL,
                sample_count INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (bucket_start, dimension_key)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS traffic_alerts (
                bucket_start INTEGER NOT NULL,
                dimension_key TEXT NOT NULL,
                process_pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                process_path TEXT NOT NULL,
                process_start_time REAL NOT NULL DEFAULT 0,
                source_port INTEGER NOT NULL DEFAULT 0,
                destination_host TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER NOT NULL,
                rule TEXT NOT NULL,
                rule_payload TEXT NOT NULL,
                route_group TEXT NOT NULL,
                exit_node TEXT NOT NULL,
                multiplier REAL NOT NULL,
                chain TEXT NOT NULL,
                owner_source TEXT NOT NULL DEFAULT 'unknown',
                owner_confidence TEXT NOT NULL DEFAULT 'unknown',
                traffic_role TEXT NOT NULL DEFAULT 'user',
                upload_bytes INTEGER NOT NULL,
                download_bytes INTEGER NOT NULL,
                estimated_billed_bytes REAL NOT NULL,
                threshold_bytes REAL NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (bucket_start, dimension_key)
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_minute_last_seen
                ON traffic_minute(last_seen);
            CREATE INDEX IF NOT EXISTS idx_hour_last_seen
                ON traffic_hour(last_seen);
            CREATE INDEX IF NOT EXISTS idx_alerts_last_seen
                ON traffic_alerts(last_seen);
            """
        )
        migrations = {
            "process_start_time": "REAL NOT NULL DEFAULT 0",
            "source_port": "INTEGER NOT NULL DEFAULT 0",
            "owner_source": "TEXT NOT NULL DEFAULT 'unknown'",
            "owner_confidence": "TEXT NOT NULL DEFAULT 'unknown'",
            "traffic_role": "TEXT NOT NULL DEFAULT 'user'",
        }
        for table in ("traffic_minute", "traffic_hour", "traffic_alerts"):
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            for column, definition in migrations.items():
                if column not in existing:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
                    )
        # Reclassify known v17 self-check rows so they remain visible in the
        # accounting ledger but no longer masquerade as user-app anomalies.
        health_hosts = (
            "www.gstatic.com", "my.ippure.com", "ipwho.is", "rdap.org",
            "rdap.arin.net", "rdap.apnic.net", "rdap.db.ripe.net",
            "rdap.lacnic.net", "rdap.afrinic.net",
        )
        placeholders = ",".join("?" for _ in health_hosts)
        for table in ("traffic_minute", "traffic_hour"):
            conn.execute(
                f"""UPDATE {table}
                       SET traffic_role='health_check'
                     WHERE lower(process_name) LIKE 'netmonitor%'
                       AND lower(destination_host) IN ({placeholders})""",
                health_hosts,
            )
        conn.execute(
            f"""DELETE FROM traffic_alerts
                  WHERE lower(process_name) LIKE 'netmonitor%'
                    AND lower(destination_host) IN ({placeholders})""",
            health_hosts,
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(self.SCHEMA_VERSION),),
        )
        conn.commit()

    def _write_records(self, conn, records):
        minute_sql = """
            INSERT INTO traffic_minute (
                bucket_start, dimension_key, connection_id, process_pid,
                process_name, process_path, process_start_time, source_ip,
                source_port, destination_host, destination_ip, destination_port,
                network, rule, rule_payload, route_kind, route_group, exit_node,
                multiplier, chain, owner_source, owner_confidence, traffic_role,
                upload_bytes, download_bytes, estimated_billed_bytes,
                sample_count, first_seen, last_seen
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(bucket_start, dimension_key) DO UPDATE SET
                connection_id=excluded.connection_id,
                source_port=excluded.source_port,
                owner_source=excluded.owner_source,
                owner_confidence=excluded.owner_confidence,
                upload_bytes=traffic_minute.upload_bytes + excluded.upload_bytes,
                download_bytes=traffic_minute.download_bytes + excluded.download_bytes,
                estimated_billed_bytes=traffic_minute.estimated_billed_bytes + excluded.estimated_billed_bytes,
                sample_count=traffic_minute.sample_count + 1,
                last_seen=MAX(traffic_minute.last_seen, excluded.last_seen)
        """
        hour_sql = """
            INSERT INTO traffic_hour (
                bucket_start, dimension_key, process_pid, process_name,
                process_path, process_start_time, source_port, destination_host,
                destination_ip, destination_port, network, rule, rule_payload,
                route_kind, route_group, exit_node, multiplier, chain,
                owner_source, owner_confidence, traffic_role, upload_bytes,
                download_bytes, estimated_billed_bytes, sample_count, first_seen,
                last_seen
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(bucket_start, dimension_key) DO UPDATE SET
                source_port=excluded.source_port,
                owner_source=excluded.owner_source,
                owner_confidence=excluded.owner_confidence,
                upload_bytes=traffic_hour.upload_bytes + excluded.upload_bytes,
                download_bytes=traffic_hour.download_bytes + excluded.download_bytes,
                estimated_billed_bytes=traffic_hour.estimated_billed_bytes + excluded.estimated_billed_bytes,
                sample_count=traffic_hour.sample_count + 1,
                last_seen=MAX(traffic_hour.last_seen, excluded.last_seen)
        """
        touched = set()
        with conn:
            for row in records:
                stamp = row["observed_at"]
                minute_bucket = stamp - stamp % 60
                hour_bucket = stamp - stamp % 3600
                common_tail = (
                    row["dimension_key"], row["process_pid"], row["process_name"],
                    row["process_path"], row["process_start_time"], row["source_port"],
                    row["destination_host"], row["destination_ip"],
                    row["destination_port"], row["network"], row["rule"],
                    row["rule_payload"], row["route_kind"], row["route_group"],
                    row["exit_node"], row["multiplier"], row["chain"],
                    row["owner_source"], row["owner_confidence"], row["traffic_role"],
                    row["upload_bytes"], row["download_bytes"],
                    row["estimated_billed_bytes"], 1, stamp, stamp,
                )
                conn.execute(
                    minute_sql,
                    (
                        minute_bucket, row["dimension_key"], row["connection_id"],
                        row["process_pid"], row["process_name"], row["process_path"],
                        row["process_start_time"], row["source_ip"], row["source_port"],
                        row["destination_host"], row["destination_ip"],
                        row["destination_port"], row["network"], row["rule"],
                        row["rule_payload"], row["route_kind"], row["route_group"],
                        row["exit_node"], row["multiplier"], row["chain"],
                        row["owner_source"], row["owner_confidence"], row["traffic_role"],
                        row["upload_bytes"], row["download_bytes"],
                        row["estimated_billed_bytes"], 1, stamp, stamp,
                    ),
                )
                conn.execute(hour_sql, (hour_bucket,) + common_tail)
                if row["route_kind"] == "proxy" and row["traffic_role"] == "user":
                    touched.add((minute_bucket, row["dimension_key"]))
            for bucket, dimension_key in touched:
                self._upsert_alert(conn, bucket, dimension_key)
        if time.time() - getattr(self, "_last_cleanup", 0) > 86400:
            self._cleanup(conn)

    def _upsert_alert(self, conn, bucket, dimension_key):
        conn.execute(
            """
            INSERT INTO traffic_alerts (
                bucket_start, dimension_key, process_pid, process_name,
                process_path, process_start_time, source_port, destination_host,
                destination_ip, destination_port, rule, rule_payload, route_group,
                exit_node, multiplier, chain, owner_source, owner_confidence,
                traffic_role, upload_bytes, download_bytes,
                estimated_billed_bytes, threshold_bytes, first_seen, last_seen
            )
            SELECT bucket_start, dimension_key, process_pid, process_name,
                   process_path, process_start_time, source_port, destination_host,
                   destination_ip, destination_port, rule, rule_payload, route_group,
                   exit_node, multiplier, chain, owner_source, owner_confidence,
                   traffic_role, upload_bytes, download_bytes,
                   estimated_billed_bytes, ?, first_seen, last_seen
              FROM traffic_minute
             WHERE bucket_start=? AND dimension_key=?
               AND traffic_role='user'
               AND estimated_billed_bytes >= ?
            ON CONFLICT(bucket_start, dimension_key) DO UPDATE SET
                upload_bytes=excluded.upload_bytes,
                download_bytes=excluded.download_bytes,
                estimated_billed_bytes=excluded.estimated_billed_bytes,
                last_seen=excluded.last_seen
            """,
            (self.anomaly_bytes, bucket, dimension_key, self.anomaly_bytes),
        )

    def _cleanup(self, conn):
        now = int(time.time())
        minute_cutoff = now - self.minute_retention_days * 86400
        summary_cutoff = now - self.summary_retention_days * 86400
        with conn:
            conn.execute("DELETE FROM traffic_minute WHERE bucket_start < ?", (minute_cutoff,))
            conn.execute("DELETE FROM traffic_hour WHERE bucket_start < ?", (summary_cutoff,))
            conn.execute("DELETE FROM traffic_alerts WHERE bucket_start < ?", (summary_cutoff,))
        self._last_cleanup = time.time()
