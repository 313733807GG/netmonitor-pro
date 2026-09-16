# -*- coding: utf-8 -*-
import csv
import os
import sqlite3
import time
import unittest
from contextlib import closing

from traffic_history import (
    TrafficHistoryStore,
    estimated_billed_bytes,
    normalize_sample,
    parse_traffic_multiplier,
)


def sample(**overrides):
    row = {
        "connection_id": "connection-1",
        "process_pid": 1234,
        "process_name": "Kimi.exe",
        "process_path": r"C:\Apps\Kimi\Kimi.exe",
        "process_start_time": 1_700_000_000.5,
        "source_ip": "127.0.0.1",
        "source_port": 50123,
        "destination_host": "kimi.com",
        "destination_ip": "1.2.3.4",
        "destination_port": 443,
        "network": "tcp",
        "rule": "DOMAIN-SUFFIX",
        "rule_payload": "kimi.com",
        "route_kind": "proxy",
        "route_group": "国外流量",
        "exit_node": "香港 2倍消耗",
        "multiplier": 2,
        "chain": "香港 2倍消耗 > 国外流量",
        "owner_source": "mihomo+socket_exact",
        "owner_confidence": "high",
        "traffic_role": "user",
        "upload_bytes": 300_000,
        "download_bytes": 300_000,
    }
    row.update(overrides)
    return row


class TrafficMultiplierTests(unittest.TestCase):
    def test_common_multiplier_labels(self):
        self.assertEqual(parse_traffic_multiplier("香港 3倍消耗"), 3.0)
        self.assertEqual(parse_traffic_multiplier("倍率：0.5"), 0.5)
        self.assertEqual(parse_traffic_multiplier("Premium x2"), 2.0)
        self.assertEqual(parse_traffic_multiplier("Windows x64"), 1.0)
        self.assertEqual(parse_traffic_multiplier("普通节点"), 1.0)

    def test_leaf_node_takes_precedence_over_group(self):
        self.assertEqual(
            parse_traffic_multiplier("香港 0.8 倍", "高倍率 3倍消耗"),
            0.8,
        )

    def test_direct_and_reject_do_not_consume_node_quota(self):
        self.assertEqual(estimated_billed_bytes(1000, "direct", 5), 0)
        self.assertEqual(estimated_billed_bytes(1000, "reject", 5), 0)
        self.assertEqual(estimated_billed_bytes(1000, "proxy", 2), 2000)

    def test_normalization_keeps_actual_and_billed_separate(self):
        row = normalize_sample(sample(), observed_at=123456)
        self.assertEqual(row["upload_bytes"] + row["download_bytes"], 600_000)
        self.assertEqual(row["estimated_billed_bytes"], 1_200_000)
        self.assertEqual(row["source_port"], 50123)
        self.assertEqual(row["process_start_time"], 1_700_000_000.5)
        self.assertEqual(row["owner_confidence"], "high")


class TrafficHistoryStoreTests(unittest.TestCase):
    def setUp(self):
        # Keep test files directly in the writable checkout.  Some Windows
        # sandboxes allow files in the checkout but intentionally deny newly
        # created arbitrary subdirectories.
        unique = f"{os.getpid()}-{time.time_ns()}"
        self.db_path = os.path.abspath(f"test-traffic-history-{unique}.sqlite3")
        self.export_paths = []
        self.store = TrafficHistoryStore(self.db_path, anomaly_mib=1)
        self.assertTrue(self.store.running, self.store.last_error)

    def tearDown(self):
        self.store.close()
        for path in (self.db_path, self.db_path + "-shm", self.db_path + "-wal",
                     *self.export_paths):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    def test_aggregates_and_creates_threshold_event(self):
        now = int(time.time())
        stamp = now - now % 60 - 50  # previous minute at :10; +1 cannot cross a bucket
        self.assertTrue(self.store.record([sample()], observed_at=stamp))
        self.assertTrue(self.store.record([sample()], observed_at=stamp + 1))
        self.assertTrue(self.store.record([
            sample(
                connection_id="direct-1",
                route_kind="direct",
                route_group="DIRECT",
                exit_node="DIRECT",
                multiplier=9,
                destination_host="cn.bing.com",
                rule_payload="cn.bing.com",
            )
        ], observed_at=stamp + 2))
        self.assertTrue(self.store.flush())

        with closing(sqlite3.connect(self.db_path)) as conn:
            proxy = conn.execute(
                """
                SELECT upload_bytes, download_bytes, estimated_billed_bytes,
                       sample_count
                  FROM traffic_minute
                 WHERE route_kind='proxy'
                """
            ).fetchone()
            direct_billed = conn.execute(
                "SELECT estimated_billed_bytes FROM traffic_minute WHERE route_kind='direct'"
            ).fetchone()[0]
            hour_count = conn.execute("SELECT COUNT(*) FROM traffic_hour").fetchone()[0]
            alert = conn.execute(
                "SELECT estimated_billed_bytes, threshold_bytes FROM traffic_alerts"
            ).fetchone()

        self.assertEqual(proxy[:2], (600_000, 600_000))
        self.assertEqual(proxy[2], 2_400_000)
        self.assertEqual(proxy[3], 2)
        self.assertEqual(direct_billed, 0)
        self.assertEqual(hour_count, 2)
        self.assertIsNotNone(alert)
        self.assertGreaterEqual(alert[0], alert[1])

    def test_exports_minute_and_hour_ledgers(self):
        stamp = int(time.time())
        self.store.record([sample()], observed_at=stamp)
        self.assertTrue(self.store.flush())

        detail_24h, alerts_24h = self.store.export_csv(24)
        detail_year, alerts_year = self.store.export_csv(365 * 24)
        self.export_paths.extend((detail_24h, alerts_24h, detail_year, alerts_year))

        self.assertIn("_minute_", os.path.basename(detail_24h))
        self.assertIn("_hour_", os.path.basename(detail_year))
        for path in (detail_24h, alerts_24h, detail_year, alerts_year):
            self.assertTrue(os.path.isfile(path))
        with open(detail_24h, newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(rows[0]["process_pid"], "1234")
        self.assertEqual(rows[0]["destination_host"], "kimi.com")
        self.assertEqual(rows[0]["billed_mib"], "1.144")
        self.assertEqual(rows[0]["source_port"], "50123")
        self.assertEqual(rows[0]["owner_source"], "mihomo+socket_exact")
        self.assertEqual(rows[0]["traffic_role"], "user")

    def test_health_check_bytes_are_kept_but_do_not_create_anomaly(self):
        stamp = int(time.time())
        health = sample(
            connection_id="health-1",
            process_pid=999,
            process_name="NetMonitor.exe",
            process_path=r"C:\NetMonitor\NetMonitor.exe",
            destination_host="www.gstatic.com",
            rule_payload="gstatic.com",
            traffic_role="health_check",
            upload_bytes=2_000_000,
            download_bytes=2_000_000,
        )
        self.assertTrue(self.store.record([health], observed_at=stamp))
        self.assertTrue(self.store.flush())
        with closing(sqlite3.connect(self.db_path)) as conn:
            minute = conn.execute(
                "SELECT traffic_role, estimated_billed_bytes FROM traffic_minute"
            ).fetchone()
            alert_count = conn.execute("SELECT COUNT(*) FROM traffic_alerts").fetchone()[0]
        self.assertEqual(minute[0], "health_check")
        self.assertGreater(minute[1], self.store.anomaly_bytes)
        self.assertEqual(alert_count, 0)

    def test_v1_database_is_migrated_in_place_without_losing_rows(self):
        self.store.close()
        for path in (self.db_path, self.db_path + "-shm", self.db_path + "-wal"):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        stamp = int(time.time())
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(
                """
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO meta VALUES ('schema_version', '1');
                CREATE TABLE traffic_minute (
                    bucket_start INTEGER NOT NULL,
                    dimension_key TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    process_pid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    process_path TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
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
                    upload_bytes INTEGER NOT NULL,
                    download_bytes INTEGER NOT NULL,
                    estimated_billed_bytes REAL NOT NULL,
                    sample_count INTEGER NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    PRIMARY KEY (bucket_start, dimension_key)
                ) WITHOUT ROWID;
                """
            )
            conn.execute(
                """INSERT INTO traffic_minute VALUES (
                       ?, 'legacy-key', 'legacy-connection', 7, 'NetMonitor.exe',
                       'C:\\NetMonitor\\NetMonitor.exe', '127.0.0.1',
                       'www.gstatic.com', '1.2.3.4', 443, 'tcp', 'MATCH', '',
                       'proxy', '国外流量', '香港', 1, '香港 > 国外流量',
                       10, 20, 30, 1, ?, ?
                   )""",
                (stamp - stamp % 60, stamp, stamp),
            )
            conn.commit()

        self.store = TrafficHistoryStore(self.db_path, anomaly_mib=1)
        self.assertTrue(self.store.running, self.store.last_error)
        self.assertTrue(self.store.flush())
        with closing(sqlite3.connect(self.db_path)) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(traffic_minute)")}
            version = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()[0]
            row = conn.execute(
                "SELECT connection_id, traffic_role, source_port FROM traffic_minute"
            ).fetchone()
        self.assertTrue({
            "process_start_time", "source_port", "owner_source",
            "owner_confidence", "traffic_role",
        }.issubset(columns))
        self.assertEqual(version, "2")
        self.assertEqual(row, ("legacy-connection", "health_check", 0))


if __name__ == "__main__":
    unittest.main()
