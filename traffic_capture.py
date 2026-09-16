# -*- coding: utf-8 -*-
"""Windows ETW based per-process network byte accounting.

The Microsoft-Windows-Kernel-Network provider exposes the process id and byte
count for TCP and UDP/QUIC send/receive events.  It is built into Windows, so
no packet capture or filter driver is required.  Starting a system-wide ETW
session does require elevation (or membership in Performance Log Users).
"""

from __future__ import annotations

import ctypes
import os
import threading
import time


try:
    import etw
    from etw.common import RETURN_RAW_UNFORMATTED_DATA
except Exception as exc:  # pragma: no cover - exercised only in broken bundles
    etw = None
    RETURN_RAW_UNFORMATTED_DATA = 0
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


PROVIDER_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
PROVIDER_NAME = "Microsoft-Windows-Kernel-Network"
SESSION_NAME = "NetMonitorProcessTraffic"

# Manifest event ids for the Microsoft-Windows-Kernel-Network provider.
# TCP: 10/11 IPv4, 26/27 IPv6. UDP (including QUIC): 42/43 IPv4, 58/59 IPv6.
UPLOAD_EVENT_IDS = frozenset((10, 26, 42, 58))
DOWNLOAD_EVENT_IDS = frozenset((11, 27, 43, 59))


def is_user_admin() -> bool:
    """Return whether the current Windows process has an elevated token."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class ProcessTrafficMonitor:
    """Collect per-PID upload/download rates from a lightweight ETW session."""

    def __init__(self, clock=time.perf_counter):
        self._clock = clock
        self._lock = threading.Lock()
        self._interval = {}
        self._job = None
        self._last_snapshot = clock()
        self.status = "stopped"
        self.error = ""
        self.event_count = 0
        self.invalid_event_count = 0

    @property
    def elevated(self) -> bool:
        return is_user_admin()

    @property
    def accurate(self) -> bool:
        return self.status == "running"

    def start(self) -> bool:
        """Start capture. Failure is recorded as status and never escapes."""
        if self.status in ("starting", "running"):
            return self.status == "running"
        self.status = "starting"
        self.error = ""

        if os.name != "nt":
            self.status = "unsupported"
            self.error = "仅支持 Windows"
            return False
        if etw is None:
            self.status = "unavailable"
            self.error = f"ETW 组件加载失败: {_IMPORT_ERROR}"
            return False
        provider = etw.ProviderInfo(
            PROVIDER_NAME,
            etw.GUID(PROVIDER_GUID),
            any_keywords=0x30,  # IPv4 | IPv6
        )
        job = etw.ETW(
            session_name=SESSION_NAME,
            providers=[provider],
            event_callback=self._on_raw_event,
            callback_data_flag=RETURN_RAW_UNFORMATTED_DATA,
            ignore_exists_error=False,
            ring_buf_size=64,
        )
        self._job = job
        try:
            # A hard-killed previous instance can leave a named session behind.
            # Stop that orphan before starting our single application session.
            job.control_stop(job.properties)
            job.start()
        except PermissionError as exc:
            self._cleanup_failed_start(job)
            self.status = "admin_required"
            self.error = "需以管理员身份运行，才能启用精准进程上下行"
            if getattr(exc, "winerror", None) not in (None, 5):
                self.error += f"（错误 {exc.winerror}）"
            return False
        except Exception as exc:
            self._cleanup_failed_start(job)
            self.status = "error"
            code = getattr(exc, "winerror", None)
            self.error = f"ETW 启动失败: {code if code is not None else exc}"
            return False

        self._last_snapshot = self._clock()
        self.status = "running"
        return True

    def _cleanup_failed_start(self, job) -> None:
        try:
            if getattr(job, "consumer", None) is not None:
                job.stop()
            elif getattr(job, "provider", None) is not None:
                job.provider.stop()
        except Exception:
            pass
        self._job = None

    def stop(self) -> None:
        job, self._job = self._job, None
        if job is not None:
            try:
                job.stop()
            except Exception:
                pass
        if self.status == "running":
            self.status = "stopped"

    def _on_raw_event(self, item) -> None:
        """Fast callback: parse only event id, PID and byte count.

        All selected provider templates start with two little-endian uint32
        values: PID and size. Avoiding TDH dictionary formatting keeps overhead
        low even when a video stream generates many events per second.
        """
        try:
            _unused, record = item
            header = record.contents.EventHeader
            event_id = int(header.EventDescriptor.Id)
            if event_id in UPLOAD_EVENT_IDS:
                direction = 0
            elif event_id in DOWNLOAD_EVENT_IDS:
                direction = 1
            else:
                return
            if not record.contents.UserData or record.contents.UserDataLength < 8:
                self.invalid_event_count += 1
                return
            raw = ctypes.string_at(record.contents.UserData, 8)
            pid = int.from_bytes(raw[0:4], "little", signed=False)
            size = int.from_bytes(raw[4:8], "little", signed=False)
            if not size or size >= (1 << 31):
                return
            self._accumulate(pid, size, direction)
        except Exception:
            self.invalid_event_count += 1

    def _accumulate(self, pid: int, size: int, direction: int) -> None:
        """Accumulate one event. Kept separate for deterministic unit tests."""
        with self._lock:
            values = self._interval.get(pid)
            if values is None:
                values = [0, 0]
                self._interval[pid] = values
            values[direction] += size
            self.event_count += 1

    def snapshot(self):
        """Return ``pid -> (upload_Bps, download_Bps)`` for the last interval."""
        now = self._clock()
        dt = max(now - self._last_snapshot, 0.05)
        self._last_snapshot = now
        with self._lock:
            interval, self._interval = self._interval, {}
        return {
            pid: (values[0] / dt, values[1] / dt)
            for pid, values in interval.items()
        }

    def status_text(self) -> str:
        if self.status == "running":
            return "Windows ETW 精准采集（TCP + UDP/QUIC）"
        if self.status == "admin_required":
            return "普通权限：连接可见；管理员启动后显示精准进程 ↑↓"
        if self.status == "stopped":
            return "精准进程流量采集已停止"
        return self.error or "精准进程流量采集不可用"
