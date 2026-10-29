# -*- coding: utf-8 -*-
"""
NetMonitor Pro v22 —— AI 节点定向探测与代理感知桌面监控小组件
两态设计：吸附迷你条（全局绿/代理黄 + 通断灯）<-> 悬停展开全盘面板
"""
import sys
from ip_quality import (PROBE_GROUP, QualityCache, ai_target, quality_key, profile_id,
                        collect_quality, proxy_get, ippure_badge, clean_color, risk_color, flclash_color, location_display)
from connection_labels import service_name, connection_name, label_basis, friendly_proc, GENERIC_RENDERERS
from unknown_log import UnknownTargetLog
import os
import time
import json
import html
import math
import socket
import subprocess
import winreg
import collections
import ctypes
import ctypes.wintypes
import sqlite3

import psutil
import re
import ssl
import threading
import ipaddress
from PySide6.QtCore import Qt, QTimer, QPoint, QSettings, QThread, Signal, QPropertyAnimation, QEasingCurve, Property, qInstallMessageHandler, QEvent
from PySide6.QtGui import QPainter, QColor, QPen, QFont, QAction, QIcon, QPixmap, QPainterPath, QBrush, QRadialGradient, QCursor
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QScrollArea, QFrame, QSystemTrayIcon, QMenu, QComboBox, QMessageBox,
    QSizePolicy, QGridLayout,
)

from pipe_client import MihomoPipe, _ai_group_rank
from traffic_capture import ProcessTrafficMonitor, is_user_admin
from traffic_history import TrafficHistoryStore, parse_traffic_multiplier
from diagnostics import LOG, setup_logging, display_text
from monitoring_state import route_evidence, probe_selection, mode_label, latency_style, strict_route_state
from status_ui import TypeBadges, mode_rich_text, ElidedLabel
import ui_theme as theme
from proxy_clients import CLIENT_LABELS, gui_process_matches
from flclash_quality import risk_annotation, usable_record, details as flclash_quality_details
from cleanip_details import risk_display
from docking import EDGE_GAP, nearest_edge, snap_edge, dock_position

# ----------------------------- 工具 -----------------------------

def fmt_speed(bps):
    if bps >= 1 << 20:
        return f"{bps / (1 << 20):.1f}M"
    if bps >= 1 << 10:
        return f"{bps / (1 << 10):.0f}K"
    return f"{bps / (1 << 10):.1f}K"   # 最小单位 K：小流量显示 0.0K~1.0K，不再用 B


def format_proxy_speed_pair(data):
    """Top-right proxy speed labels without overstating estimated traffic."""
    up, down = data.get("proxy_up", 0.0), data.get("proxy_down", 0.0)
    total = data.get("proxy_total", 0.0)
    if total > 0 and up <= 0 and down <= 0:
        if data.get("proxy_total_estimated"):
            return f"≈{fmt_speed(total)}/s", "估算"
        return f"⇅{fmt_speed(total)}/s", "合计"
    return f"↑{fmt_speed(up)}/s", f"↓{fmt_speed(down)}/s"


def _parsed_ip_address(host):
    raw = str(host or "").strip()
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    raw = raw.split("%", 1)[0]       # IPv6 scope id, e.g. fe80::1%12
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    # Windows may expose IPv4 sockets as IPv4-mapped IPv6 addresses.  Treat
    # ::ffff:127.0.0.1 exactly like 127.0.0.1 so proxy-loopback evidence is not
    # silently lost.
    return getattr(address, "ipv4_mapped", None) or address


def is_loopback_address(host):
    address = _parsed_ip_address(host)
    return bool(address and address.is_loopback)


def is_local_address(host):
    """Return whether an address is loopback, private-LAN or link-local."""
    address = _parsed_ip_address(host)
    return bool(address and (address.is_loopback or address.is_private
                             or address.is_link_local))


def address_key(host):
    """Canonical socket-address key shared by psutil and Mihomo metadata."""
    address = _parsed_ip_address(host)
    return str(address) if address else str(host or "")


def proxy_server_ports(proxy_server):
    """Extract ports from simple and per-protocol Windows proxy settings."""
    ports = []
    for part in re.split(r"[;\s]+", str(proxy_server or "")):
        endpoint = part.split("=", 1)[-1].strip()
        if "://" in endpoint:
            endpoint = endpoint.rsplit("://", 1)[-1]
        match = (re.search(r"\]:(\d+)$", endpoint)
                 if endpoint.startswith("[") else re.search(r":(\d+)$", endpoint))
        if match:
            port = int(match.group(1))
            if 0 < port <= 65535 and port not in ports:
                ports.append(port)
    return ports


def is_proxy_exit(node):
    value = str(node or "").strip().upper()
    return bool(value) and value not in {"DIRECT", "PASS", "COMPATIBLE"} and not value.startswith("REJECT")


def effective_proxy_takeover(data):
    """Whether traffic can currently use a proxy node, not merely a live core."""
    if not data.get("sw_on") or not data.get("takeover"):
        return False
    mode = str(data.get("mode") or "").lower()
    if mode == "direct":
        return False
    if mode == "global" and data.get("global_now"):
        return is_proxy_exit(data["global_now"])
    return True


def source_process_owner_detail(exact_map, port_map, source_ip, source_port):
    """Resolve an unambiguous socket owner and report the evidence source."""

    exact = exact_map.get((address_key(source_ip), source_port))
    if exact:
        return exact, "socket_exact"
    by_port = port_map.get(source_port)
    if by_port:
        return by_port, "socket_port"
    return None, ""


def source_process_owner(exact_map, port_map, source_ip, source_port):
    """Resolve a Mihomo source socket to ``(pid, name)`` when unambiguous."""

    return source_process_owner_detail(
        exact_map, port_map, source_ip, source_port,
    )[0]


def source_process_name(exact_map, port_map, source_ip, source_port):
    """Resolve a Mihomo source socket with a safe port-only fallback."""
    owner = source_process_owner(exact_map, port_map, source_ip, source_port)
    return owner[1] if owner else "?"


def _process_identity(name, path=""):
    """Return a case-insensitive executable identity, or an empty value."""

    value = str(name or "").strip()
    if not value or value == "?":
        value = os.path.basename(str(path or "").strip())
    return value.casefold() if value and value != "?" else ""


def metadata_process_owner(pid_names, pid_paths, pid_start_times,
                           metadata_process, metadata_path):
    """Find a unique running PID matching Mihomo's process metadata."""

    wanted_name = _process_identity(metadata_process, metadata_path)
    wanted_path = os.path.normcase(os.path.normpath(str(metadata_path or "")))
    path_matches = []
    name_matches = []
    for pid, name in (pid_names or {}).items():
        path = str((pid_paths or {}).get(pid, "") or "")
        if wanted_path and path and os.path.normcase(os.path.normpath(path)) == wanted_path:
            path_matches.append(pid)
        if wanted_name and _process_identity(name, path) == wanted_name:
            name_matches.append(pid)
    candidates = path_matches or name_matches
    if len(candidates) != 1:
        return None
    pid = int(candidates[0])
    path = str((pid_paths or {}).get(pid, "") or metadata_path or "")
    name = str((pid_names or {}).get(pid, "") or metadata_process
               or os.path.basename(path) or "?")
    return (pid, name, path, float((pid_start_times or {}).get(pid, 0.0) or 0.0))


def resolve_connection_owner(metadata_process="", metadata_path="",
                             metadata_owner=None, socket_owner=None,
                             socket_source="", cached=None, pid_paths=None,
                             pid_start_times=None, observed_at=None):
    """Choose one stable owner for a Mihomo connection.

    Mihomo metadata is strongest.  A cached known owner outranks a later
    socket-only disagreement because short-lived Windows ports can be reused
    between the API sample and the psutil scan.  Unknown owners may always be
    upgraded when better evidence appears.
    """

    stamp = float(observed_at if observed_at is not None else time.time())
    meta_path = str(metadata_path or "")
    meta_name = str(metadata_process or os.path.basename(meta_path) or "")
    meta_identity = _process_identity(meta_name, meta_path)
    cached = dict(cached or {})

    def make(pid, name, path, start_time, source, confidence):
        return {
            "pid": max(int(pid or 0), 0),
            "name": str(name or os.path.basename(str(path or "")) or "?"),
            "path": str(path or ""),
            "start_time": max(float(start_time or 0.0), 0.0),
            "source": str(source or "unknown"),
            "confidence": str(confidence or "unknown"),
            "last_seen": stamp,
        }

    candidates = []
    if metadata_owner:
        candidates.append((metadata_owner, "mihomo_process", "high"))
    if socket_owner:
        pid, name = socket_owner[:2]
        path = str((pid_paths or {}).get(pid, "") or "")
        start = float((pid_start_times or {}).get(pid, 0.0) or 0.0)
        confidence = "high" if socket_source == "socket_exact" else "medium"
        candidates.append(((pid, name, path, start), socket_source, confidence))
    if cached.get("name") and _process_identity(cached.get("name"), cached.get("path")):
        candidates.append((
            (cached.get("pid", 0), cached.get("name"), cached.get("path", ""),
             cached.get("start_time", 0.0)),
            cached.get("source", "connection_cache"),
            cached.get("confidence", "medium"),
        ))

    if meta_identity:
        for candidate, source, confidence in candidates:
            pid, name, path, start = candidate
            if _process_identity(name, path) == meta_identity:
                # Keep the richer API path even when the socket supplied PID.
                return make(pid, meta_name or name, meta_path or path, start,
                            source if source.startswith("mihomo") else
                            f"mihomo+{source}", "high")
        # Conflicting socket ownership is more likely a port-reuse race.  Do
        # not attach its PID to the process named by Mihomo.
        return make(0, meta_name, meta_path, 0.0, "mihomo_metadata", "high")

    if _process_identity(cached.get("name"), cached.get("path")):
        cached["last_seen"] = stamp
        return cached
    if socket_owner:
        pid, name = socket_owner[:2]
        path = str((pid_paths or {}).get(pid, "") or "")
        start = float((pid_start_times or {}).get(pid, 0.0) or 0.0)
        return make(pid, name, path, start, socket_source,
                    "high" if socket_source == "socket_exact" else "medium")
    return make(0, "?", "", 0.0, "unknown", "unknown")


HEALTH_PROBE_HOSTS = {
    "chatgpt.com", "openai.com",
    "www.gstatic.com", "my.ippure.com", "cleanip.io", "ipwho.is", "rdap.org",
    "rdap.arin.net", "rdap.apnic.net", "rdap.db.ripe.net",
    "rdap.lacnic.net", "rdap.afrinic.net",
}
AI_PROBE_URL = "https://chatgpt.com/cdn-cgi/trace"
AI_HEALTH_TARGETS = (
    ("ChatGPT", AI_PROBE_URL),
    ("OpenAI", "https://openai.com/favicon.ico"),
)
_HEALTH_PROBE_PORTS = {}
_HEALTH_PROBE_PORTS_LOCK = threading.Lock()


def register_health_probe_port(source_port, destination_host="", observed_at=None, ttl=300):
    """Remember a local source port used by NetMonitor's own node checks."""

    port = int(source_port or 0)
    if not port:
        return
    stamp = float(observed_at if observed_at is not None else time.time())
    host = str(destination_host or "").strip().lower().rstrip(".")
    with _HEALTH_PROBE_PORTS_LOCK:
        expired = [key for key, item in _HEALTH_PROBE_PORTS.items()
                   if float(item[0]) < stamp]
        for key in expired:
            _HEALTH_PROBE_PORTS.pop(key, None)
        _HEALTH_PROBE_PORTS[port] = (
            stamp + max(float(ttl), 30.0), host,
        )


def traffic_role_for(source_port, destination_host, process_name="",
                     process_path="", observed_at=None):
    """Separate NetMonitor health checks from user-application traffic."""

    stamp = float(observed_at if observed_at is not None else time.time())
    port = int(source_port or 0)
    host = str(destination_host or "").strip().lower().rstrip(".")
    with _HEALTH_PROBE_PORTS_LOCK:
        entry = _HEALTH_PROBE_PORTS.get(port)
        until, expected_host = entry if entry else (0.0, "")
        if until and until >= stamp and (not expected_host or host == expected_host):
            return "health_check"
        if until:
            _HEALTH_PROBE_PORTS.pop(port, None)
    proc = _process_identity(process_name, process_path)
    if proc.startswith("netmonitor") and any(
            host == item or host.endswith("." + item) for item in HEALTH_PROBE_HOSTS):
        return "health_check"
    return "user"


def proxy_action_node(data):
    """Return the AI group's selected leaf; never use the active route."""
    node = data.get("ai_node", "")
    return node if is_proxy_exit(node) else ""


def user_explicit_proxy(connection):
    """Explicit application proxies may remain active after OS/TUN switches off."""
    meta=connection.get('metadata') or {}
    if str(meta.get('type','')).casefold() not in ('http','https','socks4','socks5'):return False
    if PROBE_GROUP in (connection.get('chains') or []) or meta.get('inboundName')=='netmonitor-ip-check':return False
    return traffic_role_for(meta.get('sourcePort'),meta.get('host'),meta.get('process',''),meta.get('processPath',''))!='health_check'


def proxy_health_key(data):
    """Stable AI target key, empty instead of falling back to provider rules."""
    if not effective_proxy_takeover(data):
        return ""
    if not data.get("api_on"):
        return ""
    group = str(data.get("ai_group") or "").strip()
    node = proxy_action_node(data)
    key = f"AI|{group}|{node}" if group and node else ""
    if key and data.get("api_generation"):
        key += f"|{data.get('mode')}|{data['api_generation']}"
    return key


def proxy_action_state(data):
    """Return whether node actions may run and an optional transient hint.

    Both manual node actions use this single source of truth so that an
    inactive proxy never starts a misleading health/latency probe.  A running
    background core may still be used when it is genuinely taking over the
    network; in that case the hint is informational rather than blocking.
    """
    if not data:
        return False, "代理状态正在检测，请稍候再试"
    if not data.get("sw_on"):
        return False, "未检测到代理软件，请先启动代理"
    if data.get("mode") == "direct":
        return False, "当前为直连模式，请先切换到代理节点模式"
    if data.get("mode") == "global" and data.get("global_now"):
        global_exit = str(data["global_now"]).strip().upper()
        if global_exit == "DIRECT":
            return False, "GLOBAL 当前选择 DIRECT，没有可测试的代理节点"
        if global_exit.startswith("REJECT"):
            return False, "GLOBAL 当前为拦截出口，没有可测试的代理节点"
    if not data.get("takeover"):
        return False, "代理未接管网络，请先开启系统代理或 TUN"
    if not data.get("api_on"):
        return False, "代理内核未开放接口，无法绕过分流锁定 AI 节点"
    if not data.get("ai_group"):
        return False, "无法确定 AI 组或唯一主选择组，不会回退检测国外网站节点"
    if not proxy_action_node(data):
        return False, "AI服务 当前没有可测试的代理节点"
    group_type = str(data.get("ai_group_type") or "")
    if group_type in ("URLTest", "Fallback", "LoadBalance"):
        return True, "AI服务 仍是自动策略组；本次锁定当前叶子节点，但策略组本身可能切换"
    if not data.get("gui_alive", True):
        return True, "代理界面未运行，正在使用后台内核节点"
    return True, ""


def _lbl_set(lbl, text):
    """文本没变就不 setText（避免每秒触发样式/布局重算，防偶发卡顿）"""
    text = display_text(text)
    if lbl.text() != text:
        lbl.setText(text)


def _tip_set(w, tip):
    tip = display_text(tip)
    if w.toolTip() != tip:
        w.setToolTip(tip)


def choose_primary_route(route_stats):
    """Choose ``(group, exit_node)`` from real Mihomo connection chains.

    A route carrying bytes in the current interval outranks idle routes; when
    all routes are idle, connection count provides a stable fallback.
    ``route_stats`` maps a route tuple to ``[interval_bytes, connections]``.
    """
    if not route_stats:
        return "", ""

    def score(item):
        interval_bytes, connections = item[1]
        return interval_bytes > 0, interval_bytes, connections

    return max(route_stats.items(), key=score)[0]


def choose_display_proxy(route_stats, previous=("", "")):
    """Keep a confirmed proxy route until its last connection disappears."""
    candidates = {key: value for key, value in route_stats.items()
                  if is_proxy_exit(key[1])}
    if previous in candidates:
        return previous
    return choose_primary_route(candidates)


def display_provider_name(name):
    """Display-only cleanup; never change API group names or cache keys."""
    original = str(name or '')
    cleaned = re.sub(r'\s*[-—–|·：:]?\s*(?:官方网站|官方網站|官方网址|官方網址|官网|官網)(?:\s*[:：]?\s*https?://\S+)?\s*$', '', original, flags=re.I)
    cleaned = re.sub(r'\s*[（(](?:官方网站|官方網站|官网|官網)[）)]\s*$', '', cleaned)
    return cleaned.strip() or original


def format_node_status(data):
    """Return ``(label, node)`` using mode-appropriate source of truth."""
    if 'ai_target_state' in data:
        if data['ai_target_state'] == 'direct':
            return 'AI出口: DIRECT（直连，不检测 IP 评分）', 'DIRECT'
        if data['ai_target_state'] != 'confirmed':
            return 'AI出口: 等待实际连接确认', '—'
        node, group = data['ai_node'], data['ai_group']
        return f"当前AI节点: {display_provider_name(group)} → {node}", node
    if data.get("target_unified") and data.get("ai_node"):
        node, group = data["ai_node"], data["ai_group"]
        observed = any(item[1] == node for item in data.get("proxy_routes", []))
        others = len({item[1] for item in data.get("proxy_routes", []) if item[1] != node})
        label = f"当前节点: {group} → {node}（{'已观测出口' if observed else '当前选择'}）"
        if others:
            label += f" · 另{others}个出口"
        return label, node
    if data.get("mode") == "direct":
        return "路由模式: 🎯 DIRECT（新连接直连）", "DIRECT"
    if data.get("mode") == "global":
        node = data.get("global_now")
        if not node:
            # A rule-mode selection is not evidence of GLOBAL's real exit.
            return "全局出口: 检测中…", "—"
        normalized = str(node).strip().upper()
        if normalized == "DIRECT":
            return "全局出口: 🎯 DIRECT（直连）", node
        if normalized.startswith("REJECT"):
            return "全局出口: ⛔ REJECT（拦截）", node
        return f"全局出口: 🌐 {node}", node
    if data.get("mode") == "rule" and data.get("active_node"):
        node = data["active_node"]
        group = data.get("active_group")
        label = f"代理节点: {group} → {node}" if group else f"代理节点: {node}"
        others = len({item[1] for item in data.get("proxy_routes", [])}) - 1
        if others > 0:
            label += f"（另{others}个出口）"
        return label, node
    node = data.get("sel_node") or "—"
    group = data.get("sel_group")
    label = f"当前选择: {group} → {node}（待连接）" if group else "代理节点: 暂无已确认的代理连接"
    return label, node


def node_status_tooltip(data):
    routes = data.get("proxy_routes") or []
    if data.get("mode") != "rule" or not routes:
        return format_node_status(data)[0]
    return ("依据 Mihomo 真实连接出口；存在连接时固定展示，不随流量大小轮换。\n"
            "多个出口可能同时生效，旧连接也可能继续使用切换前的节点。\n" +
            "\n".join(f"{group} → {node}（{count} 条连接）"
                      for group, node, count in routes))


def request_elevated_relaunch(shell_execute=None):
    """Request a new elevated copy. Return True only when Windows accepted it."""
    if is_user_admin():
        return True
    if getattr(sys, "frozen", False):
        executable = sys.executable
        args = ["--elevated-relaunch"]
    else:
        executable = sys.executable
        args = [os.path.abspath(__file__), "--elevated-relaunch"]
    params = subprocess.list2cmdline(args)
    if shell_execute is None:
        shell_execute = ctypes.windll.shell32.ShellExecuteW
        shell_execute.restype = ctypes.c_void_p
    result = shell_execute(
        None, "runas", executable, params,
        os.path.dirname(os.path.abspath(sys.argv[0])), 1,
    )
    return int(result or 0) > 32


def instance_lock_path(smoketest=False, base_directory=None):
    """Return one product-wide lock path, independent of install directory."""

    base = (base_directory or os.environ.get("NETMONITOR_LOCK_DIR")
            or os.environ.get("LOCALAPPDATA"))
    if not base:
        base = os.path.join(os.path.expanduser("~"), "AppData", "Local")
    name = "netmonitor-smoketest.lock" if smoketest else "netmonitor.lock"
    return os.path.join(base, "NetMonitorPro", name)


def acquire_instance_lock(smoketest=False, base_directory=None):
    """Acquire a cross-integrity per-user Win32 file handle with no sharing."""

    path = instance_lock_path(smoketest, base_directory)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
        handle = kernel32.CreateFileW(
            path,
            0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
            0,                        # no sharing: this is the process lock
            None,
            4,                        # OPEN_ALWAYS
            0x80,                     # FILE_ATTRIBUTE_NORMAL
            None,
        )
        invalid = ctypes.wintypes.HANDLE(-1).value
        if not handle or handle == invalid:
            return None
        return handle
    except (OSError, PermissionError, AttributeError):
        return None


def release_instance_lock(handle):
    if handle is None:
        return
    try:
        ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass


def find_existing_netmonitor_window(user32=None):
    """Find an existing NetMonitor window, including a tray-hidden Qt window."""

    user32 = user32 or ctypes.windll.user32
    handles = []
    callback_type = ctypes.WINFUNCTYPE(
        ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM,
    )

    def callback(hwnd, _):
        buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, buf, len(buf))
        if buf.value.startswith("NetMonitor Pro"):
            handles.append(hwnd)
            return False
        return True

    callback_ref = callback_type(callback)
    try:
        user32.EnumWindows(callback_ref, 0)
    except Exception:
        return None
    return handles[0] if handles else None


def activate_netmonitor_window(hwnd, user32=None):
    if not hwnd:
        return
    user32 = user32 or ctypes.windll.user32
    try:
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        user32.SetForegroundWindow(hwnd)
    except Exception:
        pass


# 常见服务主机名 → 友好中文名（CDN 机器名没法读，按包含匹配，先具体后泛化）
FRIENDLY_HOSTS = [
    ("functional.events.data.microsoft", "微软遥测"),
    ("googlevideo.com", "YouTube 视频流"),
    ("ytimg.com", "YouTube 图片"),
    ("youtube.com", "YouTube"),
    ("googleapis.com", "Google API"),
    ("gstatic.com", "Google 静态资源"),
    ("googleusercontent.com", "Google 用户内容"),
    ("doubleclick.net", "Google 广告"),
    ("googlesyndication.com", "Google 广告"),
    ("googletagmanager.com", "Google 统计"),
    ("google-analytics.com", "Google 统计"),
    ("hdslb.com", "B站视频流"),
    ("bilivideo.com", "B站视频流"),
    ("bilibili.com", "B站"),
    ("zijieapi.com", "字节跳动"),
    ("douyin", "抖音"),
    ("volces.com", "火山引擎"),
    ("doubao.com", "豆包"),
    ("moonshot.cn", "Kimi"),
    ("bing.com", "必应"),
    ("msn.com", "MSN"), ("msn.cn", "MSN中国"),
    ("microsoft.com", "微软服务"),
    ("windows.com", "微软系统服务"),
    ("aks-prod", "Azure 云服务"),
    ("amazonaws.com", "AWS 云服务"),
    ("1e100.net", "Google"),
    ("cloudfront.net", "AWS CDN"),
    ("akamai", "Akamai CDN"),
    ("cloudflare.com", "Cloudflare"),
    ("fastly.net", "Fastly CDN"),
    ("twitter.com", "X/Twitter"), ("twimg.com", "X/Twitter"),
    ("x.com", "X/Twitter"),
    ("telegram", "Telegram"),
    ("github.com", "GitHub"), ("githubusercontent.com", "GitHub"),
    ("openai.com", "OpenAI"), ("chatgpt.com", "ChatGPT"),
    ("anthropic.com", "Claude"),
    ("netflix.com", "Netflix"), ("nflxvideo.net", "Netflix 视频流"),
    ("spotify.com", "Spotify"),
    ("apple.com", "苹果服务"), ("icloud.com", "iCloud"),
    ("qq.com", "腾讯"), ("weixin", "微信"), ("qpic.cn", "腾讯图片"),
    ("taobao.com", "淘宝"), ("alipay.com", "支付宝"), ("tmall.com", "天猫"),
    ("jd.com", "京东"), ("360buyimg.com", "京东"),
    ("baidu.com", "百度"),
    ("zhihu.com", "知乎"),
    ("weibo.com", "微博"),
    ("163.com", "网易"), ("126.net", "网易"),
    ("csdn.net", "CSDN"),
]


def friendly_host(host):
    """Domain-boundary aliases only; no substring guesses."""
    return service_name(host, FRIENDLY_HOSTS)


FG = theme.TEXT
DIM = theme.MUTED
GREEN = theme.GREEN    # 全局流量 / 正常
YELLOW = theme.YELLOW   # 代理流量
RED = theme.RED      # 异常
GRAY = "#5A6072"     # 未启用
BLUE = "#4C9AFF"


def system_route_state(data):
    """Describe unconfirmed system-socket evidence without inventing a route."""
    has_proxy = bool(data.get("fact_proxy") or data.get("proxy_socket_count", 0))
    has_direct = bool(data.get("has_direct") or data.get("direct_socket_count", 0))
    if has_proxy and has_direct:
        return "mixed"
    if has_proxy:
        return "proxy_related"
    return "system"


def supplemental_system_status(data):
    """Keep supplemental rows blue until Mihomo confirms their real exit."""
    state = system_route_state(data)
    if state == "mixed":
        return "路径待确认", "system"
    if state == "proxy_related":
        return "路径待确认", "system"
    return "系统连接", "system"


def connection_class(data):
    """Single semantic class used by the badge, dot and speed color."""
    kind = data.get("kind")
    if kind == "sys":
        # Connecting to 127.0.0.1:7897 only proves that a process handed data
        # to the proxy core; it does not prove whether Mihomo then chose
        # DIRECT or a paid node.  Only an explicit API route may be green,
        # yellow or red.  Unconfirmed system rows therefore stay blue.
        confirmed = data.get("actual_route_kind")
        return confirmed if confirmed in ("direct", "proxy", "reject") else "system"
    explicit = data.get("display_class")
    if explicit in ("system", "direct", "proxy", "reject"):
        return explicit
    return kind if kind in ("direct", "proxy", "reject") else "system"


def connection_color(data):
    """Single color source for a connection row's dot and speed text."""
    return {
        "system": BLUE,
        "direct": GREEN,
        "proxy": YELLOW,
        "reject": RED,
    }[connection_class(data)]


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
IE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# ----------------------------- 代理通断探测线程 -----------------------------

class CancelableNetworkWorker(QThread):
    """QThread that can close its current socket during application shutdown."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._socket_lock = threading.Lock()
        self._active_socket = None

    def track_socket(self, sock):
        with self._socket_lock:
            self._active_socket = sock
            cancelled = self.isInterruptionRequested()
        if cancelled:
            try:
                sock.close()
            except Exception:
                pass
            raise OSError("network worker cancelled")

    def clear_socket(self, sock):
        with self._socket_lock:
            if self._active_socket is sock:
                self._active_socket = None

    def cancel(self):
        self.requestInterruption()
        with self._socket_lock:
            sock = self._active_socket
            self._active_socket = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass


class IPQualityWorker(CancelableNetworkWorker):
    done = Signal(object)

    def __init__(self, pipe, node='', port=0, parent=None):
        super().__init__(parent)
        self.pipe = pipe.fixed_session() if isinstance(pipe, MihomoPipe) else pipe
        self.node, self.port = node, port
        self.connection = None

    def cancel(self):
        super().cancel()
        if self.connection is not None:
            self.connection.close()

    def register_port(self, port, host):
        register_health_probe_port(port, host)

    def run(self):
        try:
            if self.node:
                result = collect_quality(self.pipe, self.node, self)
            else:
                _, route = proxy_get(self.pipe, 'chatgpt.com', '/cdn-cgi/trace', self.port, owner=self)
                result = {'route': route}
        except Exception as exc:
            result = {'errors': {'request': str(exc)[:180]}, 'time': time.strftime('%Y-%m-%d %H:%M:%S')}
        if self.isInterruptionRequested():result['cancelled']=True
        self.done.emit(result)


class EngineSampler:
    """Single daemon sampler: controller/psutil waits never block button clicks."""
    def __init__(self, engine):
        self.engine = engine
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._latest = None
        self.thread = threading.Thread(target=self._run, name="NetMonitorSampler", daemon=True)
        self.thread.start()

    def _run(self):
        try:
            while not self._stop.is_set():
                started = time.monotonic()
                try:
                    data = self.engine.tick()
                    with self._lock:
                        self._latest = data
                except Exception:
                    LOG.exception("data sampling failed")
                self._stop.wait(max(0.05, 1 - (time.monotonic() - started)))
        finally:
            self.engine.close()

    def take(self):
        with self._lock:
            result, self._latest = self._latest, None
        return result

    def close(self):
        self._stop.set()
        self.thread.join(8)


class AiProbeWorker(CancelableNetworkWorker):
    """Ask Mihomo to test one explicit AI leaf, bypassing routing rules."""
    result = Signal(bool, int)  # ok, latency_ms

    def __init__(self, pipe, node, url=AI_PROBE_URL, attempts=1,
                 timeout=8000, parent=None):
        super().__init__(parent)
        self.pipe = pipe
        self.node = node
        self.url = url
        self.attempts = max(int(attempts), 1)
        self.timeout = max(int(timeout), 1000)

    def run(self):
        """Automatic checks run once; manual latency runs twice and keeps best."""
        ok2, ms2, last_ms = False, 0, 0
        for _i in range(self.attempts):
            if self.isInterruptionRequested():
                return
            try:
                delay = self.pipe.node_delay(
                    self.node, url=self.url, timeout=self.timeout,
                )
            except Exception:
                delay = None
            last_ms = int(delay or 0)
            if delay is not None and int(delay) >= 0:
                if not ok2 or int(delay) < ms2:
                    ok2, ms2 = True, int(delay)
        if self.isInterruptionRequested():
            return
        self.result.emit(ok2, ms2 if ok2 else last_ms)


# ----------------------------- 节点体检线程 -----------------------------

def _dechunk(body):
    out, i = bytearray(), 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += body[j + 2: j + 2 + size]
        i = j + 2 + size + 2
    return bytes(out)


def _https_get_once(host, path, port=7897, timeout=8, worker=None):
    """通过代理 CONNECT 隧道发一次 HTTPS GET，返回 (响应头, 解压后的 body)"""
    if worker is not None and worker.isInterruptionRequested():
        raise OSError("network worker cancelled")
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        register_health_probe_port(s.getsockname()[1], host)
    except Exception:
        pass
    if worker is not None:
        worker.track_socket(s)
    s.settimeout(timeout)
    ss = None
    try:
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                raise IOError("proxy closed")
            resp += chunk
        if b" 200" not in resp.split(b"\r\n", 1)[0]:
            raise IOError("CONNECT refused")
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(s, server_hostname=host)
        if worker is not None:
            worker.track_socket(ss)
        try:
            ss.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetMonitorPro\r\n"
                       f"Accept: application/json\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while True:
                try:
                    chunk = ss.recv(65536)
                except (ssl.SSLError, socket.timeout):
                    break
                if not chunk:
                    break
                data += chunk
        finally:
            try:
                ss.close()
            except Exception:
                pass
    finally:
        if worker is not None:
            worker.clear_socket(ss if ss is not None else s)
        try:
            s.close()
        except Exception:
            pass
    head, _, body = data.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        body = _dechunk(body)
    return head, body


def https_via_proxy(host, path, port=7897, timeout=8, redirects=3, trace=None, worker=None):
    """支持 302 跳转的 JSON GET（RDAP 查询需要跳转到各注册局）"""
    body = b""
    for _ in range(redirects + 1):
        if worker is not None and worker.isInterruptionRequested():
            raise OSError("network worker cancelled")
        if trace is not None:
            trace.append(host)
        head, body = _https_get_once(host, path, port, timeout, worker=worker)
        status_line = head.split(b"\r\n", 1)[0].decode("latin1", "replace") + " "
        m = re.search(r"\s(\d{3})\s", status_line)
        status = int(m.group(1)) if m else 0
        if status in (301, 302, 303, 307, 308):
            loc = re.search(rb"(?im)^location:\s*(\S+)", head)
            if not loc:
                break
            url = loc.group(1).decode("latin1")
            if url.startswith("http"):
                from urllib.parse import urlparse
                u = urlparse(url)
                host = u.hostname or host
                path = (u.path or "/") + (("?" + u.query) if u.query else "")
            else:
                path = url
            continue
        break
    return json.loads(body.decode("utf-8", "replace"))


class HistoryExportWorker(QThread):
    """Export a potentially large ledger without blocking the desktop widget."""

    result = Signal(bool, str, str)

    def __init__(self, store, hours, parent=None):
        super().__init__(parent)
        self.store = store
        self.hours = hours

    def run(self):
        try:
            detail_path, alert_path = self.store.export_csv(self.hours)
            self.result.emit(True, detail_path, alert_path)
        except Exception as exc:
            self.result.emit(False, str(exc), "")


COUNTRY_ZH = {"Japan": "日本", "United States": "美国", "Singapore": "新加坡",
              "Hong Kong": "中国香港", "Taiwan": "中国台湾", "South Korea": "韩国",
              "Korea": "韩国", "Germany": "德国", "United Kingdom": "英国",
              "France": "法国", "Canada": "加拿大", "Australia": "澳大利亚",
              "Netherlands": "荷兰", "India": "印度", "Malaysia": "马来西亚",
              "Thailand": "泰国", "Vietnam": "越南", "Philippines": "菲律宾",
              "Indonesia": "印尼", "Russia": "俄罗斯", "Turkey": "土耳其",
              "United Arab Emirates": "阿联酋", "Brazil": "巴西", "China": "中国"}
CITY_ZH = {"Tokyo": "东京", "Osaka": "大阪", "Singapore": "新加坡", "Seoul": "首尔",
           "Los Angeles": "洛杉矶", "San Jose": "圣何塞", "New York": "纽约",
           "Chicago": "芝加哥", "Frankfurt": "法兰克福", "London": "伦敦",
           "Paris": "巴黎", "Hong Kong": "香港", "Taipei": "台北"}

CC_ZH = {"US": "美国", "JP": "日本", "SG": "新加坡", "HK": "中国香港", "TW": "中国台湾",
         "KR": "韩国", "DE": "德国", "GB": "英国", "FR": "法国", "CA": "加拿大",
         "AU": "澳大利亚", "NL": "荷兰", "IN": "印度", "MY": "马来西亚", "TH": "泰国",
         "VN": "越南", "PH": "菲律宾", "ID": "印尼", "RU": "俄罗斯", "TR": "土耳其",
         "AE": "阿联酋", "BR": "巴西", "CN": "中国"}


def health_text(r):
    """把体检结果渲染成三行简洁中文（完整技术信息放悬停提示）"""
    if r.get("kind") == "ai_probe":
        checks = r.get("checks") or []
        group = html.escape(str(r.get("group") or "AI服务"))
        node = html.escape(str(r.get("node") or "?"))
        states = []
        for item in checks:
            label = html.escape(str(item.get("label") or "AI"))
            states.append(f"{label} {item.get('delay', 0)}ms" if item.get("ok")
                          else f"{label} 超时")
        passed = sum(1 for item in checks if item.get("ok"))
        if r.get("ok") and passed == len(checks):
            conclusion = '<font color="#3DDC97">AI 通道正常</font>'
        elif r.get("ok"):
            conclusion = '<font color="#FFC542">ChatGPT 可用 · 部分目标异常</font>'
        else:
            conclusion = '<font color="#FF5C5C">AI 目标探测失败</font>'
        return [
            f"AI目标: {group} → {node}",
            " · ".join(states) if states else "AI 探测无结果",
            f"结论: {conclusion}",
        ]
    if not r.get("ok"):
        return [f"体检失败: {r.get('error', '未知错误')}", "", ""]
    country = COUNTRY_ZH.get(r["country"], r["country"])
    city = CITY_ZH.get(r.get("city", ""), r.get("city", ""))
    if city:
        if r.get("cross_country") and r["cross_country"] != r["country"]:
            loc = f"{country}（另一库: {COUNTRY_ZH.get(r['cross_country'], r['cross_country'])}）"
        else:
            loc = f"{country}·{city}"
    else:
        loc = country
    kind_res = r.get("residential")
    if kind_res is None:
        org_l = (r.get("org") or "").lower()
        hosting_kw = ["cloud", "host", "data", "vps", "server", "amazon", "oracle",
                      "google", "microsoft", "alibaba", "tencent", "digitalocean",
                      "vultr", "linode", "akamai", "akile"]
        kind_res = not any(k in org_l for k in hosting_kw)
        kind_suffix = "（推断）"
    else:
        kind_suffix = ""
    # 来源判定：优先 IPPure isBroadcast；缺失时（IPv6）用注册局地区 vs 出口地推断
    RIR_INFO = {"arin": ("美国", {"United States", "Canada"}),
                "ripe": ("欧洲", {"Germany", "United Kingdom", "France", "Netherlands", "Russia",
                                  "Turkey", "Italy", "Spain", "Sweden", "Switzerland", "Poland",
                                  "Ukraine", "Austria", "Belgium", "Ireland", "Norway", "Denmark", "Finland"}),
                "apnic": ("亚太", {"Japan", "Singapore", "Hong Kong", "Taiwan", "South Korea", "Korea",
                                   "India", "Malaysia", "Thailand", "Vietnam", "Philippines",
                                   "Indonesia", "Australia", "China"}),
                "lacnic": ("拉美", {"Brazil", "Argentina", "Mexico", "Chile", "Colombia"}),
                "afrinic": ("非洲", {"South Africa", "Egypt", "Nigeria", "Kenya"})}
    rir = r.get("rir")
    reg_cc = (r.get("reg_country") or "").upper()
    if reg_cc:
        reg_label = CC_ZH.get(reg_cc, reg_cc)
    elif rir in RIR_INFO:
        reg_label = RIR_INFO[rir][0]
    else:
        reg_label = ""
    if r.get("broadcast") is True:
        is_b = True
    elif r.get("broadcast") is False:
        is_b = False
    elif rir in RIR_INFO and r.get("country"):
        is_b = r["country"] not in RIR_INFO[rir][1]
    elif reg_cc and r.get("countryCode"):
        is_b = reg_cc != r["countryCode"]
    else:
        is_b = None
    if is_b is True:
        src = f"广播IP（注册: {reg_label or '未知'}）"
    elif is_b is False:
        src = "原生IP"
    else:
        src = "来源未知"
    attr = ("家宽IP" if kind_res else "机房IP") + kind_suffix
    score = r.get("score")
    score_txt = "未知" if score is None else ("低" if score < 30 else "中" if score < 60 else "高") + f"（{score}）"
    hosting = not kind_res
    broadcast = is_b is True
    native = is_b is False
    sc = score if score is not None else 50
    # 五级风险灯：0 蓝(极低) 1 绿(低) 2 黄(中) 3 橙(高) 4 红(极高)
    if hosting and sc >= 60:
        ai = 4
    elif hosting or sc >= 60:
        ai = 3
    elif broadcast or sc >= 40:
        ai = 2
    elif kind_res and native and sc < 20:
        ai = 0
    else:
        ai = 1
    if broadcast and sc >= 60:
        stream = 4
    elif broadcast:
        stream = 3
    elif hosting:
        stream = 2
    elif sc < 20:
        stream = 0
    else:
        stream = 1
    browse = 4 if sc >= 80 else 3 if sc >= 60 else 2 if sc >= 40 else 1 if sc >= 20 else 0
    return [
        f"出口位置: {loc}",
        f"来源·属性: {src} · {attr}",
        f"风险 {score_txt} · 用途: AI {usage_dot(ai)} 流媒体 {usage_dot(stream)} 浏览 {usage_dot(browse)}",
    ]


RISK_COLORS = ["#4C9AFF", "#3DDC97", "#FFC542", "#FF9F43", "#FF5C5C"]  # 蓝绿黄橙红
RISK_NAMES = ["极低", "低", "中", "高", "极高"]


def usage_dot(level):
    return f'<font color="{RISK_COLORS[level]}">●</font>'


def health_tooltip(r):
    if r.get("kind") == "ai_probe":
        lines = [
            f"AI策略组: {r.get('group') or '?'}",
            f"锁定节点: {r.get('node') or '?'}",
            "探测方式: Mihomo 指定叶子节点（绕过订阅 rules/MATCH）",
        ]
        for item in r.get("checks") or []:
            status = f"{item.get('delay', 0)} ms" if item.get("ok") else "超时"
            lines.append(f"{item.get('label') or 'AI'}: {status} · {item.get('url') or ''}")
        return "\n".join(lines)
    if not r.get("ok"):
        return ""
    return (f"出口 IP: {r.get('ip', '?')}\n运营商: {r.get('org', '?')} (AS{r.get('asn', '?')})\n"
            f"注册: {r.get('reg_country') or r.get('rir', '?')}（网段 {r.get('reg_name', '?')}）\n"
            f"fraudScore: {r.get('score', 'N/A')} · isResidential: {r.get('residential')} · "
            f"isBroadcast: {r.get('broadcast')}")

class DataEngine:
    def __init__(self, capture=True):
        self.pipe = MihomoPipe()
        self.traffic = ProcessTrafficMonitor()
        self.history = TrafficHistoryStore()
        if capture:
            self.traffic.start()
            LOG.info("traffic capture status=%s detail=%s",
                     self.traffic.status, self.traffic.status_text())
        self.last_net = psutil.net_io_counters()
        self.last_time = time.time()
        self.conn_bytes = {}
        self.connection_owners = {}  # Mihomo connection id -> stable owner evidence
        self.port_pid = {}
        self.port_pid_by_port = {}  # source port -> (pid, process), only when ownership is unambiguous
        self.listen_ports = {}    # 仅 LISTEN 状态的端口 -> (pid, 进程名)
        self._proc_rates = {}     # pid -> (upload_Bps, download_Bps)，来自 Windows ETW
        self.pid_names = {}
        self.pid_parents = {}    # pid -> 父进程名（小写），通用渲染进程认爹用
        self.pid_paths = {}
        self.pid_start_times = {}
        self.last_port_scan = 0.0
        self.proxy_listen = set()  # 本机代理监听端口集合（事实代理判定的依据）
        self._tun_last = None      # (网卡名, sent, recv) TUN 网卡计数上次采样
        self._ptr_cache = {}       # IP → 反向解析主机名（"" = 无记录）
        self._ptr_pending = set()  # 正在后台解析的 IP
        # 未识别目标自动登记（域名/裸IP 认不出 → unknown-targets.json，供统一鉴定）
        self.unknown_log = UnknownTargetLog(legacy=FRIENDLY_HOSTS)
        self._ai_previous = None
        self._ai_profile = ''

    def close(self):
        """Flush the traffic ledger, then release the ETW session promptly."""
        self.unknown_log.flush()
        self.history.close()
        self.traffic.stop()

    # 已知代理软件进程名 → 显示名（子串匹配，小写）
    PROXY_PROCS = [
        ("myclash", "MyClash"),
        ("verge-mihomo", "Clash Verge"), ("clash-verge", "Clash Verge"),
        ("flclash", "FlClash"), ("mihomo-party", "Mihomo Party"),
        ("mihomo", "Mihomo"), ("clash-meta", "Clash Meta"), ("clashx", "ClashX"),
        ("clash", "Clash"), ("sing-box", "sing-box"), ("nekoray", "NekoRay"),
        ("nekobox", "NekoBox"), ("xray", "Xray"), ("v2ray", "v2ray"),
        ("hiddify", "Hiddify"), ("stash", "Stash"), ("surge", "Surge"),
    ]

    # 常驻后台服务（安装即常驻、与软件开关无关）不算"软件运行"
    SERVICE_HINTS = ("service", "helper")
    # GUI 界面进程（区别于纯内核：verge-mihomo/mihomo/clash-meta 等关窗后仍后台运行）
    GUI_HINTS = ("clash-verge", "flclash", "myclash", "mihomo-party", "clashx",
                 "nekoray", "nekobox", "hiddify", "stash", "v2rayn", "surge")
    # 常见代理监听端口（硬信号：被监听 = 有代理软件在跑，即使进程名不认识）
    PROXY_PORTS = {7890, 7891, 7892, 7893, 7897, 7877, 1080, 1087, 10808, 10809, 2080, 2081, 8889}

    def _detect_sw(self, api_on, sp_srv=""):
        """进程扫描 + 代理端口监听识别代理软件（无内核 API 的软件兜底）。3 秒一次"""
        now = time.time()
        if api_on:
            self._sw_cache = ""
            self._sw_cache_t = now
            return ""
        if now - getattr(self, "_sw_cache_t", 0) < 3:
            return getattr(self, "_sw_cache", "")
        found = ""
        try:
            for p in psutil.process_iter(["name"]):
                n = (p.info["name"] or "").lower().replace(".exe", "")
                if any(h in n for h in self.SERVICE_HINTS):
                    continue                      # HelperService / -service 常驻服务不算
                for key, label in self.PROXY_PROCS:
                    if key in n:
                        found = label
                        break
                if found:
                    break
        except Exception:
            pass
        if not found:
            # 硬信号：系统代理指向端口或常见代理端口被监听 → 有代理软件在跑
            ports = set(self.PROXY_PORTS)
            ports.update(proxy_server_ports(sp_srv))
            for port, (_pid, pname) in self.listen_ports.items():
                if port in ports and pname and pname != "?":
                    found = pname.replace(".exe", "")
                    break
        self._sw_cache = found
        self._sw_cache_t = now
        return found

    def gui_alive(self):
        """代理软件的 GUI 界面进程是否在跑（3 秒缓存）。关窗但内核后台残留时为 False"""
        now = time.time()
        if now - getattr(self, "_gui_cache_t", 0) < 3:
            return getattr(self, "_gui_cache", True)
        alive = False
        try:
            for p in psutil.process_iter(["name"]):
                n = (p.info["name"] or "").lower()
                if any(h in n for h in self.SERVICE_HINTS):
                    continue                  # clash-verge-service 等系统服务不是 GUI
                if gui_process_matches(n, getattr(self.pipe, 'client_id', '')):
                    alive = True
                    break
        except Exception:
            alive = True                      # 扫描失败时按存活处理，不误报
        self._gui_cache = alive
        self._gui_cache_t = now
        return alive

    @staticmethod
    def system_proxy():
        """返回 (系统代理开?, 代理地址)"""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, IE_KEY) as k:
                en, _ = winreg.QueryValueEx(k, "ProxyEnable")
                srv, _ = winreg.QueryValueEx(k, "ProxyServer")
            return bool(en), srv
        except OSError:
            return False, ""

    def _scan_ports(self):
        now = time.time()
        if now - self.last_port_scan < 2:
            return
        self.last_port_scan = now
        endpoint_pids = collections.defaultdict(set)
        listen_pids = collections.defaultdict(set)
        port_pids = collections.defaultdict(set)
        try:
            for c in psutil.net_connections("inet"):
                if c.laddr and c.pid:
                    endpoint_pids[(address_key(c.laddr.ip), c.laddr.port)].add(c.pid)
                    port_pids[c.laddr.port].add(c.pid)
                    if c.status == "LISTEN":
                        listen_pids[c.laddr.port].add(c.pid)
        except Exception:
            pass
        names = {}
        paths = {}
        start_times = {}
        all_pids = set()
        for pids in endpoint_pids.values():
            all_pids.update(pids)
        for pids in listen_pids.values():
            all_pids.update(pids)
        for pids in port_pids.values():
            all_pids.update(pids)
        for pid in all_pids:
            try:
                process = psutil.Process(pid)
                names[pid] = process.name()
                try:
                    paths[pid] = process.exe()
                except Exception:
                    paths[pid] = ""
                try:
                    start_times[pid] = process.create_time()
                except Exception:
                    start_times[pid] = 0.0
            except Exception:
                names[pid] = "?"
                paths[pid] = ""
                start_times[pid] = 0.0
        self.pid_names = names
        self.pid_paths = paths
        self.pid_start_times = start_times
        self.port_pid = {}
        for endpoint, pids in endpoint_pids.items():
            if len(pids) == 1:
                pid = next(iter(pids))
                self.port_pid[endpoint] = (pid, names.get(pid, "?"))
        self.port_pid_by_port = {}
        for port, pids in port_pids.items():
            if len(pids) == 1:
                pid = next(iter(pids))
                self.port_pid_by_port[port] = (pid, names.get(pid, "?"))
        self.listen_ports = {}
        for port, pids in listen_pids.items():
            # Port presence remains useful even if Windows reports shared
            # ownership; an unknown owner is safer than naming the wrong app.
            if len(pids) == 1:
                pid = next(iter(pids))
                self.listen_ports[port] = (pid, names.get(pid, "?"))
            else:
                self.listen_ports[port] = (0, "?")
        # 本机代理监听端口集合 = 已知代理端口中被监听的 + 系统代理指向的端口
        # （不含代理软件进程监听的其它端口：GUI 内部通信口会造成误判）
        pl = {port for port, (_pid, _pname) in self.listen_ports.items()
              if port in self.PROXY_PORTS}
        _en, srv = self.system_proxy()
        if _en:
            pl.update(proxy_server_ports(srv))
        self.proxy_listen = pl

    # 代理软件 TUN 模式创建的虚拟网卡名关键词
    TUN_HINTS = ("mihomo", "clash", "flclash", "sing-box", "singbox",
                 "wintun", "utun", "v2ray", "xray", "nekoray", "nekobox", "hiddify")

    # FlClash 系客户端（FlClash / MyClash 等）的本地数据库目录
    LOCAL_DB_DIRS = [
        os.path.expandvars(r"%APPDATA%\com.follow\clash"),        # FlClash
        os.path.expandvars(r"%APPDATA%\Clash Plus\Clash Plus"),   # MyClash (Clash Plus)
    ]

    def _local_db_selection(self):
        """读 FlClash 系客户端的本地数据库拿当前选中节点（selected_map），对照内核
        运行时配置确认活动订阅，防止换订阅后显示旧节点。5 秒节流，失败静默。"""
        now = time.time()
        if now - getattr(self, "_flc_t", 0) < 5:
            return getattr(self, "_flc_cache", None)
        self._flc_t = now
        sel = None
        for d in self.LOCAL_DB_DIRS:
            sel = self._read_selected_map(d)
            if sel:
                break
        self._flc_cache = sel
        return sel

    @staticmethod
    def _read_selected_map(base):
        try:
            db = os.path.join(base, "database.sqlite")
            cfg = os.path.join(base, "config.yaml")
            if not (os.path.exists(db) and os.path.exists(cfg)):
                return None
            with open(cfg, "r", encoding="utf-8", errors="ignore") as f:
                cfg_text = f.read()
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1)
            try:
                rows = con.execute(
                    "SELECT label, current_group_name, selected_map FROM profiles").fetchall()
            finally:
                con.close()
            for _label, cgroup, smap in rows:
                try:
                    m = json.loads(smap or "{}")
                except Exception:
                    continue
                # 优先用户当前展开的选择组，再遍历其余组
                items = [(cgroup, m.get(cgroup))] + [(g, n) for g, n in m.items() if g != cgroup]
                for grp, node in items:
                    if node and f'"{node}"' in cfg_text:   # 节点名在内核配置里 = 活动订阅
                        return (grp, node)
        except Exception:
            pass
        return None

    def _detect_tun(self):
        """通用模式 TUN 接管检测：存在代理软件创建的虚拟网卡且已启用。5 秒节流"""
        now = time.time()
        if now - getattr(self, "_tun_t", 0) < 5:
            return getattr(self, "_tun_cache", False)
        on = False
        try:
            for name, st in psutil.net_if_stats().items():
                if st.isup and any(h in name.lower() for h in self.TUN_HINTS):
                    on = True
                    break
        except Exception:
            pass
        self._tun_cache = on
        self._tun_t = now
        return on

    def _pid_name(self, pid):
        """进程名带兜底：TCP 扫描缓存没有（纯 UDP 进程）时现场查并补缓存"""
        name = self.pid_names.get(pid)
        if not name:
            try:
                name = psutil.Process(pid).name()
            except Exception:
                name = f"pid:{pid}"
            self.pid_names[pid] = name
        return name

    def _pid_parent_names(self, pids):
        """通用渲染进程认爹：返回这些 pid 的父进程名集合（小写排序，带缓存）"""
        out = set()
        for pid in pids:
            pp = self.pid_parents.get(pid)
            if pp is None:
                try:
                    ppid = psutil.Process(pid).ppid() or 0
                    pp = self._pid_name(ppid).lower() if ppid else ""
                except Exception:
                    pp = ""
                self.pid_parents[pid] = pp
            if pp:
                out.add(pp)
        return sorted(out)

    def _system_conns(self):
        """系统连接视图/内核列表补充源：按进程聚合对外连接（TCP 已建立 + UDP 套接字，
        覆盖 QUIC/HTTP3 视频流这类纯 UDP 流量）。指向本机代理监听端口的回环连接
        也纳入；代理/直连同时存在时明确标记为混合，不把进程总速率冒充纯代理流量。"""
        review_rows = []
        def capture_review(c, name, network):
            remote = c.raddr
            review_rows.append({
                'host': remote.ip if remote else '',
                'raw_host': remote.ip if remote else '',
                'destination_ip': remote.ip if remote else '',
                'destination_port': remote.port if remote else 0,
                'source_ip': c.laddr.ip if c.laddr else '',
                'source_port': c.laddr.port if c.laddr else 0,
                'pid': c.pid, 'proc': name,
                'process_path': getattr(self,'pid_paths',{}).get(c.pid,''),
                'network': network, 'kind': 'system', 'exit': '', 'rule': '',
                'group': '路径待确认', 'owner_source': 'system_socket',
                'owner_confidence': 'socket_pid',
            })
        agg = collections.defaultdict(lambda: {
            "n": 0, "udp": 0, "remote": [], "pids": set(), "fp": False,
            "proxy_n": 0, "direct_n": 0, "source_ports": set(),
        })
        try:
            for c in psutil.net_connections("tcp"):
                if c.status != "ESTABLISHED" or not c.raddr or not c.pid:
                    continue
                ip = c.raddr.ip
                fact = is_loopback_address(ip) and c.raddr.port in self.proxy_listen
                if not fact and is_local_address(ip):
                    continue
                name = self._pid_name(c.pid)
                capture_review(c, name, 'tcp')
                a = agg[name]
                a["n"] += 1
                a["pids"].add(c.pid)
                if c.laddr:
                    a["source_ports"].add(int(c.laddr.port))
                if fact:
                    a["fp"] = True
                    a["proxy_n"] += 1
                else:
                    a["direct_n"] += 1
                if len(a["remote"]) < 5:
                    a["remote"].append(f"{ip}:{c.raddr.port}")
        except Exception:
            pass
        try:
            for c in psutil.net_connections("udp"):       # UDP/QUIC：无状态，套接字噪声大，每进程最多记 2 条
                if not c.pid:
                    continue
                fact = False
                if c.raddr:
                    fact = (is_loopback_address(c.raddr.ip)
                            and c.raddr.port in self.proxy_listen)
                    if not fact and is_local_address(c.raddr.ip):
                        continue
                udp_name = self._pid_name(c.pid)
                capture_review(c, udp_name, 'udp')
                a = agg[udp_name]
                a["pids"].add(c.pid)
                if c.laddr:
                    a["source_ports"].add(int(c.laddr.port))
                a["udp"] = min(a["udp"] + 1, 2)
                if fact:
                    a["fp"] = True
                    a["proxy_n"] += 1
                elif c.raddr:
                    a["direct_n"] += 1
                if c.raddr and len(a["remote"]) < 5:
                    a["remote"].append(f"{c.raddr.ip}:{c.raddr.port}(UDP)")
        except Exception:
            pass

        # ETW sees short-lived TCP requests and unconnected UDP/QUIC traffic that
        # may already be absent from psutil's point-in-time connection table.
        for pid, (up, down) in self._proc_rates.items():
            if up + down > 0:
                agg[self._pid_name(pid)]["pids"].add(pid)

        rows = []
        # 按 ETW 精准上下行合计排序（谁在用网谁靠前），同速率按连接数
        for name, a in sorted(agg.items(),
                              key=lambda kv: (-sum(sum(self._proc_rates.get(pid, (0.0, 0.0)))
                                                   for pid in kv[1]["pids"]),
                                              -(kv[1]["n"] + kv[1]["udp"]))):
            up = sum(self._proc_rates.get(pid, (0.0, 0.0))[0] for pid in a["pids"])
            down = sum(self._proc_rates.get(pid, (0.0, 0.0))[1] for pid in a["pids"])
            rate = up + down
            n = name.lower().replace(".exe", "")
            is_sw = (any(k in n for k, _lbl in self.PROXY_PROCS)
                     and not any(h in n for h in self.SERVICE_HINTS))
            total_n = a["n"] + a["udp"]
            route_state = system_route_state({
                "fact_proxy": a["fp"],
                "proxy_socket_count": a["proxy_n"],
                "direct_socket_count": a["direct_n"],
            })
            rows.append({"host": name, "exit": "",
                         "group": f"×{total_n} 条" if total_n else "刚结束",
                         "rule": "", "kind": "sys", "rate": rate, "proc": name,
                         "proc_parent": (self._pid_parent_names(a["pids"])
                                         if name.lower() in GENERIC_RENDERERS else ""),
                         "remote": a["remote"], "up": up, "down": down,
                         "metered": self.traffic.accurate,
                         "pids": sorted(a["pids"]),
                         "source_ports": sorted(a["source_ports"]),
                         "is_proxy_sw": is_sw, "fact_proxy": a["fp"],
                         "proxy_socket_count": a["proxy_n"],
                         "direct_socket_count": a["direct_n"],
                         "has_direct": a["direct_n"] > 0,
                         "route_state": route_state})
        try:
            self.unknown_log.note(review_rows, 'system')
        except Exception:
            LOG.exception('system unknown-target registration failed')
        return rows[:20]

    def _tun_rates(self, dt):
        """TUN 模式下代理流量精确上下行：代理软件虚拟网卡的独立收发计数（无需管理员）"""
        try:
            for name, io in psutil.net_io_counters(pernic=True).items():
                if any(h in name.lower() for h in self.TUN_HINTS):
                    prev = self._tun_last
                    self._tun_last = (name, io.bytes_sent, io.bytes_recv)
                    if prev and prev[0] == name and dt > 0:
                        return (max(io.bytes_sent - prev[1], 0) / dt,
                                max(io.bytes_recv - prev[2], 0) / dt)
        except Exception:
            pass
        return 0.0, 0.0

    @staticmethod
    def _is_ip(host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _ptr_lookup(self, ip):
        """IP 反向解析（后台线程，不阻塞）：有缓存直接返回，没有返回 None 并发起查询"""
        if ip in self._ptr_cache:
            return self._ptr_cache[ip] or None
        if ip in self._ptr_pending:
            return None
        if len(self._ptr_pending) >= 16:
            return None
        self._ptr_pending.add(ip)

        def job():
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = ""
            self._ptr_cache[ip] = name
            if len(self._ptr_cache) > 2048:
                self._ptr_cache.pop(next(iter(self._ptr_cache)), None)
            self._ptr_pending.discard(ip)

        threading.Thread(target=job, daemon=True).start()
        return None

    def tick(self):
        now = time.time()
        dt = max(now - self.last_time, 0.1)
        self.last_time = now
        net = psutil.net_io_counters()
        sys_up = max(net.bytes_sent - self.last_net.bytes_sent, 0) / dt
        sys_down = max(net.bytes_recv - self.last_net.bytes_recv, 0) / dt
        self.last_net = net
        self._scan_ports()
        self._proc_rates = self.traffic.snapshot()

        sp_on, sp_srv = self.system_proxy()
        api_on = self.pipe.available()
        cfg = self.pipe.configs() if api_on else {}
        api_on = bool(api_on and cfg.get("mode") in ("rule", "global", "direct"))
        sw_name = self._detect_sw(api_on, sp_srv)
        if api_on:
            sw_name = CLIENT_LABELS.get(getattr(self.pipe, 'client_id', ''), sw_name)
        r = {
            "sys_up": sys_up, "sys_down": sys_down,
            "sw_on": api_on or bool(sw_name),
            "api_on": api_on, "sw_name": sw_name,
            "sp_on": sp_on, "sp_srv": sp_srv,
            "tun_on": False, "strict_route": None, "mode": "?",
            "n_direct": 0, "n_proxy": 0, "n_reject": 0,
            "proxy_up": 0.0, "proxy_down": 0.0, "proxy_total": 0.0,
            "proxy_total_estimated": False,
            "conns": [], "groups": [], "rule_top": [], "in_use_node": "",
            "sel_group": "", "sel_node": "", "active_group": "", "active_node": "",
            "ai_group": "", "ai_node": "", "ai_group_type": "", "ai_source": "",
            "proxy_routes": [],
            "active_route_group": "", "active_route_exit": "",
            "list_mode": "sys", "global_now": "",
            "gui_alive": self.gui_alive(),
            "channel": self.pipe.channel_name,
            "api_generation": getattr(self.pipe, "generation", 0),
            "core_version": getattr(self.pipe, "version", ""),
            "api_error": getattr(self.pipe, "last_error", ""),
            "target_unified": True,
            "traffic_status": self.traffic.status,
            "traffic_status_text": self.traffic.status_text(),
            "traffic_accurate": self.traffic.accurate,
            "traffic_elevated": self.traffic.elevated,
            "traffic_events": self.traffic.event_count,
            "history_status": self.history.status,
            "history_error": self.history.last_error,
            "history_path": self.history.db_path,
            "history_dropped": self.history.dropped_batches,
        }
        # 接管判定：软件运行 +（系统代理开 或 TUN 开）才算代理接管
        takeover = sp_on
        if api_on:
            r["mode"] = cfg.get("mode", "?")
            r["tun_on"] = bool((cfg.get("tun") or {}).get("enable"))
            r["strict_route"] = strict_route_state(cfg, api_on)
            takeover = takeover or r["tun_on"]
            proxy_snapshot = self.pipe.proxies()
            r["groups"] = self.pipe.active_groups(proxy_snapshot)
            sel = self.pipe.main_selection(proxy_snapshot)
            if sel:
                r["sel_group"], r["sel_node"] = sel
            ai_sel = probe_selection(self.pipe, proxy_snapshot, r["mode"])
            if ai_sel:
                r["ai_group"], r["ai_node"], r["ai_group_type"] = ai_sel
                r["ai_source"] = ("全局 GLOBAL" if r["mode"] == "global" else
                                  ("AI策略组" if _ai_group_rank(r["ai_group"]) is not None
                                   else "唯一主选择组（订阅无独立AI组）"))
            r["global_now"] = self.pipe.global_selection(proxy_snapshot)  # 全局模式真实出口
            data = self.pipe.connections()
            if not isinstance(data.get("connections"), list):
                api_on = r["api_on"] = False
                r["api_error"] = getattr(self.pipe, "last_error", "") or "连接接口返回无效数据"
            else:
                explicit = any(user_explicit_proxy(c) for c in data["connections"])
                r["explicit_proxy"] = explicit
                takeover = takeover or explicit
        elif sw_name:
            # 通用模式：检测代理软件创建的虚拟网卡来识别 TUN 接管
            r["tun_on"] = self._detect_tun()
            takeover = takeover or r["tun_on"]
            # FlClash 系客户端：从本地数据库读真实选中节点
            sel = self._local_db_selection()
            if sel:
                r["sel_group"], r["sel_node"] = sel
        r["takeover"] = takeover and (api_on or bool(sw_name))
        r['ai_target_state'] = 'waiting'
        r['main_proxy_port'] = int(cfg.get('mixed-port') or cfg.get('port') or 0)
        r['profile_id'] = profile_id(getattr(self.pipe, '_chan', None), getattr(self.pipe, 'client_id', None))
        if r['profile_id'] != getattr(self, '_ai_profile', ''):
            self._ai_previous = None
            self._ai_profile = r['profile_id']
        if api_on and takeover:
            observed = list(data.get('connections') or [])
            hint = getattr(self.pipe, 'ai_route_hint', None)
            if hint and hint.get('mode') == r['mode'] and hint.get('profile') == r['profile_id'] and time.monotonic()-hint['at']<30:
                if hint.get('route'):
                    observed.append(hint['route'])
            target = ai_target(observed, proxy_snapshot, r['mode'], getattr(self, '_ai_previous', None))
            self._ai_previous = target
            r.update(ai_target_state=target['state'], ai_node=target['node'], ai_group=target['group'],
                     ai_source=target['evidence'], other_ai_exits=target.get('other_ai_exits',0))
        else:
            self._ai_previous = None
            r.update(ai_node='', ai_group='', ai_source='未开启代理接管')

        # 无内核接口或未接管 → 系统进程连接视图（窗口始终有内容）
        if not (api_on and takeover):
            self._display_proxy = ("", "")
            self.conn_bytes = {}
            r["conns"] = self._system_conns()
            # 通用模式下的代理流量估算：
            #  TUN 接管 → 虚拟网卡独立收发计数（精确拆分 ↑↓，无需管理员）
            #  系统代理 → 指向本机代理端口的回环连接速率合计（收发合并值）
            if sw_name and takeover:
                if r["tun_on"]:
                    # TUN counters include DIRECT. They are not proven node bytes.
                    r["tun_up"], r["tun_down"] = self._tun_rates(dt)
                    r["proxy_stats_unknown"] = True
                else:
                    r["proxy_total"] = sum(c["rate"] for c in r["conns"]
                                           if c.get("fact_proxy"))
                    r["proxy_total_estimated"] = True
            return r

        r["list_mode"] = "proxy"

        rules = collections.Counter()
        exit_counter = collections.Counter()
        route_stats = {}
        proxy_route_stats = {}
        rows = []
        history_rows = []
        new_bytes = {}
        active_connection_ids = set()
        owner_cache = getattr(self, "connection_owners", {})
        for c in data.get("connections") or []:
            meta = c.get("metadata", {})
            destination_domain = str(meta.get("host") or "")
            destination_ip = str(meta.get("destinationIP") or "")
            host = destination_domain or destination_ip or "?"
            raw_host = host
            if self._is_ip(host):                 # IP 目标：后台反解成主机名
                ptr = self._ptr_lookup(host)
                if ptr:
                    host = ptr
            chains = c.get("chains") or []
            route_kind, exit_node, raw_group = route_evidence(chains, proxy_snapshot)
            group = raw_group
            # 全局/直连模式没有规则组概念，统一成带图标的徽标，与规则模式视觉一致
            if group.upper() == "GLOBAL":
                group = f"🌐 {exit_node}"                     # 全局：徽标显示出口节点
            elif group.upper() in ("", "DIRECT") and exit_node.upper() == "DIRECT":
                group = "🎯 直连"
            elif group.upper().startswith("REJECT"):
                group = "⛔ 拦截"
            eu = exit_node.upper()
            is_direct = route_kind == "direct"
            is_reject = route_kind == "reject"
            if is_direct:
                r["n_direct"] += 1
            elif is_reject:
                r["n_reject"] += 1
            elif route_kind == "proxy":
                r["n_proxy"] += 1
                exit_counter[exit_node] += 1
            rule_name = str(c.get("rule") or "")
            rule_payload = str(c.get("rulePayload") or "")
            rule = f"{rule_name}/{rule_payload}".strip("/")
            # 全局/直连模式无规则命中：如实标注，不显示无意义的 Match
            mode_now = r.get("mode", "")
            if not rule and mode_now in ("global", "direct"):
                rule = "全局" if mode_now == "global" else "直连"
            rules[rule or "Match"] += 1
            cid = c.get("id")
            cache_key = str(cid or "")
            if cache_key:
                active_connection_ids.add(cache_key)
            up, down = c.get("upload", 0), c.get("download", 0)
            prev = self.conn_bytes.get(cid, (up, down))
            delta_up = max(up - prev[0], 0)
            delta_down = max(down - prev[1], 0)
            rate = (delta_up + delta_down) / dt
            new_bytes[cid] = (up, down)
            stat = route_stats.setdefault((raw_group, exit_node), [0, 0])
            stat[0] += delta_up + delta_down
            stat[1] += 1
            if route_kind == "proxy":                       # 事实代理流量
                r["proxy_up"] += delta_up / dt
                r["proxy_down"] += delta_down / dt
                proxy_stat = proxy_route_stats.setdefault((raw_group, exit_node), [0, 0])
                proxy_stat[0] += delta_up + delta_down
                proxy_stat[1] += 1
            sip, sport = meta.get("sourceIP"), int(meta.get("sourcePort") or 0)
            socket_owner, socket_source = source_process_owner_detail(
                self.port_pid, self.port_pid_by_port, sip, sport,
            )
            metadata_path = str(meta.get("processPath") or "")
            metadata_process = str(meta.get("process") or "")
            meta_owner = metadata_process_owner(
                getattr(self, "pid_names", {}), getattr(self, "pid_paths", {}),
                getattr(self, "pid_start_times", {}), metadata_process, metadata_path,
            )
            stable_owner = resolve_connection_owner(
                metadata_process=metadata_process,
                metadata_path=metadata_path,
                metadata_owner=meta_owner,
                socket_owner=socket_owner,
                socket_source=socket_source,
                cached=owner_cache.get(cache_key),
                pid_paths=getattr(self, "pid_paths", {}),
                pid_start_times=getattr(self, "pid_start_times", {}),
                observed_at=now,
            )
            if cache_key:
                owner_cache[cache_key] = stable_owner
            pid = stable_owner["pid"]
            pname = stable_owner["name"]
            process_path = stable_owner["path"]
            process_start_time = stable_owner["start_time"]
            traffic_role = traffic_role_for(
                sport, destination_domain or destination_ip, pname, process_path, now,
            )
            if delta_up or delta_down:
                history_rows.append({
                    "connection_id": str(cid or ""),
                    "process_pid": pid,
                    "process_name": pname,
                    "process_path": process_path,
                    "process_start_time": process_start_time,
                    "source_ip": str(sip or ""),
                    "source_port": sport,
                    "destination_host": destination_domain or destination_ip,
                    "destination_ip": destination_ip,
                    "destination_port": int(meta.get("destinationPort") or 0),
                    "network": str(meta.get("network") or ""),
                    "rule": rule_name or ("GLOBAL" if mode_now == "global" else
                                           ("DIRECT" if mode_now == "direct" else "")),
                    "rule_payload": rule_payload,
                    "route_kind": route_kind,
                    "route_group": raw_group,
                    "exit_node": exit_node,
                    "multiplier": parse_traffic_multiplier(exit_node, raw_group, *chains),
                    "chain": " > ".join(str(item) for item in chains),
                    "owner_source": stable_owner["source"],
                    "owner_confidence": stable_owner["confidence"],
                    "traffic_role": traffic_role,
                    "upload_bytes": delta_up,
                    "download_bytes": delta_down,
                })
            rows.append({
                "host": host, "exit": exit_node, "group": group,
                "rule": rule, "kind": route_kind,
                "rate": rate, "proc": pname, "raw_host": raw_host,
                "pid": pid, "process_path": process_path, "source_port": sport,
                "source_ip": str(sip or ''), "destination_ip": destination_ip,
                "destination_port": int(meta.get('destinationPort') or 0),
                "network": str(meta.get('network') or ''), "connection_id": cache_key,
                "owner_source": stable_owner['source'],
                "owner_confidence": stable_owner['confidence'],
                "up": delta_up / dt, "down": delta_down / dt,
            })
        if history_rows:
            self.history.record(history_rows, observed_at=now)
        # Register before GUI merging/truncation so PID, port and exit survive.
        try:
            self.unknown_log.note(rows, 'proxy')
        except Exception:
            LOG.exception('kernel unknown-target registration failed')
        self.conn_bytes = new_bytes
        self.connection_owners = {
            key: value for key, value in owner_cache.items()
            if key in active_connection_ids or now - float(value.get("last_seen", 0)) < 300
        }
        # 相同目标+同类出路的连接合并成一行（×N）：QUIC 会对同一地址开十几条长连接刷屏
        merged = {}
        for row in rows:
            key = (row["host"], row["kind"], row["group"], row["exit"], row["proc"])
            m = merged.get(key)
            if m is None:
                row["n"] = 1
                merged[key] = row
            else:
                m["n"] += 1
                m["rate"] += row["rate"]
                m["up"] += row["up"]
                m["down"] += row["down"]
        rows = list(merged.values())
        rows.sort(key=lambda x: -x["rate"])
        # 系统代理模式下补充 API 未覆盖的进程。系统套接字只能证明它连接过
        # 本机代理端口，不能证明最终走 DIRECT 还是节点，因此统一保留蓝色待确认。
        # TUN 模式全网卡接管，无需补充（也避免重复）。
        if not r["tun_on"]:
            kernel_procs = {row["proc"] for row in rows}
            known_kernel_procs = {
                str(name).casefold() for name in kernel_procs if name not in ("", "?")
            }
            known_kernel_pids = {int(row.get("pid") or 0) for row in rows
                                 if int(row.get("pid") or 0) > 0}
            known_source_ports = {int(row.get("source_port") or 0) for row in rows
                                  if int(row.get("source_port") or 0) > 0}
            for srow in self._system_conns():
                overlaps_pid = bool(known_kernel_pids.intersection(srow.get("pids") or []))
                overlaps_port = bool(known_source_ports.intersection(
                    srow.get("source_ports") or []))
                if (not overlaps_pid and not overlaps_port
                        and str(srow["proc"]).casefold() not in known_kernel_procs
                        and not srow.get("is_proxy_sw")):
                    badge, display_class = supplemental_system_status(srow)
                    srow["group"] = badge
                    srow["display_class"] = display_class
                    rows.append(srow)
            rows.sort(key=lambda x: -x["rate"])   # 合并重排：有流量的系统进程也能挤进前20
        r["conns"] = rows[:20]
        r["rule_top"] = rules.most_common(5)
        r["active_route_group"], r["active_route_exit"] = choose_primary_route(route_stats)
        r["active_group"], r["active_node"] = choose_display_proxy(
            proxy_route_stats, getattr(self, "_display_proxy", ("", "")))
        self._display_proxy = (r["active_group"], r["active_node"])
        r["proxy_routes"] = [(group, node, value[1])
                             for (group, node), value in sorted(proxy_route_stats.items())]
        if r["active_node"]:
            r["in_use_node"] = r["active_node"]
        elif exit_counter:
            r["in_use_node"] = exit_counter.most_common(1)[0][0]
        elif r["groups"]:
            r["in_use_node"] = r["groups"][0][1]
        return r


# ----------------------------- 呼吸灯 -----------------------------

class LightDot(QWidget):
    def __init__(self, label="", size=16, parent=None):
        super().__init__(parent)
        self.state = "off"          # off / ok / bad / warn
        self.phase = 0.0
        self.label_text = label
        self._s = size
        self.setFixedSize(size, size)
        self.setToolTip(label)

    def set_state(self, s):
        if s != self.state:
            self.state = s
            self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        base = {"off": GRAY, "ok": GREEN, "bad": RED, "warn": YELLOW}[self.state]
        c = QColor(base)
        s = self._s
        # 平缓呼吸灯：ok 慢速深呼吸（2.4s 周期），bad 急促脉冲，warn 中速，off 静止
        if self.state == "ok":
            t = (math.sin(self.phase) + 1) / 2          # 0..1
            glow = 0.25 + 0.75 * t
        elif self.state == "bad":
            t = abs(math.sin(self.phase * 2.4))
            glow = 0.30 + 0.70 * t
        elif self.state == "warn":
            t = (math.sin(self.phase * 1.5) + 1) / 2
            glow = 0.35 + 0.55 * t
        else:
            glow = 0.25
        g = QRadialGradient(s / 2, s / 2, s / 2)
        gc = QColor(c); gc.setAlpha(int(235 * glow))
        g.setColorAt(0, gc)
        middle=QColor(c);middle.setAlpha(int(145*glow));g.setColorAt(.48,middle)
        gc2 = QColor(c); gc2.setAlpha(0)
        g.setColorAt(1, gc2)
        p.setBrush(QBrush(g)); p.setPen(Qt.NoPen)
        p.drawRect(0, 0, s, s)
        if self.state!='off':c=c.darker(int(165-65*glow))
        p.setBrush(QBrush(c))
        m = s / 4
        p.drawEllipse(QPoint(int(s / 2), int(s / 2)), int(s / 4), int(s / 4))


# ----------------------------- 连接行 -----------------------------

class ConnRow(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyleSheet("""
            ConnRow { background: rgba(255,255,255,12); border-radius: 6px; }
            QLabel { background: transparent; border: none; }
        """)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 3, 8, 3)
        lay.setSpacing(6)
        self.dot = QLabel("●")
        self.dot.setFixedWidth(10)
        self.dot.setAlignment(Qt.AlignCenter)
        self.host = QLabel()
        self.host.setMinimumWidth(0)
        # QLabel 的 sizeHint 会随长进程名增长；Ignored 才能让布局在窄窗口中
        # 真正压缩这一列，把固定的速率/规则组两列留在可视区域内。
        self.host.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.host.setStyleSheet(f"color:{FG}; font-size:12px;")
        self.route = QLabel()
        self.route.setFixedWidth(76)
        self.route.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.route.setStyleSheet(f"color:{DIM}; font-size:11px;")
        self.rate = QLabel()
        self.rate.setFixedWidth(104)
        self.rate.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.rate.setStyleSheet(f"color:{FG}; font-size:11px;")
        for label in (self.host, self.route, self.rate):
            label.setTextFormat(Qt.PlainText)
        lay.addWidget(self.dot)
        lay.addWidget(self.host, 1)
        lay.addWidget(self.rate)     # 速率在前
        lay.addWidget(self.route)    # 规则徽标在后

    def set_data(self, r):
        kind = r["kind"]
        if kind == "sys":
            # 系统连接视图：管理员模式由 Windows ETW 精准拆分进程上下行。
            is_sw = r.get("is_proxy_sw", False)
            fact = r.get("fact_proxy", False)                # 至少一个套接字连接本机代理端口
            route_state = system_route_state(r)
            busy = (is_sw or fact) and r.get("rate", 0) > 512  # 代理相关且有流量 = 正在转发
            metered = r.get("metered", False)
            idle = r.get("rate", 0) <= 8
            color = connection_color(r)
            style_key = ("sys", color, is_sw)
            if getattr(self, "_style_key", None) != style_key:
                self.dot.setStyleSheet(f"color:{color}; font-size:10px;")
                self.host.setStyleSheet(f"color:{FG}; font-size:12px;")
                self.rate.setStyleSheet(f"color:{color}; font-size:11px;")
                self.route.setStyleSheet(f"color:{color}; font-size:11px;")
            self._style_key = style_key
            # 与代理视图同一套命名：命中别名 → 友好名，否则去 .exe；原始进程名见悬停提示
            disp = connection_name(r, FRIENDLY_HOSTS)
            _lbl_set(self.host, disp[:23] if len(disp) <= 23 else disp[:22] + "…")
            if metered:
                up, down = r.get("up", 0), r.get("down", 0)
                _lbl_set(self.rate, "空闲" if idle else f"↑{fmt_speed(up)} ↓{fmt_speed(down)}")
            else:
                _lbl_set(self.rate, "↑— ↓—")
            _praw = str(r.get('proc') or '')
            _fp = friendly_proc(_praw)
            _ptxt = _fp if (not _praw or _fp.lower() == _praw.lower()) else f"{_fp}（{_praw}）"
            tip = f"进程: {_ptxt or '未知'}"
            if is_sw:
                tip += "（代理软件" + ("·正在转发流量" if busy else "·空闲") + "）"
            elif route_state == "mixed":
                tip += ("（同时检测到本机代理端口和外部目标）"
                        "\n最终出口尚未由 Mihomo API 确认，因此保持系统蓝色")
            elif route_state == "proxy_related":
                tip += ("（检测到连接本机代理端口）"
                        "\n这不代表最终走代理节点；确认前保持系统蓝色")
            if metered:
                tip += ("\n速率: Windows ETW 精准进程上下行"
                        "\n覆盖 TCP、UDP/QUIC；无需安装第三方驱动")
            else:
                tip += ("\n当前仅显示连接，未把磁盘/其它 I/O 冒充网络流量"
                        "\n请从托盘选择“启用精准进程流量（管理员）”")
            remotes = r.get("remote", [])
            if remotes:
                tip += "\n对外连接:\n" + "\n".join(remotes)
            _tip_set(self, tip)
            badge = r["group"]
            if badge in ("未接管", "代理相关", "混合流量",
                         "系统连接", "路径待确认"):
                # Recompute semantic badges at render time as a final invariant.
                badge, _display_class = supplemental_system_status(r)
            _lbl_set(self.route, badge)
            return
        color = connection_color(r)
        # 每条连接的实时上下行（内核 API 精确拆分），显示在规则徽标前
        up, down = r.get("up", 0), r.get("down", 0)
        idle = (up + down) <= 8
        style_key = ("proxy", color)
        if getattr(self, "_style_key", None) != style_key:
            self.dot.setStyleSheet(f"color:{color}; font-size:10px;")
            self.host.setStyleSheet(f"color:{FG}; font-size:12px;")
            self.route.setStyleSheet(f"color:{color}; font-size:11px;")
            self.rate.setStyleSheet(f"color:{color}; font-size:11px;")
        self._style_key = style_key
        host = r["host"]
        disp = connection_name(r, FRIENDLY_HOSTS)
        _lbl_set(self.host, disp if len(disp) <= 26 else disp[:25] + "…")
        shown_exit = "直连" if kind == "direct" else ("拦截" if kind == "reject" else (r["exit"] or "未确认"))
        badge = (r["group"] or shown_exit)
        if kind == "system":
            badge = "路径待确认"
        elif kind == "direct":
            badge = "直连"
        elif kind == "reject":
            badge = "拦截"
        if r.get("n", 1) > 1:
            badge = f"{badge}×{r['n']}"               # 多条相同目标合并显示
        _lbl_set(self.route, badge[:12])
        tip_host = r.get("raw_host") or host
        if tip_host != host:
            tip_host = f"{host}\n原始地址: {tip_host}"
        _praw = str(r.get('proc') or '')
        if not _praw or _praw in ('?', ':System'):
            _ptxt = '未知进程'
        else:
            _fp = friendly_proc(_praw)
            _ptxt = _fp if _fp.lower() == _praw.lower() else f"{_fp}（{_praw}）"
        _tip_set(self,
                 f"显示名称: {disp}\n名称依据: {label_basis(r, FRIENDLY_HOSTS)}\n原始目标: {tip_host}\n真实出口: {shown_exit}\n规则组: {r['group']}\n"
                 f"命中规则: {r['rule'] or 'Match'}\n来源进程: {_ptxt}"
                 + (f"\n程序路径: {r['process_path']}" if r.get('process_path') else '')
                 + (f"\n合并连接数: {r['n']}" if r.get("n", 1) > 1 else ""))
        _lbl_set(self.rate, "空闲" if idle else f"↑{fmt_speed(up)} ↓{fmt_speed(down)}")


# ----------------------------- 速度曲线 -----------------------------

class Sparkline(QWidget):
    def __init__(self, color, parent=None):
        super().__init__(parent)
        self.color = QColor(color)
        self.data = collections.deque(maxlen=60)
        self.setFixedHeight(30)

    def push(self, v):
        self.data.append(v)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        if len(self.data) < 2:
            return
        mx = max(max(self.data), 1)
        w, h = self.width(), self.height()
        pts = [QPoint(int(i * w / 59), int(h - 3 - (v / mx) * (h - 8))) for i, v in enumerate(self.data)]
        fill = QPainterPath()
        fill.moveTo(pts[0].x(), h)
        for pt in pts:
            fill.lineTo(pt)
        fill.lineTo(pts[-1].x(), h)
        fill.closeSubpath()
        c = QColor(self.color); c.setAlpha(45)
        p.fillPath(fill, c)
        p.setPen(QPen(self.color, 2))
        for a, b in zip(pts, pts[1:]):
            p.drawLine(a, b)


# ----------------------------- 主窗口 -----------------------------

class NetMonitorWidget(QWidget):
    # 300px 会把进程名、双向速率和规则组挤在一起；380px 可在常见
    # 100%~150% DPI 下完整保留右侧两列，同时仍适合作为桌面小组件。
    W, H = 380, 680
    H_BARE = 535          # 精简状态（无节点信息块）高度：连接区同样固定露 ~10 行
    MINI_V = (78, 205)
    MINI_H = (272, 54)
    PROBE_CHOICES = [("30 秒", 30), ("1 分钟", 60), ("5 分钟", 300), ("10 分钟", 600), ("半小时", 1800)]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetMonitor Pro v22")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.engine = DataEngine()
        self.settings = QSettings("NetMonitorPro", "NetMonitorPro")
        # v17's 30-second default produced needless background test traffic.
        # Migrate that legacy default once; users may still explicitly select
        # 30 seconds afterwards if they value faster detection.
        if not self.settings.value("probe_interval_v18_migrated", False, type=bool):
            if int(self.settings.value("probe_interval", 30)) == 30:
                self.settings.setValue("probe_interval", 300)
            self.settings.setValue("probe_interval_v18_migrated", True)
        self._on_top = self.settings.value("always_on_top", True, type=bool)
        if self._on_top:
            self.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        self.mode = "full"           # full / mini_v / mini_h
        self._bare = False           # 精简状态（内核后台/无内核）
        self._target_h = self.H      # 完整模式当前目标高度（随状态在 H / H_BARE 间切换）
        self.pinned = False
        self.drag_pos = None
        self._shutting_down = False
        self.probe_worker = None
        self.probe_retry_timer = QTimer(self)
        self.probe_retry_timer.setSingleShot(True)
        self.probe_retry_timer.timeout.connect(self.start_probe)
        self.probe_state = None      # True/False/None(未测)
        self.quality_worker = None
        self.route_worker = None
        self.quality_cache = QualityCache()
        self._route_retry_at = 0.0
        self.history_export_worker = None
        self._prev_sw_on = False
        self._prev_take = False
        self._prev_node = ""
        self._build_ui()
        self._build_tray()
        self._last_sample_at = time.monotonic()
        self.sampler = EngineSampler(self.engine)

        # 数据刷新
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        # 灯光动画（约 22fps，占用可忽略）
        self.anim = QTimer(self)
        self.anim.timeout.connect(self._animate)
        self.anim.start(45)
        # 探测定时
        self.probe_timer = QTimer(self)
        self.probe_timer.timeout.connect(self.start_probe)
        self._apply_probe_interval()
        QTimer.singleShot(800, self.start_probe)

        # 只恢复"位置"，不恢复尺寸（Qt 无边框窗口 restoreGeometry 会在 show 时
        # 盖掉 resize，旧尺寸阴魂不散；尺寸永远以代码 W×H 为准，连接区固定 ~10 行）
        self.resize(self.W, self.H)
        pos = self.settings.value("pos")
        if pos is not None:
            self.move(pos)
        # 钳制进当前屏幕（防止上次贴在右/下边缘退出后溢出屏幕）
        scr = self._cur_screen()
        fw, fh = self.frameGeometry().width(), self.frameGeometry().height()
        nx = max(scr.left(), min(self.x(), scr.right() - fw + 1))
        ny = max(scr.top(), min(self.y(), scr.bottom() - fh + 1))
        self.move(nx, ny)
        QTimer.singleShot(150, self._enforce_size)
        # 关机/注销也会触发 aboutToQuit：先收拢网络线程，再关闭 ETW，避免
        # PyInstaller 窗口版在 QThread 尚未退出时销毁对象而异常终止。
        QApplication.instance().aboutToQuit.connect(self._shutdown)

    # ---------- UI 构建 ----------
    def _enforce_size(self):
        """首次显示后强制标准尺寸（仅完整模式；迷你条模式不打扰）"""
        if self.mode == "full":
            self.setFixedWidth(self.W)
            self.resize(self.W, getattr(self, "_target_h", self.H))

    def _build_ui(self):
        self.setFixedWidth(self.W)
        self.resize(self.W, self.H)
        root = QVBoxLayout(self)
        root.setContentsMargins(EDGE_GAP, EDGE_GAP, EDGE_GAP, EDGE_GAP)
        self.panel = QFrame()
        self.panel.setObjectName("panel")
        self.panel.setStyleSheet(f"""
            #panel {{ background: {theme.BACKGROUND}; border-radius: 13px;
                     border: 1px solid #647084; }}
            QLabel {{ color: {FG}; background: transparent; }}
            {theme.controls_css()}
            QScrollArea {{ border: none; background: transparent; }}
        """)
        root.addWidget(self.panel)
        pl = QVBoxLayout(self.panel)
        pl.setContentsMargins(10, 8, 10, 8)
        pl.setSpacing(5)

        # ===== 迷你条（吸附态）：竖版 + 横版两套独立容器 =====
        def build_strip(horizontal):
            w = QWidget()
            lay = QHBoxLayout() if horizontal else QVBoxLayout()
            lay.setContentsMargins(8, 3, 8, 3) if horizontal else lay.setContentsMargins(3, 6, 3, 6)
            lay.setSpacing(9 if horizontal else 4)
            light = LightDot("AI服务当前手选节点的可用状态", size=20)
            g_up = QLabel("↑0"); g_down = QLabel("↓0")
            p_up = QLabel("↑0"); p_down = QLabel("↓0")
            gl = QLabel("全"); plb = QLabel("代")
            gl.setStyleSheet(f"color:{GREEN}; font-size:11px;")
            plb.setStyleSheet(f"color:{YELLOW}; font-size:11px;")
            for l in (g_up, g_down):
                l.setStyleSheet(f"color:{GREEN}; font-size:11px; font-weight:600;")
            for l in (p_up, p_down):
                l.setStyleSheet(f"color:{YELLOW}; font-size:11px; font-weight:600;")
            for x in (gl, g_up, g_down, plb, p_up, p_down):
                x.setAlignment(Qt.AlignCenter)
            lay.addWidget(light, 0, Qt.AlignCenter)
            for x in (gl, g_up, g_down, plb, p_up, p_down):
                lay.addWidget(x)
            w.setLayout(lay)
            return w, light, (g_up, g_down, p_up, p_down)

        self.mini_v, self.mini_v_light, self.mini_v_labels = build_strip(False)
        self.mini_h, self.mini_h_light, self.mini_h_labels = build_strip(True)
        pl.addWidget(self.mini_v)
        pl.addWidget(self.mini_h)
        self.mini_v.hide()
        self.mini_h.hide()

        # ===== 全盘面板 =====
        self.full = QWidget()
        fl = QVBoxLayout(self.full)
        fl.setContentsMargins(0, 0, 0, 0)
        fl.setSpacing(5)
        pl.addWidget(self.full)

        # 标题栏
        top = QHBoxLayout()
        title = QLabel("⚡ NetMonitor Pro 22")
        title.setStyleSheet("font-size:13px; font-weight:600;")
        btn_close = QPushButton("✕")
        btn_close.setFixedWidth(28)
        btn_close.clicked.connect(self.hide)
        self.btn_pin = QPushButton("📌")
        self.btn_pin.setFixedWidth(28)
        self.btn_pin.setCheckable(True)
        self.btn_pin.setChecked(self._on_top)
        self.btn_pin.setToolTip("窗口置顶开关（点亮=始终置顶）")
        self.btn_pin.setStyleSheet(
            "QPushButton { border: 1px solid transparent; border-radius: 4px; padding: 1px; opacity: 0.45; }"
            "QPushButton:checked { border: 1px solid #4C9AFF; border-radius: 4px;"
            " background: rgba(76,154,255,0.22); opacity: 1.0; }")
        self.btn_pin.clicked.connect(self._toggle_on_top)
        top.addWidget(title); top.addStretch(1)
        top.addWidget(self.btn_pin); top.addWidget(btn_close)
        fl.addLayout(top)

        # 三盏灯
        lights = QHBoxLayout()
        self.light_sw = LightDot("代理软件运行状态", size=27)
        self.light_take = LightDot("代理接管状态（系统代理/TUN）", size=27)
        self.light_node = LightDot("AI服务当前手选节点的可用状态", size=27)
        for dot, name in ((self.light_sw, "软件"), (self.light_take, "接管"), (self.light_node, "AI节点")):
            box = QHBoxLayout()
            box.setSpacing(5)
            lab = QLabel(name)
            lab.setStyleSheet("font-size:12.5px;")
            box.addWidget(dot); box.addWidget(lab)
            lights.addLayout(box)
        lights.addStretch(1)
        fl.addLayout(lights)

        # 网速 + 曲线：左半绿色=系统总上传/下载，右半黄色=代理上传/下载
        spd = QHBoxLayout()
        spd.setSpacing(0)
        self.lbl_up = QLabel("↑0.0K/s")
        self.lbl_down = QLabel("↓0.0K/s")
        self.lbl_proxy_up = QLabel("↑0.0K/s")
        self.lbl_proxy_down = QLabel("↓0.0K/s")
        for label in (self.lbl_up, self.lbl_down):
            label.setStyleSheet(f"color:{GREEN}; font-size:13px; font-weight:600;")
        for label in (self.lbl_proxy_up, self.lbl_proxy_down):
            label.setStyleSheet(f"color:{YELLOW}; font-size:13px; font-weight:600;")
        for label in (self.lbl_up, self.lbl_down, self.lbl_proxy_up, self.lbl_proxy_down):
            label.setMinimumWidth(0)
            label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.lbl_up.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.lbl_down.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.lbl_proxy_up.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.lbl_proxy_down.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.lbl_up.setToolTip("系统总上传")
        self.lbl_down.setToolTip("系统总下载")
        self.lbl_proxy_up.setToolTip("代理上传（Mihomo API / TUN）")
        self.lbl_proxy_down.setToolTip("代理下载（Mihomo API / TUN）")
        total_spd = QHBoxLayout()
        total_spd.setContentsMargins(0, 0, 0, 0)
        total_spd.setSpacing(10)
        total_spd.addWidget(self.lbl_up, 1)
        total_spd.addWidget(self.lbl_down, 1)
        proxy_spd = QHBoxLayout()
        proxy_spd.setContentsMargins(0, 0, 0, 0)
        proxy_spd.setSpacing(10)
        proxy_spd.addWidget(self.lbl_proxy_up, 1)
        proxy_spd.addWidget(self.lbl_proxy_down, 1)
        spd.addLayout(total_spd, 1)
        spd.addSpacing(32 + 2*self.lbl_up.fontMetrics().horizontalAdvance('00'))
        spd.addLayout(proxy_spd, 1)
        fl.addLayout(spd)
        self.spark = Sparkline(GREEN)
        fl.addWidget(self.spark)

        # 代理信息区
        box = QFrame()
        self.proxy_box = box
        box.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        box.setObjectName('proxyBox')
        box.setStyleSheet(f"QFrame#proxyBox {{ background: {theme.SURFACE}; border-radius: 8px; }} QLabel {{ background: transparent; }}")
        bl = QVBoxLayout(box)
        bl.setContentsMargins(10, 7, 10, 7)
        bl.setSpacing(5)
        self.lbl_modes = QLabel("接管方式: 检测中…")
        self.lbl_modes.setStyleSheet("color:#FFFFFF; font-size:12.5px; font-weight:600; letter-spacing:0px;")
        self.lbl_modes.setWordWrap(True)   # 长提示自动换行，不把窗口撑宽
        self.lbl_node = QLabel("")
        self.lbl_node.setStyleSheet("color:#F6DE9A; font-size:13.5px; letter-spacing:0px;")
        self.lbl_node.setWordWrap(True)
        self.lbl_split = QLabel("")
        self.lbl_split.setStyleSheet("color:#FFFFFF; font-size:12.5px; letter-spacing:0px;")
        self.lbl_split.setWordWrap(True)   # 长统计行自动换行，不撑宽窗口
        self.lbl_modes.setTextFormat(Qt.RichText)
        for label in (self.lbl_node, self.lbl_split):
            label.setTextFormat(Qt.PlainText)
        row = QHBoxLayout()
        row.setSpacing(8)
        lbl_probe = QLabel("探测周期")
        lbl_probe.setStyleSheet("color:#FFFFFF; font-size:12.5px; letter-spacing:0px;")
        lbl_probe.setToolTip("选择当前 AI 节点访问 ChatGPT 检测地址的自动探测周期；不控制 IP 质量检测频率。")
        row.addWidget(lbl_probe, 0, Qt.AlignBottom)
        lbl_probe.setFixedHeight(28)
        lbl_probe.setAlignment(Qt.AlignVCenter)
        self.combo_probe = QComboBox()
        for name, sec in self.PROBE_CHOICES:
            self.combo_probe.addItem(name, sec)
        saved = int(self.settings.value("probe_interval", 300))
        idx = next((i for i, (_, s) in enumerate(self.PROBE_CHOICES) if s == saved), 0)
        self.combo_probe.setCurrentIndex(idx)
        self.combo_probe.currentIndexChanged.connect(self._probe_interval_changed)
        self.btn_ip_quality = QPushButton('IP质量')
        self.btn_ip_quality.clicked.connect(self.on_ip_quality)
        self.btn_ip_quality.setToolTip('手动重新检测 AI 实际出口，更新本次启动缓存；不切换主策略组')
        self.btn_delay = QPushButton("测AI延迟")
        self.btn_delay.clicked.connect(self.on_delay)
        for control in (self.combo_probe, self.btn_ip_quality, self.btn_delay):
            control.setFixedSize(78, 28)
            control.setStyleSheet('color:#FFFFFF; font-size:12.5px; letter-spacing:0px; padding:2px 5px;')
        row.addWidget(self.combo_probe, 0, Qt.AlignBottom); row.addStretch(1)
        row.addWidget(self.btn_ip_quality, 0, Qt.AlignBottom)
        self.lbl_latency = QLabel("— ms")
        self.lbl_latency.setFixedSize(78, 32)
        self.lbl_latency.setTextFormat(Qt.PlainText)
        self.lbl_latency.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
        self.lbl_latency.setStyleSheet(f"color:{DIM}; font-size:13px; font-weight:600; letter-spacing:0px;")
        row.addWidget(self.btn_delay, 0, Qt.AlignBottom)
        bl.addWidget(self.lbl_modes); bl.addWidget(self.lbl_node)
        bl.addWidget(self.lbl_split)
        quality_row = QGridLayout()
        self.quality_grid=quality_row
        quality_row.setHorizontalSpacing(8)
        quality_row.setVerticalSpacing(5)
        quality_row.setColumnStretch(0, 0)
        quality_row.setColumnStretch(1, 1)
        self.lbl_ippure = QLabel('IPPure：等待 AI 出口')
        self.lbl_ippure.setTextFormat(Qt.RichText)
        self.lbl_ippure.setStyleSheet('color:#FFFFFF; font-size:12.5px; font-weight:700; letter-spacing:0px;')
        quality_row.addWidget(self.lbl_ippure, 0, 0)
        bl.addLayout(quality_row)
        self.lbl_cleanip = QLabel('CleanIP：—　风险：—')
        self.lbl_cleanip.setTextFormat(Qt.RichText)
        self.lbl_cleanip.setStyleSheet('color:#FFFFFF; font-size:12.5px; font-weight:700; letter-spacing:0px;')
        self.ip_type_badges = TypeBadges()
        quality_row.addWidget(self.lbl_cleanip, 1, 0)
        self.lbl_cleanrisk=QLabel('风险：—')
        self.lbl_cleanrisk.setTextFormat(Qt.RichText)
        self.lbl_cleanrisk.setStyleSheet('color:#FFFFFF;font-size:12.5px;font-weight:700;letter-spacing:0px;')
        quality_row.addWidget(self.lbl_cleanrisk, 1, 1)
        risk_row = QHBoxLayout()
        risk_row.setSpacing(8)
        self.lbl_flclash = QLabel('Fl：—')
        self.lbl_flclash.setTextFormat(Qt.RichText)
        self.lbl_flclash.setStyleSheet('color:#FFFFFF;font-size:12.5px;font-weight:700;letter-spacing:0px;')
        quality_row.addWidget(self.lbl_flclash,0,1)
        self.lbl_risk_flags = ElidedLabel()
        self.lbl_risk_flags.setStyleSheet('color:#FFFFFF;font-size:12.5px;font-weight:700;letter-spacing:0px;')
        self.lbl_location = ElidedLabel()
        self.lbl_location.setSizePolicy(QSizePolicy.Preferred,QSizePolicy.Fixed)
        self.lbl_location.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
        self.lbl_location.setStyleSheet(f'color:{theme.ACCENT};font-size:13px;font-weight:600;letter-spacing:0px;')
        risk_row.addWidget(self.lbl_risk_flags, 1)
        risk_row.addWidget(self.lbl_location, 0)
        bl.addLayout(risk_row)
        types_row = QHBoxLayout()
        types_row.setSpacing(8)
        types_row.addWidget(self.ip_type_badges, 1)
        types_row.addWidget(self.lbl_latency, 0, Qt.AlignVCenter)
        bl.addLayout(types_row)
        bl.addLayout(row)
        fl.addWidget(box)

        # 规则命中
        self.lbl_rules = QLabel("")
        self.lbl_rules.setStyleSheet(f"color:{DIM}; font-size:11px;")
        self.lbl_rules.setWordWrap(True)
        self.lbl_rules.setTextFormat(Qt.PlainText)
        fl.addWidget(self.lbl_rules)

        # 连接明细
        self.sec_label = QLabel("活跃连接（蓝=系统待确认 绿=直连 黄=代理 红=拦截 · 右列=真实路由）")
        self.sec_label.setStyleSheet(f"color:{DIM}; font-size:11px;")
        self.sec_label.setWordWrap(True)   # 同上：不把窗口撑宽
        fl.addWidget(self.sec_label)
        scroll = QScrollArea()
        self.conn_scroll = scroll
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        scroll.viewport().setStyleSheet("background: transparent;")
        scroll.viewport().setAutoFillBackground(False)
        holder = QWidget()
        holder.setMinimumWidth(0)
        holder.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        holder.setStyleSheet("background: transparent;")
        holder.setAutoFillBackground(False)
        self.conn_lay = QVBoxLayout(holder)
        self.conn_lay.setContentsMargins(0, 0, 0, 0)
        self.conn_lay.setSpacing(1)
        self.rows = [ConnRow() for _ in range(20)]
        for r_ in self.rows:
            self.conn_lay.addWidget(r_)
            r_.hide()
        self.conn_lay.addStretch(1)
        # 连接区任意位置单击 = 固定/取消固定行刷新，便于悬停看清瞬态连接详情
        self.freeze_conns = False
        self._freeze_list_mode = None
        scroll.viewport().installEventFilter(self)
        holder.installEventFilter(self)
        for r_ in self.rows:
            r_.installEventFilter(self)
        scroll.setWidget(holder)
        fl.addWidget(scroll, 1)

        hint = QLabel("拖到屏幕边缘吸附 · 悬停迷你条展开 · 单击迷你条固定")
        hint.setStyleSheet(f"color:{DIM}; font-size:10px;")
        hint.setAlignment(Qt.AlignCenter)
        fl.addWidget(hint)

        # 非模态状态提示：不抢焦点、不拦截鼠标，自动消失。
        self.toast = QLabel(self.panel)
        self.toast.setAlignment(Qt.AlignCenter)
        self.toast.setWordWrap(True)
        self.toast.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.toast.setStyleSheet(
            "background-color: rgba(31,35,48,216); color: #F4F6FA;"
            "border: 1px solid rgba(255,255,255,55); border-radius: 8px;"
            "padding: 8px 12px; font-size: 12px; font-weight: 600;"
        )
        self.toast.hide()
        self.toast_timer = QTimer(self)
        self.toast_timer.setSingleShot(True)
        self.toast_timer.timeout.connect(self.toast.hide)

    def _build_tray(self):
        pix = QPixmap(32, 32)
        pix.fill(Qt.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(GREEN)); p.setPen(Qt.NoPen)
        p.drawRoundedRect(2, 2, 28, 28, 8, 8)
        p.setPen(QPen(QColor("#12141C"), 2))
        p.setFont(QFont("Arial", 12, QFont.Bold))
        p.drawText(pix.rect(), Qt.AlignCenter, "N")
        p.end()
        self.tray = QSystemTrayIcon(QIcon(pix), self)
        menu = QMenu()
        act_show = QAction("显示 / 隐藏", self)
        act_show.triggered.connect(lambda: self.hide() if self.isVisible() else (self.showNormal(), self.activateWindow()))
        self.act_precise = QAction("启用精准进程流量（管理员）", self)
        self.act_precise.triggered.connect(self._restart_elevated)
        if self.engine.traffic.accurate:
            self.act_precise.setText("精准进程流量：已启用（ETW）")
            self.act_precise.setEnabled(False)
        self.act_history_status = QAction("流量账本：启动中…", self)
        self.act_history_status.setEnabled(False)
        self.act_history_export_24h = QAction("导出最近 24 小时（分钟明细）", self)
        self.act_history_export_24h.triggered.connect(lambda: self._export_history(24))
        self.act_history_export_year = QAction("导出最近 1 年（小时汇总）", self)
        self.act_history_export_year.triggered.connect(lambda: self._export_history(365 * 24))
        self.act_history_open = QAction("打开流量账本目录", self)
        self.act_history_open.triggered.connect(self._open_history_directory)
        act_logs = QAction("打开诊断日志目录", self)
        act_logs.triggered.connect(lambda: os.startfile(os.path.join(
            os.environ.get("LOCALAPPDATA", "."), "NetMonitorPro", "logs")))
        self.act_review_counts = QAction('待鉴定：统计中…', self)
        self.act_review_counts.setEnabled(False)
        menu.aboutToShow.connect(self._update_review_counts)
        self.act_auto = QAction("开机自启", self)
        self.act_auto.setCheckable(True)
        self.act_auto.setChecked(self._autostart_get())
        self.act_auto.triggered.connect(self._autostart_set)
        act_quit = QAction("退出", self)
        act_quit.triggered.connect(self._quit)
        menu.addAction(act_show); menu.addAction(self.act_precise)
        menu.addAction(act_logs)
        menu.addAction(self.act_review_counts)
        menu.addSeparator(); menu.addAction(self.act_history_status)
        menu.addAction(self.act_history_export_24h)
        menu.addAction(self.act_history_export_year)
        menu.addAction(self.act_history_open)
        menu.addSeparator(); menu.addAction(self.act_auto)
        menu.addSeparator(); menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.setToolTip("NetMonitor Pro 22")
        self.tray.activated.connect(lambda r_: self.showNormal() if r_ == QSystemTrayIcon.Trigger else None)
        self.tray.show()
        self._update_history_actions({
            "history_status": self.engine.history.status,
            "history_error": self.engine.history.last_error,
            "history_path": self.engine.history.db_path,
            "history_dropped": self.engine.history.dropped_batches,
        })

    def _update_review_counts(self):
        counts = self.engine.unknown_log.counts()
        self.act_review_counts.setText(f"待鉴定：域名/其他 {counts['domain']}/500 · 裸IP {counts['ip']}/500 · 异常 {counts['anomaly']}/200")

    def _update_history_actions(self, data):
        status = data.get("history_status", "starting")
        dropped = int(data.get("history_dropped") or 0)
        if status == "running":
            suffix = f" · 丢弃 {dropped} 批" if dropped else ""
            self.act_history_status.setText(f"流量账本：运行中（分钟30天 / 小时1年）{suffix}")
            enabled = True
        elif status == "error":
            self.act_history_status.setText("流量账本：写入异常")
            enabled = False
        else:
            self.act_history_status.setText("流量账本：启动中…")
            enabled = False
        tip = data.get("history_path", "")
        if data.get("history_error"):
            tip += f"\n{data['history_error']}"
        self.act_history_status.setToolTip(tip)
        exporting = bool(self.history_export_worker and self.history_export_worker.isRunning())
        self.act_history_export_24h.setEnabled(enabled and not exporting)
        self.act_history_export_year.setEnabled(enabled and not exporting)

    def _export_history(self, hours):
        if self.history_export_worker and self.history_export_worker.isRunning():
            self._show_toast("流量账本正在导出，请稍候")
            return
        if not self.engine.history.running:
            self._show_toast(self.engine.history.last_error or "流量账本尚未就绪")
            return
        self.history_export_worker = HistoryExportWorker(
            self.engine.history, hours, self,
        )
        self.history_export_worker.result.connect(self._history_export_done)
        self.history_export_worker.finished.connect(self.history_export_worker.deleteLater)
        self.act_history_export_24h.setEnabled(False)
        self.act_history_export_year.setEnabled(False)
        self._show_toast("正在后台导出流量账本…")
        self.history_export_worker.start()

    def _history_export_done(self, ok, detail_path, alert_path):
        self.history_export_worker = None
        self._update_history_actions({
            "history_status": self.engine.history.status,
            "history_error": self.engine.history.last_error,
            "history_path": self.engine.history.db_path,
            "history_dropped": self.engine.history.dropped_batches,
        })
        if ok:
            message = (f"已导出 {os.path.basename(detail_path)}\n"
                       f"以及 {os.path.basename(alert_path)}")
            self._show_toast("流量账本导出完成", 4000)
            self.tray.showMessage("流量账本导出完成", message,
                                  QSystemTrayIcon.Information, 6000)
        else:
            self._show_toast(f"导出失败：{detail_path}", 5000)
            self.tray.showMessage("流量账本导出失败", detail_path,
                                  QSystemTrayIcon.Warning, 6000)

    def _open_history_directory(self):
        try:
            os.makedirs(self.engine.history.directory, exist_ok=True)
            os.startfile(self.engine.history.directory)
        except Exception as exc:
            self._show_toast(f"无法打开账本目录：{exc}", 5000)

    def _restart_elevated(self):
        """Ask Windows to relaunch this build with an elevated token."""
        if is_user_admin():
            QMessageBox.information(self, "精准进程流量", "当前已经是管理员模式，ETW 采集已启用。")
            return
        if request_elevated_relaunch():
            self._save_geo()
            QApplication.quit()
        else:
            QMessageBox.warning(
                self,
                "未启用精准进程流量",
                "管理员授权已取消或启动失败。\n当前仍可查看系统总网速和进程连接。",
            )

    # ---------- 探测 ----------
    def _apply_topmost(self):
        """用 Win32 断言当前置顶状态（不抢焦点、不闪动）。Qt 在 show 时会按旧 flags 重排层级，故每次显示后都调用"""
        SWP = 0x2 | 0x1 | 0x10      # NOMOVE | NOSIZE | NOACTIVATE
        ctypes.windll.user32.SetWindowPos(
            int(self.winId()), -1 if self._on_top else -2, 0, 0, 0, 0, SWP)

    def showEvent(self, e):
        super().showEvent(e)
        self._apply_topmost()

    def _toggle_on_top(self):
        self._on_top = self.btn_pin.isChecked()
        self.settings.setValue("always_on_top", self._on_top)
        # 同步 Qt 内部标志（持久行为正确）+ 立即用 Win32 修正层级（避免闪烁/抢焦点）
        self.setWindowFlag(Qt.WindowStaysOnTopHint, self._on_top)
        self.show()
        self._apply_topmost()

    def _apply_probe_interval(self):
        sec = int(self.settings.value("probe_interval", 300))
        self.probe_timer.start(sec * 1000)

    def _probe_interval_changed(self, i):
        sec = self.PROBE_CHOICES[i][1]
        self.settings.setValue("probe_interval", sec)
        self._apply_probe_interval()
        self._show_toast('自动探测周期：'+self.combo_probe.currentText())
        self.start_probe()

    def start_probe(self):
        if self._shutting_down:
            return
        if self.probe_worker and self.probe_worker.isRunning():
            return
        d = getattr(self, "_last_data", {})
        target = proxy_health_key(d)
        node = proxy_action_node(d)
        if not target or not node or not d.get("api_on"):
            return
        self.probe_retry_timer.stop()
        self._probe_target = target
        self._probe_node = node
        self._probe_group = d.get("ai_group", "")
        self._probe_source = d.get("ai_source", "AI策略组")
        attempts = 2 if getattr(self, "_delay_btn_probe", False) else 1
        self.probe_worker = AiProbeWorker(
            self.engine.pipe, node, url=AI_PROBE_URL, attempts=attempts,
        )
        self.probe_worker.result.connect(lambda ok, ms, key=target: self._probe_done(ok, ms, key))
        self.probe_worker.finished.connect(self._sync_detection_buttons)
        self.probe_worker.start()
        self._sync_detection_buttons()
        _lbl_set(self.lbl_latency, "探测中…")
        LOG.info("AI probe started mode=%s group=%s node=%s", d.get("mode"), self._probe_group, node)

    def _probe_done(self, ok, ms, target_key=None):
        d = getattr(self, "_last_data", {})
        takeover = effective_proxy_takeover(d)
        current_target = proxy_health_key(d)
        started_target = target_key if target_key is not None else getattr(self, "_probe_target", "")
        manual_delay = getattr(self, "_delay_btn_probe", False)
        self._delay_btn_probe = False
        if not takeover or not current_target or started_target != current_target:
            self.probe_state = None
            if manual_delay:
                self.btn_delay.setText("测AI延迟")
                self.btn_delay.setEnabled(True)
                self._delay_result_key = ""
            if current_target and started_target != current_target:
                QTimer.singleShot(100, self.start_probe)
            return

        prev = self.probe_state
        self.probe_state = ok
        self.light_node.set_state("ok" if ok else "bad")
        group = getattr(self, "_probe_group", "AI服务")
        node = getattr(self, "_probe_node", "?")
        tip = (f"AI节点状态: {'正常' if ok else '不通'}\n"
               f"锁定目标: {group} → {node}\n"
               f"来源: {getattr(self, '_probe_source', 'AI策略组')}\n"
               f"ChatGPT 探测: {str(ms) + 'ms' if ok else '失败或超时'}\n"
               "路径: Mihomo 指定叶子节点（未经过订阅分流规则）")
        self.light_node.setToolTip(tip)
        self._sync_node_lights()
        self._set_latency(ok, ms, current_target, tip)
        LOG.info("AI probe complete node=%s ok=%s delay_ms=%s", node, ok, ms if ok else None)
        # 手动"测延迟"（通用模式经代理通道实测）
        if manual_delay:
            self._show_delay_result(f"{ms} ms" if ok else "超时", current_target)
        # 只有代理接管中才弹提醒/重试，避免用户主动关代理时误报
        if not ok:
            # 失败自动补测：前 3 次快速退避（5/10/15 秒，应对内核刚启动未就绪的假失败），
            # 此后每 30 秒持续补测直到恢复——出口从直连切回节点后红灯会自己变绿，不用等周期
            self._probe_retry = getattr(self, "_probe_retry", 0) + 1
            delay_ms = 5000 * self._probe_retry if self._probe_retry <= 3 else 30000
            self.probe_retry_timer.start(delay_ms)
            if prev is True:
                self.tray.showMessage("NetMonitor Pro", "⚠ 当前节点的 AI 目标探测失败；不代表节点所有网站都不可用", QSystemTrayIcon.Warning, 6000)
            self._node_bad = True
        else:
            self._probe_retry = 0
            self.probe_retry_timer.stop()
            if prev is False and getattr(self, "_node_bad", False):
                self.tray.showMessage("NetMonitor Pro", "✓ AI 节点已恢复", QSystemTrayIcon.Information, 4000)
            self._node_bad = False

    # ---------- 迷你条 ----------
    def _sync_node_lights(self):
        for light in (self.mini_v_light, self.mini_h_light):
            light.set_state(self.light_node.state)
            _tip_set(light, self.light_node.toolTip())

    def _set_latency(self, ok, milliseconds, key, detail=""):
        self._latency_key = key
        text, color = latency_style(ok, milliseconds)
        _lbl_set(self.lbl_latency, text)
        self.lbl_latency.setStyleSheet(f"color:{color}; font-size:13px; font-weight:600; letter-spacing:0px;")
        stamp = time.strftime("%H:%M:%S") if ok is not None else "未测"
        _tip_set(self.lbl_latency, f"{detail}\n更新时间: {stamp}\n"
                 "当前节点访问 ChatGPT 的 HTTP 探测耗时（非 ICMP ping）。\n"
                 "≤200ms 绿；201–500ms 黄；>500ms 或失败 红。\n"
                 "红色高延迟不等于节点失效；可达也不代表账号/地区解锁。")

    _was_mini = False

    def enter_mini(self, orientation, edge=None, screen=None):
        screen=screen if screen is not None else self._cur_screen()
        edge=edge or nearest_edge(self.frameGeometry(),screen,('l','r') if orientation=='v' else ('t','b'))[0]
        self._was_mini = False
        self.mode = "mini_h" if orientation == "h" else "mini_v"
        self.pinned = False
        self.full.hide()
        (self.mini_h if orientation == "h" else self.mini_v).show()
        (self.mini_v if orientation == "h" else self.mini_h).hide()
        self.setFixedWidth((self.MINI_H if orientation == "h" else self.MINI_V)[0])
        self.resize(*(self.MINI_H if orientation == "h" else self.MINI_V))
        self._dock_to_edge(edge,screen)

    def exit_mini(self):
        self._was_mini = True
        # 关键顺序：先按迷你条的小尺寸位置确定所在屏幕和吸附边，再放大窗口。
        # 若先放大，右/下边缘吸附时窗口中心会溢出到相邻屏幕（或屏外），被误判到别的显示器
        pre = self.frameGeometry()
        screen = self._cur_screen(pre.center())
        edge = getattr(self,'_dock_edge',None) or nearest_edge(pre,screen)[0]
        self._dock_edge = edge          # 记住吸附边，收回时原边返回，不重新猜
        self.mode = "full"
        self.setFixedWidth(self.W)
        self.mini_v.hide()
        self.mini_h.hide()
        self.full.show()
        self.resize(self.W, getattr(self, "_target_h", self.H))
        # 用放大后的实际尺寸定位（内容最小宽度可能超过 W，用常量会把右边/下边推出屏幕）
        fw, fh = self.frameGeometry().width(), self.frameGeometry().height()
        x, y = pre.x(), pre.y()
        if edge == "l":
            nx, ny = screen.left(), max(screen.top(), min(y, screen.bottom() - fh + 1))
        elif edge == "r":
            nx, ny = screen.right() - fw + 1, max(screen.top(), min(y, screen.bottom() - fh + 1))
        elif edge == "t":
            nx, ny = max(screen.left(), min(x, screen.right() - fw + 1)), screen.top()
        else:
            nx, ny = max(screen.left(), min(x, screen.right() - fw + 1)), screen.bottom() - fh + 1
        nx = max(screen.left(), min(nx, screen.right() - fw + 1))
        ny = max(screen.top(), min(ny, screen.bottom() - fh + 1))
        self.move(nx, ny)

    def _cur_screen(self, point=None):
        """指定点（默认窗口中心）所在的屏幕（支持副屏），取不到退回主屏。返回可用区域（不含任务栏）"""
        s = QApplication.screenAt(point if point is not None else self.frameGeometry().center())
        return (s or QApplication.primaryScreen()).availableGeometry()

    def _dock_to_edge(self, force_edge=None, screen=None):
        """仅迷你条调用：按当前所在屏幕贴边；force_edge 指定时直接贴该边（收回场景用）"""
        screen = screen if screen is not None else self._cur_screen()
        edge = force_edge or nearest_edge(self.frameGeometry(),screen,('l','r') if self.mode=='mini_v' else ('t','b'))[0]
        self._dock_edge = edge           # 用户手动吸附也更新记忆
        self.move(*dock_position(self.frameGeometry(),screen,edge))

    # ---------- 事件 ----------
    def eventFilter(self, obj, ev):
        # 连接区任意位置左键单击 = 固定/取消固定行刷新。
        # 行/标签默认不消费鼠标事件，会逐级冒泡到 holder/viewport，一并监听。
        # ⚠️ 必须返回 False 放行事件：主窗口 mouseReleaseEvent 依赖冒泡路径
        # 重启刷新定时器与动画，吞掉会导致整个窗口停刷（timer 停在按下时的状态）。
        if ev.type() == QEvent.MouseButtonRelease and ev.button() == Qt.LeftButton:
            if (obj is self.conn_scroll.viewport()
                    or obj is self.conn_scroll.widget()
                    or obj in self.rows):
                self.freeze_conns = not self.freeze_conns
                self._freeze_list_mode = None
                self.refresh()
        return super().eventFilter(obj, ev)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
            self._press_pos = e.position().toPoint()
            self._moved = False          # 本次按压是否发生过拖动（单击不触发吸附判定）
            # 拖动期间暂停刷新与动画，避免定时器撞上拖动造成掉帧
            self.timer.stop()
            self.anim.stop()
            if self.mode != "full":
                self._click_pos = e.position().toPoint()

    def mouseMoveEvent(self, e):
        if self.drag_pos is not None and e.buttons() & Qt.LeftButton:
            if self.mode != "full" and hasattr(self, "_click_pos"):
                # 迷你条拖动：先展开成全盘再拖
                delta = e.position().toPoint() - self._click_pos
                if abs(delta.x()) + abs(delta.y()) > 12:
                    self._moved = True
                    self.exit_mini()
                    self.drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
            if self.mode == "full":
                # 全盘态发生实际拖动 → 取消悬停展开的自动收回
                if hasattr(self, "_press_pos"):
                    dd = e.position().toPoint() - self._press_pos
                    if abs(dd.x()) + abs(dd.y()) > 8:
                        self._moved = True
                        self._was_mini = False
                if self._moved:
                    self.move(e.globalPosition().toPoint() - self.drag_pos)

    def mouseReleaseEvent(self, e):
        self.drag_pos = None
        # 松手恢复刷新与动画，并立即补一次刷新
        self.timer.start(1000)
        self.anim.start(45)
        QTimer.singleShot(0, self.refresh)
        if self.mode != "full":
            # 单击迷你条 = 固定/取消固定展开
            if hasattr(self, "_click_pos"):
                delta = e.position().toPoint() - self._click_pos
                if abs(delta.x()) + abs(delta.y()) <= 6:
                    if self.pinned:
                        self.pinned = False
                        self.enter_mini("h" if self.mode == "mini_h" else "v")
                    else:
                        self.pinned = True
                        self.exit_mini()
            return
        # 全盘态松手：只有真的拖动过才做吸附判定；单纯点击展开面板不做任何吸附
        if not getattr(self, "_moved", False):
            return
        # 贴边则吸附；远离边缘则留在原地（并彻底取消自动收回）
        # 以鼠标所在屏幕的边缘判定（窗口可能横跨两屏，光标位置才代表用户意图）
        screen = self._cur_screen(QCursor.pos())
        edge=snap_edge(self.frameGeometry(),screen)
        if edge:
            self.enter_mini('v' if edge in ('l','r') else 'h',edge,screen)
        else:
            self._was_mini = False
        self._save_geo()     # 拖动/吸附结束即保存，崩溃或断电也不丢位置

    def enterEvent(self, e):
        if self.mode != "full" and not self.pinned:
            self.exit_mini()

    def leaveEvent(self, e):
        if self.mode == "full" and not self.pinned and self._was_mini:
            QTimer.singleShot(300, self._maybe_collapse)

    def _maybe_collapse(self):
        if self.mode == "full" and not self.pinned and self._was_mini and not self.underMouse():
            # 滞后余量：光标还在窗口 60px 范围内不收回（边缘抖动/DPI 误差防闪烁）
            if self.frameGeometry().adjusted(-60, -60, 60, 60).contains(QCursor.pos()):
                return
            # 收回时原边返回（缩小后中心会偏移 290px，重新猜边必跳到对边）
            edge = getattr(self, "_dock_edge", None)
            if edge is None:
                screen = self._cur_screen()
                cy = self.y() + self.height() / 2
                cx = self.x() + self.width() / 2
                d = {"l": cx - screen.left(), "r": screen.right() - cx,
                     "t": cy - screen.top(), "b": screen.bottom() - cy}
                edge = min(d, key=d.get)
            self.enter_mini("v" if edge in ("l", "r") else "h", edge)

    def closeEvent(self, e):
        e.ignore()
        self.hide()

    def _save_geo(self):
        """保存窗口位置（主动退出/关机/拖动结束都会经过）；尺寸不保存，永远以代码为准"""
        try:
            self.settings.setValue("pos", self.pos())
        except Exception:
            pass

    def _quit(self):
        self._save_geo()
        QApplication.quit()

    def _shutdown(self):
        """按依赖顺序停止定时器、网络线程和 ETW 会话。"""
        if self._shutting_down:
            return
        self._shutting_down = True
        self._save_geo()

        for timer in (self.timer, self.anim, self.probe_timer, self.toast_timer):
            timer.stop()

        for worker in (self.quality_worker, self.route_worker):
            if worker is not None and worker.isRunning():
                worker.cancel()
                worker.wait(45000)  # bounded requests; allow finally to REJECT our group

        workers = tuple(
            worker for worker in (self.probe_worker,)
            if worker is not None and worker.isRunning()
        )
        for worker in workers:
            worker.cancel()
        for worker in workers:
            if not worker.wait(6000):
                # 只在应用进程已经退出且套接字取消仍未生效时兜底。
                worker.terminate()
                worker.wait(1000)

        exporter = self.history_export_worker
        if exporter is not None and exporter.isRunning() and not exporter.wait(8000):
            exporter.terminate()
            exporter.wait(1000)

        if getattr(self, "sampler", None):
            self.sampler.close()
        else:
            self.engine.close()
        try:
            self.tray.hide()
        except Exception:
            pass

    # ---------- 自启 ----------
    def _autostart_get(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
                winreg.QueryValueEx(k, "NetMonitorPro")
            return True
        except OSError:
            return False

    def _autostart_set(self, on):
        target = f'"{os.path.abspath(sys.argv[0])}"'
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
                if on:
                    winreg.SetValueEx(k, "NetMonitorPro", 0, winreg.REG_SZ, target)
                else:
                    try:
                        winreg.DeleteValue(k, "NetMonitorPro")
                    except OSError:
                        pass
        except OSError:
            pass

    # ---------- 动画 ----------
    def _animate(self):
        if not self.isVisible():
            return
        for d in (self.light_sw, self.light_take, self.light_node,
                  self.mini_v_light, self.mini_h_light):
            if d.state == "off" or not d.isVisible():
                continue                       # 熄灭/隐藏的灯不做呼吸动画
            d.phase += 0.13
            d.update()

    # ---------- 节点体检 ----------
    def _show_toast(self, text, duration=2600):
        """Show an in-panel translucent message without blocking interaction."""
        if not text:
            return
        width = max(210, min(316, self.panel.width() - 28))
        self.toast.setText(text)
        self.toast.setFixedWidth(width)
        height = self.toast.heightForWidth(width)
        self.toast.resize(width, max(42, height + 4 if height > 0 else 42))
        anchor_y = self.btn_ip_quality.mapTo(self.panel, QPoint(0, 0)).y()
        x = max(14, (self.panel.width() - self.toast.width()) // 2)
        y = max(14, min(anchor_y - self.toast.height() - 9,
                        self.panel.height() - self.toast.height() - 14))
        self.toast.move(x, y)
        self.toast.raise_()
        self.toast.show()
        self.toast_timer.start(duration)

    def _ensure_proxy_action(self):
        allowed, hint = proxy_action_state(getattr(self, "_last_data", {}))
        if hint:
            self._show_toast(hint)
        return allowed

    # ---------- 测延迟 ----------
    def on_delay(self):
        if not self._ensure_proxy_action():
            return
        d = getattr(self, "_last_data", {})
        if self.probe_worker and self.probe_worker.isRunning():
            self._show_toast("AI 探测正在进行，结果会显示在按钮上方")
            return
        self._delay_btn_probe = True
        self._delay_pending_key = proxy_health_key(d)
        self.start_probe()

    def _show_delay_result(self, text, target_key):
        self._delay_result_key = target_key
        self.btn_delay.setText("测AI延迟")
        self.btn_delay.setEnabled(True)
        QTimer.singleShot(8000, lambda expected=text, key=target_key:
                          self._reset_delay_result(expected, key))

    def _reset_delay_result(self, expected_text, target_key):
        if (self.btn_delay.text() == expected_text
                and getattr(self, "_delay_result_key", "") == target_key):
            self.btn_delay.setText("测AI延迟")
            self._delay_result_key = ""

    def on_ip_quality(self):
        d = getattr(self, '_last_data', {})
        key = quality_key(d)
        if not key:
            self._show_toast('未确认 AI 代理出口，或当前未接管/直连；不进行 IP 检测')
            return
        if not self._start_quality(d, manual=True):
            self._show_toast('IP 质量正在检测，请稍候')

    def _start_quality(self, d, manual=False):
        key = quality_key(d)
        if self.quality_worker and self.quality_worker.isRunning():
            return False
        if not self.quality_cache.begin(key, manual):
            return False
        self.quality_worker = IPQualityWorker(self.engine.pipe, node=d['ai_node'], parent=self)
        self.quality_worker.done.connect(lambda result, k=key: self._quality_done(k, result))
        self.quality_worker.finished.connect(lambda w=self.quality_worker:self._network_worker_finished('quality_worker',w))
        self.quality_worker.start()
        self._sync_detection_buttons()
        return True

    def _quality_done(self, key, result):
        self.quality_cache.finish(key, result)
        if result.get('cancelled'):
            LOG.info('IP quality cancelled; no new result cached')
        elif result.get('errors'):
            LOG.warning('IP quality incomplete errors=%s', result['errors'])
        else:
            LOG.info('IP quality complete sources=%s', ','.join(k for k in ('ippure','cleanip','flclash') if result.get(k)))
        if not self._shutting_down:
            self._render_quality(getattr(self, '_last_data', {}))

    def _network_worker_finished(self, attribute, worker):
        if getattr(self, attribute, None) is worker:setattr(self, attribute, None)
        worker.deleteLater()
        self._sync_detection_buttons()

    def _sync_detection_buttons(self):
        if self._shutting_down:return
        for button, worker, text in ((self.btn_delay,self.probe_worker,'测AI延迟'),
                                     (self.btn_ip_quality,self.quality_worker,'IP质量')):
            busy=bool(worker and worker.isRunning())
            button.setText('检测中…' if busy else text)
            button.setEnabled(not busy)

    def _route_done(self, result, mode, profile):
        if result.get('route') and not result.get('cancelled') and not self._shutting_down:
            self.engine.pipe.ai_route_hint = dict(result, mode=mode, profile=profile, at=time.monotonic())

    def _refresh_quality(self, d):
        if not d.get('api_on') or not (d.get('sp_on') or d.get('tun_on')) or d.get('ai_target_state')=='direct':
            for worker in (self.quality_worker, self.route_worker):
                if worker and worker.isRunning():worker.cancel()
        # A tiny ChatGPT request identifies the primary AI path when idle.
        # It uses the ordinary proxy port without modifying any selections.
        eligible = d.get('api_on') and (d.get('sp_on') or d.get('tun_on')) and d.get('mode')=='rule'
        if eligible and d.get('ai_target_state')=='waiting' and time.monotonic()>=self._route_retry_at:
            if not self.route_worker or not self.route_worker.isRunning():
                self._route_retry_at = time.monotonic()+30
                port = d.get('main_proxy_port')
                if port:
                    self.route_worker = IPQualityWorker(self.engine.pipe, port=port, parent=self)
                    self.route_worker.done.connect(lambda result, m=d['mode'], p=d['profile_id']: self._route_done(result,m,p))
                    self.route_worker.finished.connect(lambda w=self.route_worker:self._network_worker_finished('route_worker',w))
                    self.route_worker.start()
        self._start_quality(d)
        self._render_quality(d)

    def _render_quality(self, d):
        key = quality_key(d)
        result = self.quality_cache.results.get(key) if key else None
        self.ip_type_badges.render(result or {})
        flags_detail = risk_annotation(result or {})[1]
        clean=(result or {}).get('cleanip') or {}
        flags,clean_detail=risk_display(clean)
        flags_detail+='\n'+clean_detail
        if (result or {}).get('errors',{}).get('cleanip_details'):
            flags_detail+='\n明细读取失败：'+result['errors']['cleanip_details']
        third=usable_record(result or {})
        if third:
            _lbl_set(self.lbl_flclash,f'Fl：<span style="color:{flclash_color(third["level"])}">{html.escape(third["quality_label"])}</span>')
            if third['flags']:flags+=' · Fl：'+'、'.join(third['flags'])
        else:_lbl_set(self.lbl_flclash,'Fl：—')
        self.lbl_flclash.setToolTip(flags_detail)
        self.lbl_risk_flags.set_full_text('标记：'+flags)
        self.lbl_risk_flags.setToolTip(flags_detail)
        location, location_tip = location_display(result or {})
        self.lbl_location.set_full_text(location)
        self._fit_location()
        self.lbl_location.setToolTip(location_tip)
        pending = bool(key and self.quality_cache.pending==key)
        _lbl_set(self.lbl_cleanrisk,'风险：—')
        if not key:
            state = '直连 · 不检测' if d.get('ai_target_state')=='direct' else '等待 AI 代理出口'
            _lbl_set(self.lbl_ippure, 'IPPure：'+state)
            _lbl_set(self.lbl_cleanip, 'CleanIP：—')
            for label in (self.lbl_ippure,self.lbl_cleanip,self.lbl_cleanrisk):
                _tip_set(label, d.get('ai_source','未开启代理接管'))
            return
        if not result:
            _lbl_set(self.lbl_ippure, 'IPPure：检测中…' if pending else 'IPPure：等待检测')
            _lbl_set(self.lbl_cleanip, 'CleanIP：检测中…' if pending else 'CleanIP：—')
            return
        errors=result.get('errors',{})
        pure=result.get('ippure')
        clean=result.get('cleanip')
        if pure:
            text,_=ippure_badge(pure['score'])
            _lbl_set(self.lbl_ippure, f'IPPure：<span style="color:{risk_color(pure["score"])}">{html.escape(text)}</span>')
        else:
            _lbl_set(self.lbl_ippure, 'IPPure：暂不可用（悬停查看）')
        if clean:
            _lbl_set(self.lbl_cleanip,
                f'CleanIP：<span style="color:{clean_color(clean["score"])};font-weight:700">{clean["score"]:g} {html.escape(clean["grade"])}</span>'
                f' /100')
            _lbl_set(self.lbl_cleanrisk,f'风险：<span style="color:{risk_color(clean["risk"])}">{clean["risk"]:g}</span> /100')
        else:
            _lbl_set(self.lbl_cleanip, 'CleanIP：暂不可用')
        tip = f"AI节点：{d.get('ai_node')}\n{d.get('ai_source','')}\n检测时间：{result.get('time','')}\n"
        tip += '本次启动按订阅/节点缓存；切回不会自动重测。手动点击可更新。\nIPPure/风险分越低越好；CleanIP 纯净度越高越好。第三方评分仅供参考。'
        if pure: tip += '\nIPPure 出口 IP：'+pure['ip']
        if clean: tip += '\nCleanIP 出口 IP：'+clean['ip']+'\n完整标记：'+clean['flags']
        if result.get('flclash'):tip += '\n'+flclash_quality_details(result)
        if result.get('ip_mismatch'):tip += '\n注意：两站观测 IP 不同，不能视为同一个 IP 的综合评分。'
        if d.get('other_ai_exits'):tip += '\n存在其他 AI 出口，此处优先跟随 ChatGPT 实际路径。'
        if pending:tip += '\n正在手动刷新，当前为上次结果。'
        for label,error in errors.items():tip += '\n'+label+'：'+error
        if result.get('refresh_errors'):
            tip+='\n最近刷新失败，保留上次成功结果（不是本次新检测值）：'+str(result.get('refresh_time',''))
            for label,error in result['refresh_errors'].items():tip+='\n'+label+'：'+error
            self.lbl_risk_flags.set_full_text('刷新失败 · 标记：'+flags)
            self.lbl_risk_flags.setToolTip(tip)
        for label in (self.lbl_ippure,self.lbl_cleanip,self.lbl_cleanrisk):_tip_set(label,tip)

    def _fit_location(self):
        # Keep the right edge aligned with latency; allocate longer addresses
        # leftwards while leaving room for the Fl grade and elided risk flags.
        natural=self.lbl_location.fontMetrics().horizontalAdvance(self.lbl_location.full_text)+2
        available=self.lbl_location.parentWidget().width()-20
        # Halve the visible whitespace, not just the layout's spacing property:
        # the former 3:2 stretch also left unused space in the left column.
        natural_left=max(self.lbl_ippure.sizeHint().width(),self.lbl_cleanip.sizeHint().width())
        old_right=max(natural_left+16,(available-16)*.6+16)
        self.quality_grid.setColumnMinimumWidth(0,round((natural_left+old_right)/2-8))
        width=min(natural,max(60,available-110))
        self.lbl_location.setFixedWidth(width)

    def _compact_empty_status(self):
        # Empty QLabels still have a line-height in Qt; explicitly remove them
        # from the layout instead of leaving invisible rows above the scores.
        for label in (self.lbl_node, self.lbl_split, self.lbl_rules):
            label.setVisible(bool(label.text().strip()))

    # ---------- 刷新 ----------
    def refresh(self):
        d = self.sampler.take() if getattr(self, "sampler", None) else self.engine.tick()
        if d is None:
            if time.monotonic() - self._last_sample_at > 6:
                _lbl_set(self.lbl_modes, "内核数据更新延迟，正在重试…")
                self.light_node.set_state("warn")
                self._sync_node_lights()
                self._last_data = dict(getattr(self, "_last_data", {}), api_on=False)
                self._prev_node = ""
                self._prev_take = False
                self.probe_state = None
                self._set_latency(None, 0, "", "数据过期，等待重新读取内核")
                self._render_quality(self._last_data)
                for worker in (self.quality_worker, self.route_worker):
                    if worker and worker.isRunning():worker.cancel()
            return
        self._last_sample_at = time.monotonic()
        self._last_data = d
        signature = (d.get("api_on"), d.get("api_generation"), d.get("mode"),
                     d.get("sp_on"), d.get("tun_on"), d.get("ai_group"), d.get("ai_node"))
        if signature != getattr(self, "_logged_state", None):
            LOG.info("state api=%s generation=%s mode=%s system_proxy=%s tun=%s group=%s node=%s",
                     *signature)
            self._logged_state = signature
        self._update_history_actions(d)

        traffic_status = d.get("traffic_status")
        if traffic_status == "running":
            self.act_precise.setText("精准进程流量：已启用（ETW）")
            self.act_precise.setEnabled(False)
            self.tray.setToolTip("NetMonitor Pro 22 · 精准进程流量已启用")
        elif traffic_status == "admin_required":
            self.act_precise.setText("启用精准进程流量（管理员）")
            self.act_precise.setEnabled(True)
            self.tray.setToolTip("NetMonitor Pro 22 · 普通权限模式")
        else:
            self.act_precise.setText("精准进程流量不可用")
            self.act_precise.setEnabled(False)
            self.act_precise.setToolTip(d.get("traffic_status_text", ""))

        # 当前代理端口：优先系统代理指向且在监听的端口；否则回退到监听中的常见代理端口
        # （TUN 模式下系统代理关着，注册表指向可能失效）
        cand = []
        cand.extend(proxy_server_ports(d.get("sp_srv", "")))
        cand += sorted(self.engine.PROXY_PORTS)
        listening = set(self.engine.listen_ports)
        self._proxy_port = next((p for p in cand if p in listening), cand[0] if cand else 7897)
        self._refresh_quality(d)

        # 软件灯表示 GUI；接管灯表示真实网络接管，两者不再互相代替。
        sw_gui = d["sw_on"] and d.get("gui_alive", True)
        self.light_sw.set_state("ok" if sw_gui else "off")
        chan = d.get("channel") or ""
        if sw_gui:
            src = f"已连接 {chan}" if chan else f"检测到 {d.get('sw_name', '代理软件')}"
            _tip_set(self.light_sw, f"代理软件: 运行中（{src}）")
        elif d["sw_on"]:
            # GUI 已关但内核仍在后台监听（如 Clash Verge 服务模式拉起内核）
            src = f"已连接 {chan}" if chan else f"检测到 {d.get('sw_name', '代理内核')}"
            _tip_set(self.light_sw, f"代理软件: 界面未运行（关窗即灭灯）\n内核状态: 仍在后台运行（{src}）")
        else:
            _tip_set(self.light_sw, "代理软件: 未运行")
        taken_over = bool(d.get("takeover"))
        effective_take = effective_proxy_takeover(d)
        if not effective_take:self.probe_retry_timer.stop()
        current_health_key = proxy_health_key(d)
        if current_health_key != getattr(self, "_latency_key", ""):
            self._set_latency(None, 0, current_health_key, "等待当前节点的 AI 探测")
        pending_delay_key = getattr(self, "_delay_pending_key", "")
        shown_delay_key = getattr(self, "_delay_result_key", "")
        if (not effective_take
                or (pending_delay_key and pending_delay_key != current_health_key)
                or (shown_delay_key and shown_delay_key != current_health_key)):
            self._delay_btn_probe = False
            self._delay_pending_key = ""
            self._delay_result_key = ""
            self.btn_delay.setText("测AI延迟")
            self.btn_delay.setEnabled(True)
        self.light_take.set_state("ok" if effective_take else ("warn" if sw_gui else "off"))
        ways = []
        ways.append("系统代理 开" if d["sp_on"] else "系统代理 关")
        ways.append("TUN 开" if d["tun_on"] else "TUN 关")
        take_tip = "接管方式: " + " · ".join(ways)
        if not sw_gui and d["sw_on"]:
            take_tip += ("\n界面已关闭；后台内核正在接管" if effective_take
                         else "\n界面已关闭；后台内核当前未接管")
        if d.get("mode") == "direct" and taken_over:
            take_tip += "\n直连模式：新连接不走代理节点；切换前的连接可能短暂保留"
        elif (d.get("mode") == "global" and d.get("global_now")
              and not is_proxy_exit(d["global_now"]) and taken_over):
            route = str(d["global_now"]).strip().upper()
            take_tip += ("\nGLOBAL 当前为拦截出口，没有代理节点流量" if route.startswith("REJECT")
                         else "\nGLOBAL 当前选择 DIRECT，不使用代理节点")
        _tip_set(self.light_take, take_tip)
        # 节点灯实时跟随接管开关：未接管立即熄灭，接管后按探测结果显示
        if not d["sw_on"] or not taken_over:
            self.light_node.set_state("off")
            _tip_set(self.light_node, "AI节点状态: 代理未接管")
            self.probe_state = None      # 状态清零，重开时不会拿旧状态误报
            self._probe_retry = 0
        elif d.get("mode") == "direct":
            # 直连模式不以互联网可达代替代理节点可达，避免绿灯误导。
            self.light_node.set_state("off")
            _tip_set(self.light_node, "直连模式：不探测代理节点；切换前的连接可能短暂保留")
            self.probe_state = None
            self._probe_retry = 0
        elif (d.get("mode") == "global" and d.get("global_now")
              and not is_proxy_exit(d["global_now"])):
            self.light_node.set_state("off")
            route = str(d["global_now"]).strip().upper()
            _tip_set(self.light_node, "GLOBAL 当前为拦截出口" if route.startswith("REJECT")
                     else "GLOBAL 当前选择 DIRECT，不经过代理节点")
            self.probe_state = None
            self._probe_retry = 0
        elif not d.get("api_on"):
            self.light_node.set_state("warn")
            _tip_set(self.light_node, "AI节点状态: 内核接口不可用，无法绕过订阅规则锁定节点")
            self.probe_state = None
        elif not d.get("ai_group"):
            self.light_node.set_state("warn")
            _tip_set(self.light_node, "AI节点状态: 无可识别的 AI 组或唯一主选择组；检测目标不明确")
            self.probe_state = None
        elif not d.get("ai_node"):
            self.light_node.set_state("warn")
            _tip_set(self.light_node, "当前选择为直连/拦截，或没有唯一可测试叶子节点；不是探测失败")
            self.probe_state = None
        elif current_health_key != self._prev_node:
            self.light_node.set_state("warn")
            _tip_set(self.light_node,
                     f"AI节点状态: 等待探测\n锁定目标: {d['ai_group']} → {d['ai_node']}")
        elif self.probe_state is None:
            self.light_node.set_state("warn")
            _tip_set(self.light_node,
                     f"AI节点状态: 等待探测\n锁定目标: {d['ai_group']} → {d['ai_node']}")

        # 迷你条内容（横竖两套同步更新）
        self._sync_node_lights()
        if d["proxy_up"] > 0 or d["proxy_down"] > 0:
            p_lab = (f"↑{fmt_speed(d['proxy_up'])}", f"↓{fmt_speed(d['proxy_down'])}")
        elif d.get("proxy_total", 0) > 0:
            p_lab = (("≈" if d.get("proxy_total_estimated") else "⇅"),
                     fmt_speed(d["proxy_total"]))
        else:
            p_lab = ("↑0", "↓0")
        vals = (f"↑{fmt_speed(d['sys_up'])}", f"↓{fmt_speed(d['sys_down'])}") + p_lab
        for labels in (self.mini_v_labels, self.mini_h_labels):
            for lab, v in zip(labels, vals):
                _lbl_set(lab, v)

        if self.mode == "full":
            _lbl_set(self.lbl_up, f"↑{fmt_speed(d['sys_up'])}/s")
            _lbl_set(self.lbl_down, f"↓{fmt_speed(d['sys_down'])}/s")
            proxy_up_text, proxy_down_text = format_proxy_speed_pair(d)
            _lbl_set(self.lbl_proxy_up, proxy_up_text)
            _lbl_set(self.lbl_proxy_down, proxy_down_text)
            estimated_proxy = bool(d.get("proxy_total_estimated"))
            proxy_tip = ("系统代理参考值：按连接本机代理端口的进程总流量估算；"
                         "无法拆分上下行，进程同时直连时可能偏高" if estimated_proxy
                         else "代理上传/下载（Mihomo API 或 TUN 网卡）")
            _tip_set(self.lbl_proxy_up, proxy_tip)
            _tip_set(self.lbl_proxy_down, proxy_tip)
            self.spark.push(d["sys_down"])
            proxy_context = sw_gui or effective_take
            if proxy_context:
                health_key = proxy_health_key(d)
                # GUI 已关闭但后台内核确实接管时，API 节点/分流仍是当前真实网络数据。
                if d.get("api_on"):
                    self.btn_delay.setEnabled(True)
                    self.btn_ip_quality.setEnabled(True)
                    _lbl_set(self.lbl_modes, mode_rich_text(d))
                    node_label, _shown_exit = format_node_status(d)
                    _lbl_set(self.lbl_node, node_label)
                    _tip_set(self.lbl_node, node_status_tooltip(d))
                    _lbl_set(self.lbl_split,
                             f"直连 {d['n_direct']} · 代理 {d['n_proxy']} · 拦截 {d['n_reject']}")
                else:
                    # 通用模式：无内核 API（如 FlClash 未开放接口）
                    _lbl_set(self.lbl_modes, mode_rich_text(d) + "（接口重连中）")
                    _tip_set(self.lbl_modes, d.get("api_error", ""))
                    if d.get("sel_node"):
                        grp = d.get("sel_group")
                        _lbl_set(self.lbl_node, f"当前选择: {grp} → {d['sel_node']}" if grp
                                 else f"当前节点: {d['sel_node']}")
                    else:
                        _lbl_set(self.lbl_node, "节点: 由代理软件内部管理（未开放接口）")
                    if d.get("proxy_stats_unknown"):
                        _lbl_set(self.lbl_split, "代理统计待确认（TUN 流量含直连，不计作节点流量）")
                    elif d.get("proxy_total_estimated") and d.get("proxy_total", 0) > 0:
                        _lbl_set(self.lbl_split, "代理统计: 系统代理相关进程总量（估算）")
                    else:
                        _lbl_set(self.lbl_split, "代理流量: 暂无可确认的节点流量（系统行保持蓝色）")
                    self.btn_delay.setEnabled(True)   # 通用模式：经代理通道实测延迟
                    self.btn_ip_quality.setEnabled(True)
                if d["rule_top"]:
                    _lbl_set(self.lbl_rules, "规则命中: " + "  ".join(f"{r}×{n}" for r, n in d["rule_top"]))
                else:
                    _lbl_set(self.lbl_rules, "")
            else:
                if d["sw_on"]:
                    state = ("当前仍在接管网络" if effective_take else
                             ("当前为直连模式" if d.get("mode") == "direct" else "当前未接管网络"))
                    _lbl_set(self.lbl_modes, f"代理软件界面未运行（后台内核运行中 · {state}）")
                else:
                    _lbl_set(self.lbl_modes, "代理软件未运行（仅显示全局网速与系统连接）")
                _lbl_set(self.lbl_node, "")
                _lbl_set(self.lbl_split, "")
                _lbl_set(self.lbl_rules, "")
                # 无代理也保持按钮可点，统一以面板内半透明提示反馈，不再弹阻塞对话框。
                self.btn_delay.setEnabled(True)
                self.btn_ip_quality.setEnabled(True)

            self._compact_empty_status()
            # Keep existing full/bare window sizes; freed space belongs to connections.
            self._bare = not proxy_context
            self._target_h = self.H_BARE if self._bare else self.H
            if self.mode == "full" and self.height() != self._target_h:
                self.resize(self.W, self._target_h)

            # 连接列表：代理接管时=分流明细；未接管=系统进程连接
            if self.mode == "full":
                if d["list_mode"] == "proxy":
                    section = "活跃连接（蓝=系统待确认 绿=直连 黄=代理 红=拦截 · 右列=真实路由）"
                elif d.get("traffic_accurate"):
                    section = "系统连接（蓝=出口待确认 · ETW 精准 ↑↓ · TCP/UDP/QUIC）"
                elif d.get("traffic_status") == "admin_required":
                    section = "系统连接（蓝=出口待确认 · 托盘可启用管理员精准 ↑↓）"
                else:
                    section = "系统连接（蓝=出口待确认 · 精准流量采集不可用）"
                # 列表模式切换（代理分流 ↔ 系统连接）时旧行数据已不对应，自动解除固定
                if self.freeze_conns:
                    if self._freeze_list_mode is None:
                        self._freeze_list_mode = d["list_mode"]
                    elif self._freeze_list_mode != d["list_mode"]:
                        self.freeze_conns = False
                        self._freeze_list_mode = None
                if self.freeze_conns:
                    section += "　⏸ 已固定（点击连接区恢复）"
                _lbl_set(self.sec_label, section)
                _tip_set(self.sec_label, d.get("traffic_status_text", ""))
                if not self.freeze_conns:
                    conns = d["conns"]
                    for i, row in enumerate(self.rows):
                        if i < len(conns):
                            row.set_data(conns[i])
                            row.show()
                        else:
                            row.hide()

        # AI 节点灯只跟随 AI服务 当前叶子节点。其它流量切换到国外网站、
        # 流媒体或 DIRECT 时，不得改变探测对象或沿用旧节点结果。
        node_now = proxy_health_key(d)
        take_now = effective_proxy_takeover(d)
        target_changed = node_now != self._prev_node
        if target_changed:
            self.probe_state = None
            self._probe_retry = 0
        if take_now and node_now and (not self._prev_take or target_changed):
            self.start_probe()
        self._prev_sw_on = d["sw_on"]
        self._prev_take = take_now
        self._prev_node = node_now
        self._sync_detection_buttons()
        # 长连接空闲是正常现象，不再把“15 秒零流量”误当断网并反复补测。
        # 周期探测、节点切换探测和失败退避已经覆盖真实通断检查。


# ----------------------------- 入口 -----------------------------

def selftest():
    stdout = getattr(sys, "stdout", None)
    try:
        stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    eng = DataEngine(capture="--no-capture" not in sys.argv)
    d = {}
    try:
        for _ in range(3):
            d = eng.tick()
            time.sleep(1.1)
        ai_delay = None
        if d.get("api_on") and proxy_action_node(d):
            ai_delay = eng.pipe.node_delay(
                proxy_action_node(d), url=AI_PROBE_URL, timeout=8000,
            )
        payload = {
            "sw_on": d["sw_on"], "api_on": d.get("api_on"),
            "sp_on": d["sp_on"], "sp_srv": d.get("sp_srv"),
            "tun_on": d["tun_on"], "strict_route": d.get("strict_route"), "mode": d["mode"],
            "n_direct": d["n_direct"], "n_proxy": d["n_proxy"],
            "sel_group": d.get("sel_group"), "sel_node": d.get("sel_node"),
            "active_group": d.get("active_group"), "active_node": d.get("active_node"),
            "active_route_group": d.get("active_route_group"),
            "active_route_exit": d.get("active_route_exit"),
            "ai_group": d.get("ai_group"), "ai_node": d.get("ai_node"),
            "ai_group_type": d.get("ai_group_type"),
            "ai_source": d.get("ai_source"),
            "ai_probe_key": proxy_health_key(d),
            "ai_probe_url": AI_PROBE_URL,
            "ai_delay_ms": ai_delay,
            "groups": d["groups"],
            "proxy_up_Bs": round(d["proxy_up"], 1),
            "proxy_down_Bs": round(d["proxy_down"], 1),
            "proxy_total_Bs": round(d.get("proxy_total", 0), 1),
            "proxy_total_estimated": bool(d.get("proxy_total_estimated")),
            "traffic_status": d.get("traffic_status"),
            "traffic_status_text": d.get("traffic_status_text"),
            "traffic_events": d.get("traffic_events"),
            "history_status": d.get("history_status"),
            "history_error": d.get("history_error"),
            "history_path": d.get("history_path"),
            "history_dropped": d.get("history_dropped"),
            "sample": [
                {"host": c["host"], "exit": c["exit"], "kind": c["kind"],
                 "display_class": connection_class(c),
                 "group": c["group"],
                 "route_state": system_route_state(c) if c["kind"] == "sys" else c["kind"],
                 "proxy_sockets": c.get("proxy_socket_count", 0),
                 "direct_sockets": c.get("direct_socket_count", 0),
                 "up_Bs": round(c.get("up", 0), 1),
                 "down_Bs": round(c.get("down", 0), 1)}
                for c in d["conns"][:6]
            ],
        }
        rendered = json.dumps(payload, ensure_ascii=False, indent=2)
        if "--selftest-output" in sys.argv:
            idx = sys.argv.index("--selftest-output")
            if idx + 1 < len(sys.argv):
                with open(sys.argv[idx + 1], "w", encoding="utf-8") as out:
                    out.write(rendered)
        elif stdout is not None:
            print(rendered)
    finally:
        eng.close()


if __name__ == "__main__":
    setup_logging()
    def _exception_hook(kind, value, traceback):
        LOG.error("unhandled exception", exc_info=(kind, value, traceback))
        sys.__excepthook__(kind, value, traceback)
    sys.excepthook = _exception_hook
    if "--selftest" in sys.argv:
        selftest()
        sys.exit(0)
    if "--elevated-relaunch" in sys.argv:
        # ShellExecute creates the elevated process just before the normal
        # instance exits. Give its per-user file lock a moment to release.
        time.sleep(0.8)
    _smoketest = "--smoketest" in sys.argv
    # 单实例守卫：锁位于固定的 LocalAppData 产品目录，不受安装路径、ZIP
    # 解压目录和 UAC 前后进程完整性影响。额外扫描旧版窗口，避免跨版本并跑。
    _instance_lock = acquire_instance_lock(_smoketest)
    _existing_hwnd = None if _smoketest else find_existing_netmonitor_window()
    if _instance_lock is None or _existing_hwnd:
        if _existing_hwnd is None and not _smoketest:
            time.sleep(0.25)  # 另一实例可能刚取得锁、窗口尚未创建
            _existing_hwnd = find_existing_netmonitor_window()
        activate_netmonitor_window(_existing_hwnd)
        release_instance_lock(_instance_lock)
        sys.exit(0)
    # 默认双击即申请管理员令牌，成功后直接启用 ETW 精准进程流量。
    # 自检/冒烟测试不弹 UAC；--normal-mode 是取消授权或排障时的显式后备入口。
    if (not _smoketest
            and "--normal-mode" not in sys.argv
            and "--elevated-relaunch" not in sys.argv
            and not is_user_admin()):
        if request_elevated_relaunch():
            sys.exit(0)
    app = QApplication(sys.argv)
    app.setFont(QFont("Microsoft YaHei UI", 9))
    qInstallMessageHandler(lambda kind, context, message:
                          LOG.warning("Qt %s: %s", kind, display_text(message)[:1000]))
    app.setQuitOnLastWindowClosed(False)
    # Win10/11 深色模式下 Qt 工具提示会跟随系统深色背景但文字色不跟随 → 黑底黑字空盒子。
    # 显式指定前景/背景色修复
    app.setStyleSheet(
        f"QToolTip {{ background-color: {theme.SURFACE}; color: {theme.TEXT}; "
        "border: 1px solid #8796A9; padding: 6px 8px; font-size: 12px; }")
    w = NetMonitorWidget()
    w.show()
    if _smoketest:
        QTimer.singleShot(2500, app.quit)
    sys.exit(app.exec())
