# -*- coding: utf-8 -*-
"""Clash 系内核 API 客户端 —— 多通道自动识别（命名管道 / TCP API 端口）"""
import ctypes
import json
import re
import socket
import time
from ctypes import wintypes

GENERIC_READ_WRITE = 0xC0000000
OPEN_EXISTING = 3

# 常见 Clash 系内核的通道候选
PIPE_CANDIDATES = [
    r"\\.\pipe\verge-mihomo",      # Clash Verge Rev
    r"\\.\pipe\mihomo",            # 原生 mihomo / 其他发行版
    r"\\.\pipe\mihomo-party",      # Mihomo Party
    r"\\.\pipe\clash-meta",        # Clash Meta 系
]
TCP_CANDIDATES = [9097, 9090, 9099, 2080]  # CFW/ClashX 常用 9090，Verge 桌面模式 9097
PROXY_GROUP_TYPES = ("Selector", "URLTest", "Fallback", "LoadBalance")


def _ai_group_rank(name):
    """Return a stable preference rank for common AI proxy-group names."""
    raw = str(name or "").strip().casefold()
    compact = "".join(ch for ch in raw if ch.isalnum())
    if compact in {"ai", "ai服务", "aiservice", "人工智能", "人工智能服务"}:
        return 0
    if ("ai服务" in compact or "aiservice" in compact
            or "人工智能" in compact):
        return 1
    # Keep the ASCII token boundary so names such as "Main" are not mistaken
    # for an AI group merely because they contain the letters "ai".
    if re.search(r"(^|[^a-z0-9])ai([^a-z0-9]|$)", raw):
        return 2
    return None


def _is_proxy_leaf(name):
    value = str(name or "").strip()
    upper = value.upper()
    return bool(value and upper not in {
        "DIRECT", "PASS", "COMPATIBLE", "REJECT", "REJECT-DROP",
        "REJECT-TINYGIF",
    } and not upper.startswith("REJECT"))


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


class MihomoPipe:
    def __init__(self, pipe=r"\\.\pipe\verge-mihomo", secret="set-your-secret"):
        self.pipe = pipe
        self.secret = secret
        self._k32 = ctypes.windll.kernel32
        self._chan = None          # ('pipe', path) 或 ('tcp', port, use_auth)
        self.channel_name = ""

    # ---------- 通道探测 ----------
    def available(self):
        """非阻塞：通道已建立→True；冷却中→False；冷却到期→后台线程探测并立即返回 False"""
        if self._chan is not None:
            return True
        now = time.time()
        if now - getattr(self, "_detect_fail_t", 0) < 10:
            return False
        if getattr(self, "_detecting", False):
            return False
        # 冷却立即生效并后台探测，绝不阻塞调用方（UI 线程）
        self._detect_fail_t = now
        self._detecting = True
        import threading
        threading.Thread(target=self._detect_bg, daemon=True).start()
        return False

    def _detect_bg(self):
        try:
            self._detect()
        except Exception:
            pass
        finally:
            self._detecting = False

    def _detect(self):
        for p in PIPE_CANDIDATES:
            h = self._k32.CreateFileW(p, GENERIC_READ_WRITE, 0, None, OPEN_EXISTING, 0, None)
            ok = h not in (None, 0, -1) and h != 0xFFFFFFFFFFFFFFFF
            if ok:
                self._k32.CloseHandle(h)
                self._chan = ("pipe", p)
                self.channel_name = f"管道 {p.split(chr(92))[-1]}"
                return True
        for port in TCP_CANDIDATES:
            for use_auth in (True, False):
                if self._tcp_ok(port, use_auth):
                    self._chan = ("tcp", port, use_auth)
                    self.channel_name = f"API 127.0.0.1:{port}"
                    return True
        return False

    def _tcp_ok(self, port, use_auth):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.25)
            s.settimeout(0.5)
            auth = f"Authorization: Bearer {self.secret}\r\n" if use_auth else ""
            s.sendall(f"GET /version HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Connection: close\r\n\r\n".encode())
            data = s.recv(512)
            s.close()
            return b"200" in data.split(b"\r\n", 1)[0] and b"version" in data
        except Exception:
            return False

    def mark_dead(self):
        """当前通道失效（软件关闭）时调用，下次重新探测"""
        self._chan = None
        self.channel_name = ""

    # ---------- 传输 ----------
    def _raw_once(self, path):
        if self._chan is None:
            return None
        if self._chan[0] == "pipe":
            return self._raw_pipe(path)
        return self._raw_tcp(path)

    def _raw_pipe(self, path):
        h = self._k32.CreateFileW(self._chan[1], GENERIC_READ_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if h in (None, 0, -1) or h == 0xFFFFFFFFFFFFFFFF:
            return None
        try:
            req = (f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                   f"Authorization: Bearer {self.secret}\r\nConnection: close\r\n\r\n")
            self._k32.WriteFile(h, req.encode(), len(req), None, None)
            self._k32.FlushFileBuffers(h)
            chunks, buf, n = [], ctypes.create_string_buffer(65536), wintypes.DWORD(0)
            for _ in range(200):
                ok = self._k32.ReadFile(h, buf, 65536, ctypes.byref(n), None)
                if not ok or n.value == 0:
                    break
                chunks.append(buf.raw[: n.value])
            data = b"".join(chunks)
        finally:
            self._k32.CloseHandle(h)
        head, _, body = data.partition(b"\r\n\r\n")
        if b"chunked" in head.lower():
            return _dechunk(body)
        return body if body else None

    def _raw_tcp(self, path):
        _, port, use_auth = self._chan
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.settimeout(3)
            auth = f"Authorization: Bearer {self.secret}\r\n" if use_auth else ""
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Connection: close\r\n\r\n".encode())
            chunks = []
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            s.close()
        except Exception:
            return None
        data = b"".join(chunks)
        head, _, body = data.partition(b"\r\n\r\n")
        if b"chunked" in head.lower():
            return _dechunk(body)
        return body if body else None

    def _raw(self, path):
        import time as _t
        for _ in range(3):
            r = self._raw_once(path)
            if r:
                return r
            _t.sleep(0.15)
        self.mark_dead()
        return None

    def get(self, path):
        raw = self._raw(path)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def connections(self):
        return self.get("/connections") or {}

    def configs(self):
        return self.get("/configs") or {}

    def proxies(self):
        return self.get("/proxies") or {}

    def node_delay(self, name, url="https://www.gstatic.com/generate_204", timeout=3000):
        from urllib.parse import quote
        r = self.get(f"/proxies/{quote(name, safe='')}/delay?url={quote(url, safe='')}&timeout={timeout}")
        if r and "delay" in r:
            return r["delay"]
        return None

    def active_groups(self, snapshot=None):
        """返回 [(组名, 当前节点, 类型), ...]，手动选择器优先"""
        out = []
        data = self.proxies() if snapshot is None else snapshot
        for name, p in (data.get("proxies") or {}).items():
            t = p.get("type", "")
            if t in PROXY_GROUP_TYPES and name not in ("GLOBAL",):
                out.append((name, p.get("now", "?"), t))
        order = {"Selector": 0, "URLTest": 1, "Fallback": 2, "LoadBalance": 3}
        out.sort(key=lambda x: order.get(x[2], 9))
        return out

    @staticmethod
    def _group_leaf(proxies, group_name):
        """Resolve a nested proxy group to its currently selected leaf."""
        current = str(group_name or "").strip()
        seen = set()
        while current in proxies and proxies[current].get("type") in PROXY_GROUP_TYPES:
            if current in seen:
                return ""
            seen.add(current)
            current = str(proxies[current].get("now") or "").strip()
            if not current:
                return ""
        return current if _is_proxy_leaf(current) else ""

    def ai_selection(self, snapshot=None):
        """Return ``(AI group, selected leaf, group type)`` without using rules.

        Providers decorate the same semantic group in many ways (for example
        ``AI服务`` and ``🧚 AI服务``).  The match is deliberately limited to
        proxy groups and never falls back to the main selector or the currently
        active route.  Callers can therefore fail closed instead of silently
        testing an unrelated ``国外网站`` group.
        """
        data = self.proxies() if snapshot is None else snapshot
        proxies = data.get("proxies") or {}
        type_order = {"Selector": 0, "URLTest": 1, "Fallback": 2,
                      "LoadBalance": 3}
        candidates = []
        for order, (name, item) in enumerate(proxies.items()):
            group_type = item.get("type", "")
            if group_type not in PROXY_GROUP_TYPES or str(name).upper() == "GLOBAL":
                continue
            rank = _ai_group_rank(name)
            if rank is None:
                continue
            candidates.append((rank, type_order.get(group_type, 9), order,
                               str(name), group_type))
        for _rank, _type_rank, _order, name, group_type in sorted(candidates):
            leaf = self._group_leaf(proxies, name)
            if leaf:
                return name, leaf, group_type
        return None

    def main_selection(self, snapshot=None):
        """返回普通路由模式的主入口组及其最终节点。

        GLOBAL 是 Mihomo 的特殊全局组，只应在 global 模式读取。普通 rule
        模式优先选择未被其它组引用的根 Selector，再链式解析到叶子节点。
        """
        data = self.proxies() if snapshot is None else snapshot
        proxies = data.get("proxies") or {}
        groups = {n: p for n, p in proxies.items()
                  if (p.get("type") in PROXY_GROUP_TYPES
                      and n.upper() != "GLOBAL")}
        if not groups:
            return None

        referenced = {p.get("now") for p in groups.values() if p.get("now") in groups}
        roots = [n for n in groups if n not in referenced]
        root_selectors = [n for n in roots if groups[n].get("type") == "Selector"]
        all_selectors = [n for n, p in groups.items() if p.get("type") == "Selector"]
        candidates = root_selectors or roots or all_selectors or list(groups)
        main = candidates[0]
        node, seen = groups[main].get("now", "?"), set()
        while node in groups and node not in seen:
            seen.add(node)
            node = groups[node].get("now", node)
        return main, node

    def global_selection(self, snapshot=None):
        """全局模式的真实出口：GLOBAL 组链式解析到最终节点（全局模式流量只走 GLOBAL）"""
        data = self.proxies() if snapshot is None else snapshot
        proxies = data.get("proxies") or {}
        g = proxies.get("GLOBAL") or {}
        groups = {n: p for n, p in proxies.items()
                  if p.get("type") in PROXY_GROUP_TYPES}
        node, seen = g.get("now", ""), set()
        while node in groups and node not in seen:
            seen.add(node)
            node = groups[node].get("now", node)
        return node
