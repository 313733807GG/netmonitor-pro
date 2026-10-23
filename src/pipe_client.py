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
    if any(word in compact for word in ("openai", "chatgpt", "claude", "anthropic", "gemini")):
        return 3
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


from controller_transport import ControllerTransport


class MihomoPipe(ControllerTransport):

    def select_probe_node(self, node):
        """Only write the user-authorized NetMonitor selector. No reload API."""
        from ip_quality import PROBE_GROUP
        from urllib.parse import quote
        channel = self._chan
        if channel is None:
            return False
        group = self.proxies().get('proxies', {}).get(PROBE_GROUP, {})
        if group.get('type') != 'Selector' or node not in group.get('all', []):
            return False
        try:
            status, _ = self._exchange(channel, '/proxies/' + quote(PROBE_GROUP, safe=''),
                                       3, method='PUT', payload={'name':node})
            return status in (200, 204)
        except (OSError, ValueError, TypeError):
            return False

    def connections(self):
        return self.get("/connections") or {}

    def configs(self):
        return self.get("/configs") or {}

    def proxies(self):
        return self.get("/proxies") or {}

    def node_delay(self, name, url="https://www.gstatic.com/generate_204", timeout=3000):
        from urllib.parse import quote
        r = self.get(f"/proxies/{quote(name, safe='')}/delay?url={quote(url, safe='')}&timeout={timeout}")
        if r and isinstance(r.get("delay"), (int, float)) and not isinstance(r.get("delay"), bool) and r["delay"] >= 0:
            return int(r["delay"])
        return None

    def active_groups(self, snapshot=None):
        """返回 [(组名, 当前节点, 类型), ...]，手动选择器优先"""
        out = []
        data = self.proxies() if snapshot is None else snapshot
        for name, p in (data.get("proxies") or {}).items():
            t = p.get("type", "")
            if t in PROXY_GROUP_TYPES and name not in ("GLOBAL", "NetMonitor-IP-Check"):
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
            if proxies[current].get("type") == "LoadBalance":
                return ""  # A load balancer has no single selected exit.
            current = str(proxies[current].get("now") or "").strip()
            if not current:
                return ""
        kind = str(proxies.get(current, {}).get("type", "")).upper()
        return current if (_is_proxy_leaf(current) and kind not in {
            "DIRECT", "PASS", "REJECT", "REJECTDROP", "COMPATIBLE",
        }) else ""

    def ai_selection(self, snapshot=None):
        """Resolve an AI group or a simple subscription's unique Selector.

        Explicit AI selections (including DIRECT) take precedence. Ambiguous
        groups are not guessed from current traffic. An empty leaf means the
        group exists but has no single testable proxy exit.
        """
        data = self.proxies() if snapshot is None else snapshot
        proxies = {n:p for n,p in (data.get("proxies") or {}).items() if n != 'NetMonitor-IP-Check'}
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
        if candidates:
            _rank, _type_rank, _order, name, group_type = min(candidates)
            leaf = self._group_leaf(proxies, name)
            return name, leaf, group_type
        # Simple subscriptions often expose just one provider-named Selector
        # plus automatic/fallback helpers. Use that explicit entry, not traffic
        # statistics or the first arbitrary group. Multiple selectors are ambiguous.
        selectors = [(n, p) for n, p in proxies.items()
                     if n != "GLOBAL" and p.get("type") == "Selector"]
        if len(selectors) == 1:
            name, item = selectors[0]
            if not any(word in name.casefold() for word in (
                    "国外", "流媒体", "广告", "游戏", "下载", "电视",
                    "foreign", "stream", "media", "netflix", "youtube", "gaming")):
                leaf = self._group_leaf(proxies, name)
                return name, leaf, item["type"]
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
                      and n.upper() != "GLOBAL" and n != 'NetMonitor-IP-Check')}
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
