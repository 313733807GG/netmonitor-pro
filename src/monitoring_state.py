"""Pure state helpers shared by UI and tests."""
from pipe_client import MihomoPipe
import ui_theme as theme

def strict_route_state(config, api_on=True):
    """Mihomo serializes strict-route with omitempty: false is absent.

    Only apply that default to a recognizable, complete TUN API object;
    an unavailable/partial controller response must remain unknown.
    """
    if not api_on or not isinstance(config,dict) or config.get('mode') not in ('rule','global','direct'):
        return None
    tun=config.get('tun')
    if not isinstance(tun,dict):return None
    if 'strict-route' in tun:
        value=tun['strict-route']
        return value if isinstance(value,bool) else None
    if (isinstance(tun.get('enable'),bool) and isinstance(tun.get('auto-route'),bool)
            and isinstance(tun.get('stack'),str) and tun['stack']):
        return False
    return None


def route_evidence(chains, snapshot):
    """Missing API evidence is unknown, never DIRECT or paid proxy by default."""
    chain = [str(x) for x in chains if isinstance(x, str) and x] if isinstance(chains, list) else []
    if not chain:
        return "system", "", ""
    node = chain[0]
    item = (snapshot.get("proxies") or {}).get(node, {})
    kind = str(item.get("type", "")).casefold().replace("-", "")
    name = node.upper()
    if name == "DIRECT" or kind == "direct":
        category = "direct"
    elif name.startswith("REJECT") or kind in ("reject", "rejectdrop"):
        category = "reject"
    elif name in ("PASS", "COMPATIBLE") or kind in ("pass", "compatible", "selector", "urltest", "fallback", "loadbalance"):
        category = "system"
    else:
        category = "proxy"
    return category, node, chain[-1]


def probe_selection(pipe, snapshot, mode):
    """GLOBAL wins in global mode; rule mode retains the dedicated AI selection."""
    if mode == "direct":
        return None
    if mode == "global":
        proxies = snapshot.get("proxies") or {}
        if "GLOBAL" not in proxies:
            return None
        return "GLOBAL", MihomoPipe._group_leaf(proxies, "GLOBAL"), str(proxies['GLOBAL'].get('type','Selector'))
    if mode != "rule":
        return None
    return pipe.ai_selection(snapshot)


def mode_label(data):
    mode = {"rule":"规则", "global":"全局", "direct":"直连"}.get(data.get("mode"), "未知")
    return f"系统代理 {'开' if data.get('sp_on') else '关'} · TUN {'开' if data.get('tun_on') else '关'} · {mode}模式"


def latency_style(ok, milliseconds):
    """HTTP probe latency bands, UI conventions rather than a universal standard."""
    if ok is None:
        return "— ms", theme.MUTED
    if not ok:
        return "超时/失败", theme.RED
    milliseconds = max(0, int(milliseconds))
    color = theme.GREEN if milliseconds <= 200 else (theme.YELLOW if milliseconds <= 500 else theme.RED)
    return f"{milliseconds} ms", color


def proxy_switch_state(data):
    """Whether a supported client's real proxy switches allow manual quality checks."""
    data = data if isinstance(data, dict) else {}
    client = data.get('client_id') or {
        'Clash Verge': 'verge', 'FlClash': 'flclash',
    }.get(data.get('sw_name'), '')
    label = {'verge': 'Clash Verge', 'flclash': 'FlClash'}.get(client, '代理软件')
    if not data.get('sw_on'):
        return False, f'未检测到{label}正在运行'
    if client == 'flclash' and data.get('proxy_running') is not True:
        return False, 'FlClash 代理开关未开启，手动 IP 检测不可用'
    if not (data.get('sp_on') or data.get('tun_on')):
        return False, f'{label} 未开启系统代理或 TUN，手动 IP 检测不可用'
    if not data.get('takeover'):
        return False, f'{label} 当前未实际接管网络，手动 IP 检测不可用'
    return True, ''
