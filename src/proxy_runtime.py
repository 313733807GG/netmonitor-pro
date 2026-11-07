"""Separate FlClash's configured switches from its live network listeners.

The controller, old connections and NetMonitor auxiliary listener survive Stop.
Only ordinary listener ports and the exact live TUN interface count here.
No probing, connection creation, global interface guessing or settings writes.
"""

def flclash_runtime(config, interfaces):
    tun = config.get('tun') or {}
    configured = tun.get('enable') is True
    device = tun.get('device') or 'FlClash'
    if not configured:
        active = False
    elif interfaces is None:
        active = None
    else:
        state = interfaces.get(device)
        active = bool(state and state.isup)
    keys = ('port', 'socks-port', 'mixed-port', 'redir-port', 'tproxy-port')
    ports = [config[k] for k in keys if k in config]
    valid = bool(ports) and all(type(p) is int and 0 <= p <= 65535 for p in ports)
    listening = any(p > 0 for p in ports) if valid else None
    if listening is True or active is True:
        running = True
    elif listening is False and active is False:
        running = False
    else:
        running = None
    return {'proxy_running': running, 'tun_active': active,
            'tun_configured': configured, 'runtime_uncertain': running is None}
