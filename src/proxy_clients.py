"""Read-only desktop client metadata; never log subscriptions or credentials."""
import json
import os
from pathlib import Path
import re

import psutil

VERGE_DIR = 'io.github.clash-verge-rev.clash-verge-rev'
FLCLASH_DIR = 'com.follow/clash'
CLIENT_LABELS = {'verge': 'Clash Verge', 'flclash': 'FlClash'}


def appdata_root():
    return Path(os.environ.get('APPDATA', ''))


def read_json(path):
    try:
        with open(path, encoding='utf-8-sig') as stream:
            text = stream.read(4 * 1024 * 1024 + 1)
        if len(text) > 4 * 1024 * 1024:
            return {}
        result = json.loads(text)
        return result if isinstance(result, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def flclash_settings(base=None):
    base = Path(base) if base is not None else appdata_root() / FLCLASH_DIR
    value = read_json(base / 'shared_preferences.json').get('flutter.config', {})
    try:
        if isinstance(value, str):
            value = json.loads(value)
    except (ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def read_controller_values(path):
    """Read only the three controller fields; JSON runtime files may be stale."""
    path = Path(path)
    keys = ('external-controller-pipe', 'external-controller', 'secret')
    if path.suffix.lower() == '.json':
        obj = read_json(path)
        return {k: obj[k] for k in keys if k in obj}
    values = {}
    try:
        with open(path, encoding='utf-8-sig') as stream:
            for line in stream:
                match = re.match(r'^(external-controller-pipe|external-controller|secret):\s*(.*?)\s*$', line)
                if not match:
                    continue
                value = match[2]
                if value.startswith('"'):
                    value = json.loads(value)
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1].replace("''", "'")
                else:
                    value = value.split(' #', 1)[0]
                values[match[1]] = value
    except (OSError, ValueError, TypeError):
        return {}
    return values


def local_endpoints(values):
    """Credentials can only go to local named pipes or loopback TCP."""
    if not isinstance(values, dict):
        return []
    secret = values.get('secret', '')
    if not isinstance(secret, str) or any(ord(c) < 32 or ord(c) == 127 for c in secret):
        return []
    result = []
    pipe = values.get('external-controller-pipe', '')
    if (isinstance(pipe, str) and pipe.startswith('\\\\.\\pipe\\')
            and not any(ord(c) < 32 for c in pipe)):
        result.append(('pipe', pipe, secret))
    address = values.get('external-controller', '')
    tcp = re.fullmatch(r'(?:127\.0\.0\.1|localhost|0\.0\.0\.0):([0-9]+)', address) if isinstance(address, str) else None
    if tcp and 0 < int(tcp[1]) < 65536:
        result.append(('tcp', int(tcp[1]), secret))
    return result


def running_clients():
    clients = set()
    try:
        for process in psutil.process_iter(['name']):
            name = (process.info.get('name') or '').lower()
            if 'service' in name or 'helper' in name:
                continue
            if name in ('flclash.exe', 'flclashcore.exe'):
                clients.add('flclash')
            elif name.startswith(('clash-verge', 'verge-mihomo')):
                clients.add('verge')
    except (psutil.Error, OSError):
        pass
    return clients


def configured_clients():
    base = appdata_root()
    records = []
    for name in ('clash-verge.yaml', 'config.yaml'):
        records.extend(('verge', c) for c in local_endpoints(read_controller_values(base / VERGE_DIR / name)))
    settings = flclash_settings(base / FLCLASH_DIR)
    patch = settings.get('patchClashConfig')
    if isinstance(patch, dict) and 'external-controller' in patch:
        # FlClash applies this setting live. Its config.json/config.yaml can
        # still describe an older full reload; never let those override OFF
        # or a newly rotated controller credential.
        records.extend(('flclash', c) for c in local_endpoints(patch))
    else:
        for name in ('config.yaml', 'config.json'):
            records.extend(('flclash', c) for c in local_endpoints(read_controller_values(base / FLCLASH_DIR / name)))
    active = running_clients()
    if active == {'flclash'}:
        records.sort(key=lambda item: item[0] != 'flclash')
    return list(dict.fromkeys(records))


def client_for_channel(channel):
    if not channel:
        return ''
    if channel[0] == 'pipe' and str(channel[1]).startswith('\\\\.\\pipe\\verge-mihomo'):
        return 'verge'
    for client, candidate in configured_clients():
        if candidate == channel:
            return client
    return ''


def profile_identity(channel, client=None):
    """Keep per-launch caches separate across clients and their subscriptions."""
    if not channel:
        return 'offline'
    client = client if client is not None else client_for_channel(channel)
    if client == 'flclash':
        value = flclash_settings().get('currentProfileId')
        value = str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else ''
        return 'flclash:' + (value if re.fullmatch(r'[0-9]{1,30}', value) else 'unknown')
    if client == 'verge':
        try:
            text = (appdata_root() / VERGE_DIR / 'profiles.yaml').read_text(encoding='utf-8-sig')
            match = re.search(r'^current:\s*([^\r\n]+)', text, re.M)
            value = match[1].split(' #', 1)[0].strip().strip('\'"') if match else ''
            return 'verge:' + (value[:128] or 'unknown')
        except (OSError, ValueError):
            return 'verge:unknown'
    # Include the endpoint, never its secret. An unsupported client must not
    # inherit the last known Clash Verge subscription or its scores.
    return f'mihomo:{channel[0]}:{channel[1]}:unknown'


def gui_process_matches(name, client=''):
    name = str(name or '').lower()
    if 'service' in name or 'helper' in name or name in ('flclashcore', 'flclashcore.exe'):
        return False
    if client == 'flclash':
        return name in ('flclash', 'flclash.exe')
    if client == 'verge':
        return name.startswith('clash-verge')
    return any(hint in name for hint in ('clash-verge','flclash','myclash','mihomo-party',
                                         'clashx','nekoray','nekobox','hiddify','stash','v2rayn','surge'))
