"""Read-only local Mihomo controller discovery and bounded HTTP transport."""
import ctypes
from ctypes import wintypes
import json
import logging
import os
from pathlib import Path
import re
import socket
import threading
import time
from proxy_clients import configured_clients, read_controller_values, local_endpoints, client_for_channel

LOG = logging.getLogger("netmonitor.controller")
PIPE_PREFIX = "\\\\.\\pipe\\"
PIPE_NAMES = ("verge-mihomo", "mihomo", "mihomo-party", "clash-meta")


def config_endpoints(paths=None):
    """Read only controller fields, never log subscriptions or credentials."""
    if paths is None:
        return list(dict.fromkeys(channel for _client, channel in configured_clients()))
    result = []
    for path in paths:
        try:
            result.extend(local_endpoints(read_controller_values(path)))
        except (OSError, ValueError, TypeError):
            continue
    return list(dict.fromkeys(result))


def decode_http(data, eof=False):
    """Return (status, body) only for a complete response. Never decode partial UTF-8."""
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        return None
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split()[1])
        headers = {k.strip().lower(): v.strip().lower()
                   for k, v in (line.split(b":", 1) for line in lines[1:] if b":" in line)}
        if b"chunked" in headers.get(b"transfer-encoding", b""):
            out, i = bytearray(), 0
            while True:
                j = body.find(b"\r\n", i)
                if j < 0:
                    return None
                size = int(body[i:j].split(b";", 1)[0], 16)
                if size == 0:
                    if len(body) < j + 4:
                        return None
                    return status, bytes(out)
                end = j + 2 + size
                if len(body) < end + 2:
                    return None
                if body[end:end + 2] != b"\r\n":
                    raise ValueError("bad chunk delimiter")
                out.extend(body[j + 2:end])
                i = end + 2
        if b"content-length" in headers:
            size = int(headers[b"content-length"])
            if size < 0:
                raise ValueError("negative content length")
            return (status, body[:size]) if len(body) >= size else None
        return (status, body) if eof else None
    except (ValueError, IndexError) as exc:
        raise ValueError("invalid controller HTTP response") from exc


class ControllerTransport:
    def __init__(self, pipe=PIPE_PREFIX + "verge-mihomo", secret="set-your-secret"):
        self.pipe, self.secret = pipe, secret
        self._chan = None
        self.channel_name = ""
        self.version = ""
        self.client_id = ""
        self.generation = 0
        self.last_error = ""
        self._lock = threading.Lock()
        self._detecting = False
        self._detect_fail_t = 0
        self._config_checked = 0
        self._configured = []
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self._k32
        k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k.CreateFileW.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        k.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        k.WriteFile.argtypes = k.ReadFile.argtypes
        k.PeekNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                   ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]

    def available(self):
        # Config discovery and I/O always happen in a background thread.
        if time.monotonic() - self._config_checked > 3 and not self._detecting:
            self._detecting = True
            threading.Thread(target=self._detect_bg, daemon=True).start()
        return self._chan is not None

    def _detect_bg(self):
        try:
            configured = config_endpoints()
            changed = configured != self._configured
            self._configured = configured
            if changed or self._chan is None:
                if changed:
                    self.mark_dead()
                self._detect()
        except Exception:
            LOG.exception("controller discovery failed")
        finally:
            self._config_checked = time.monotonic()
            self._detecting = False

    def _detect(self):
        candidates = config_endpoints()
        self._configured = list(candidates)
        candidates += [("pipe", self.pipe, self.secret)]
        try:
            names = sorted(os.listdir(PIPE_PREFIX))
            secrets = list(dict.fromkeys([c[2] for c in candidates
                                         if c[0] == 'pipe' and str(c[1]).startswith(PIPE_PREFIX+'verge-mihomo')]
                                        + [c[2] for client, c in configured_clients() if client == 'verge']
                                        + [self.secret, ""]))
            candidates += [("pipe", PIPE_PREFIX + name, secret) for name in names
                           if name.startswith(("verge-mihomo-sidecar-", "verge-mihomo-production-"))
                           for secret in secrets]
        except OSError:
            pass
        candidates += [("pipe", PIPE_PREFIX + name, self.secret) for name in PIPE_NAMES]
        candidates += [("tcp", port, secret) for port in (9097, 9090, 9099, 2080)
                       for secret in (self.secret, "")]
        for channel in dict.fromkeys(candidates):
            try:
                status, body = self._exchange(channel, "/version", 0.6)
                data = json.loads(body)
                if status != 200 or not isinstance(data, dict) or not data.get("version"):
                    continue
                with self._lock:
                    self._chan = channel
                    self.generation += 1
                    self.version = str(data["version"])
                    self.client_id = client_for_channel(channel)
                    self.channel_name = ("管道 " + str(channel[1]).split("\\")[-1]
                                         if channel[0] == "pipe" else f"API 127.0.0.1:{channel[1]}")
                    self.last_error = ""
                LOG.info("controller connected channel=%s version=%s generation=%s",
                         self.channel_name, self.version, self.generation)
                return True
            except (OSError, ValueError, TypeError):
                continue
        self.last_error = "未找到可访问的内核接口（请检查管理员权限/代理是否运行）"
        return False

    def mark_dead(self, expected=None):
        with self._lock:
            if expected is not None and self._chan != expected:
                return
            self._chan = None
            self.channel_name = ""
            self.client_id = ""
            self._config_checked = 0

    def _exchange(self, channel, path, timeout, method='GET', payload=None):
        if "\r" in path or "\n" in path:
            raise ValueError("invalid request path")
        if method not in ('GET','PUT'):
            raise ValueError('unsupported controller method')
        body = json.dumps(payload).encode('utf-8') if payload is not None else b''
        request = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n"
                   f"Authorization: Bearer {channel[2]}\r\nContent-Type: application/json\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("utf-8") + body
        deadline = time.monotonic() + timeout
        data = bytearray()
        handle = None
        sock = None
        try:
            if channel[0] == "pipe":
                handle = self._k32.CreateFileW(channel[1], 0xC0000000, 0, None, 3, 0, None)
                if handle in (None, 0, ctypes.c_void_p(-1).value):
                    handle = None
                    raise OSError("controller pipe unavailable")
                written = wintypes.DWORD()
                if not self._k32.WriteFile(handle, request, len(request), ctypes.byref(written), None) or written.value != len(request):
                    raise OSError("controller write failed")
            else:
                sock = socket.create_connection(("127.0.0.1", channel[1]), timeout=timeout)
                sock.sendall(request)
            while time.monotonic() < deadline:
                complete = decode_http(bytes(data))
                if complete is not None:
                    return complete
                if len(data) > 32 * 1024 * 1024:
                    raise OSError("controller response too large")
                eof = False
                if handle is not None:
                    available = wintypes.DWORD()
                    if not self._k32.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
                        eof = True
                    elif not available.value:
                        time.sleep(0.01)
                        continue
                    else:
                        size = min(available.value, 65536)
                        buf, received = ctypes.create_string_buffer(size), wintypes.DWORD()
                        ok = self._k32.ReadFile(handle, buf, size, ctypes.byref(received), None)
                        data.extend(buf.raw[:received.value])
                        eof = not ok or not received.value
                else:
                    sock.settimeout(max(0.01, deadline - time.monotonic()))
                    chunk = sock.recv(65536)
                    data.extend(chunk)
                    eof = not chunk
                if eof:
                    complete = decode_http(bytes(data), eof=True)
                    if complete is not None:
                        return complete
                    raise OSError("incomplete controller response")
            raise TimeoutError("controller deadline exceeded")
        finally:
            if handle is not None:
                self._k32.CloseHandle(handle)
            if sock is not None:
                sock.close()

    def get(self, path):
        channel = self._chan
        if channel is None:
            return None
        delay_request = "/delay?" in path
        timeout_match = re.search(r"[?&]timeout=(\d+)", path)
        timeout = min(int(timeout_match[1]) / 1000 + 1, 20) if timeout_match else 2
        try:
            status, raw = self._exchange(channel, path, timeout)
            if status != 200:
                LOG.warning("controller HTTP %s endpoint=%s", status, "delay" if delay_request else path.split("?")[0])
                if status in (401, 403):
                    self.mark_dead(channel)
                self.last_error = f"内核接口 HTTP {status}"
                return None
            result = json.loads(raw.decode("utf-8"))
            if not isinstance(result, dict):
                raise ValueError("expected JSON object")
            self.last_error = ""
            return result
        except (OSError, ValueError, TypeError) as exc:
            self.last_error = f"内核接口读取失败: {type(exc).__name__}"
            LOG.warning("controller request failed endpoint=%s error=%s", "delay" if delay_request else path, type(exc).__name__)
            # A single node timing out must not disconnect the healthy API.
            if not delay_request:
                self.mark_dead(channel)
            return None
