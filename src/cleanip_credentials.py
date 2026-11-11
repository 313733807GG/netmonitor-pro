"""Per-user Windows DPAPI storage; credentials never belong in a release."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re

class Blob(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]

def _crypt(data, protect=False):
    buf = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    fn = getattr(ctypes.WinDLL('crypt32', use_last_error=True),
                 'CryptProtectData' if protect else 'CryptUnprotectData')
    fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fn.restype = wintypes.BOOL
    if not fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
        raise ValueError('CleanIP 密钥无法解密，请在当前 Windows 用户下重新配置')
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        free = ctypes.WinDLL('kernel32').LocalFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = ctypes.c_void_p
        free(output.pbData)

def credential_path():
    return Path(os.environ['LOCALAPPDATA']) / 'NetMonitorPro' / 'credentials' / 'cleanip.dpapi'

def _validate(key):
    if not isinstance(key, str) or not re.fullmatch(r'cip_[0-9a-fA-F]{32,128}', key):
        raise ValueError('CleanIP 密钥格式无效，请重新配置')
    return key

def load_key():
    try:
        path = credential_path()
        if not path.exists():
            return ''
        if path.stat().st_size > 4096:
            raise ValueError('CleanIP 密钥文件异常，请重新配置')
        return _validate(_crypt(path.read_bytes()).decode('ascii'))
    except (OSError, UnicodeError, KeyError):
        raise ValueError('CleanIP 密钥无法读取，请重新配置') from None

def save_key(key):
    encrypted = _crypt(_validate(key.strip()).encode('ascii'), True)
    path = credential_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_bytes(encrypted)
    os.replace(temp, path)
