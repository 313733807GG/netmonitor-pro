"""Portable public entry point; run with your own Python 3.12 environment."""
from pathlib import Path
import os
import runpy
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]
sys.dont_write_bytecode = True

def main():
    command = sys.argv[1] if len(sys.argv) > 1 else 'help'
    if command == 'test':
        import unittest
        tests = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
        from unittest.mock import patch
        # Offline tests use a dummy configured key and never read real credentials.
        # Missing-key and DPAPI tests override this patch explicitly.
        with patch('cleanip_credentials.load_key', return_value='unit-test-cleanip-key'):
            result = unittest.TextTestRunner(verbosity=1).run(tests)
        return 0 if result.wasSuccessful() else 1
    if command == 'check':
        import ssl, PySide6, psutil, etw, win32api
        print('Python:', sys.version.split()[0], 'SSL:', ssl.OPENSSL_VERSION)
        for module in (PySide6, psutil, etw, win32api):
            print(module.__name__, module.__file__)
        return 0
    if command == 'run':
        sys.argv = [str(ROOT / 'src' / 'app.py')] + sys.argv[2:]
        runpy.run_path(sys.argv[0], run_name='__main__')
        return 0
    if command == 'build':
        import PyInstaller.__main__
        os.chdir(ROOT / 'src')
        PyInstaller.__main__.run(['--noconfirm', '--workpath', str(ROOT / 'build'),
                                 '--distpath', str(ROOT / 'dist'), 'NetMonitor.spec'])
        return 0
    print('Commands: check | test | run | build. Build never installs or restarts the app.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
