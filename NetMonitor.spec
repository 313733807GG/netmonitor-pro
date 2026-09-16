# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('使用说明.txt', '.'),
        ('CHANGELOG_v19.md', '.'),
        ('优化说明_v19.md', '.'),
        ('THIRD_PARTY_LICENSES', 'THIRD_PARTY_LICENSES'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# PyInstaller's PySide6 hook also gathers optional QML/Quick/PDF/OpenGL,
# virtual-keyboard, TLS and translation assets.  This widget uses only
# QtCore/QtGui/QtWidgets plus the Windows platform and basic image loaders.
_qt_runtime_keep = {
    'pyside6/msvcp140.dll',
    'pyside6/msvcp140_1.dll',
    'pyside6/msvcp140_2.dll',
    'pyside6/vcruntime140.dll',
    'pyside6/vcruntime140_1.dll',
    'pyside6/pyside6.abi3.dll',
    'pyside6/qt6core.dll',
    'pyside6/qt6gui.dll',
    'pyside6/qt6widgets.dll',
    'pyside6/qtcore.pyd',
    'pyside6/qtgui.pyd',
    'pyside6/qtwidgets.pyd',
}
_qt_plugin_keep = {
    'pyside6/plugins/platforms/qwindows.dll',
    'pyside6/plugins/platforms/qoffscreen.dll',
    'pyside6/plugins/styles/qmodernwindowsstyle.dll',
    'pyside6/plugins/imageformats/qico.dll',
    'pyside6/plugins/imageformats/qjpeg.dll',
}


def _keep_runtime_entry(entry):
    destination = entry[0].replace('\\', '/').lower()
    if not destination.startswith('pyside6/'):
        return True
    if destination.startswith('pyside6/plugins/'):
        return destination in _qt_plugin_keep
    if destination.startswith('pyside6/translations/'):
        return False
    return destination in _qt_runtime_keep


a.binaries = [entry for entry in a.binaries if _keep_runtime_entry(entry)]
a.datas = [entry for entry in a.datas if _keep_runtime_entry(entry)]

# Some PyInstaller/Python runtime combinations discover private copies of the
# Windows UCRT/API-set forwarders and ICU beside the build interpreter.  When
# bundled at application root they shadow Windows' own loader targets and Qt
# can fail with ERROR_PROC_NOT_FOUND while importing QtCore.  The working v17
# runtime deliberately relied on the Windows copies, so exclude these shadows.
_windows_runtime_shadows = {
    'ucrtbase.dll',
    'icuuc.dll',
    'icudt78.dll',
}


def _keep_windows_runtime_entry(entry):
    name = entry[0].replace('\\', '/').rsplit('/', 1)[-1].lower()
    return not (name.startswith('api-ms-win-') or name in _windows_runtime_shadows)


a.binaries = [entry for entry in a.binaries if _keep_windows_runtime_entry(entry)]
a.datas = [entry for entry in a.datas if _keep_windows_runtime_entry(entry)]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetMonitor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetMonitor',
)
