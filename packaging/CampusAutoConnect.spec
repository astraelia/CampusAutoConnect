# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import os
import sys

from PyInstaller.utils.hooks import collect_all
pw_datas, pw_binaries, pw_imports = collect_all("playwright")
root = Path(SPECPATH).parent
assets = root / 'src' / 'campus_autoconnect' / 'assets'
windows = Path(os.environ.get('SYSTEMROOT', r'C:\Windows'))
# Build tools on PATH may ship incompatible DLLs with Windows-system names (e.g. ICU).
os.environ['PATH'] = os.pathsep.join(str(path) for path in (
    Path(sys.prefix) / 'Scripts', Path(sys.base_prefix), Path(sys.base_prefix) / 'DLLs',
    windows / 'System32', windows,
))
a = Analysis(
    [str(root / 'src' / 'campus_autoconnect' / 'entry.py')],
    pathex=[str(root / 'src')],
    binaries=pw_binaries,
    datas=[(str(assets), 'campus_autoconnect/assets'), *pw_datas],
    hiddenimports=['keyring.backends.Windows', 'PySide6.QtNetwork', *pw_imports],
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=['tkinter', 'pytest', 'PySide6.QtQml', 'PySide6.QtQuick',
              'PySide6.QtWebEngineCore', 'PySide6.QtWebEngineWidgets'],
    noarchive=False, optimize=0,
)
allowed_binary_roots = [Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve(), windows.resolve()]
foreign = [Path(source).name for _, source, _ in a.binaries
           if not any(Path(source).resolve().is_relative_to(base) for base in allowed_binary_roots)]
if foreign:
    raise ValueError('Undeclared binary dependency: ' + ', '.join(sorted(set(foreign))))
# Windows 10/11 provides ICU/API sets; never redistribute a different tool's substitutes.
a.binaries = [entry for entry in a.binaries
              if Path(entry[0]).name.lower() != 'icuuc.dll'
              and not Path(entry[0]).name.lower().startswith(('api-ms-win-', 'ext-ms-win-'))]
pyz = PYZ(a.pure)
options = [('X utf8', None, 'OPTION')]
gui = EXE(
    pyz, a.scripts, options, exclude_binaries=True, name='CampusAutoConnect',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    console=False, disable_windowed_traceback=True,
    icon=str(assets / 'app.ico'), version=str(root / 'packaging' / 'version_info.txt'),
    uac_admin=False,
)
cli = EXE(
    pyz, a.scripts, options, exclude_binaries=True, name='CampusAutoConnect-CLI',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    console=True, icon=str(assets / 'app.ico'),
    version=str(root / 'packaging' / 'version_info.txt'), uac_admin=False,
)
collection = COLLECT(
    gui, cli, a.binaries, a.datas, strip=False, upx=False,
    name='CampusAutoConnect-1.0.1-win-x64',
)
