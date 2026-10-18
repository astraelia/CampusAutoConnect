# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import os
import sys

tool = Path(SPECPATH)
workspace = tool.parent
windows = Path(os.environ.get('SYSTEMROOT', r'C:\Windows'))
os.environ['PATH'] = os.pathsep.join(str(path) for path in (
    Path(sys.prefix) / 'Scripts', Path(sys.base_prefix), Path(sys.base_prefix) / 'DLLs',
    windows / 'System32', windows,
))
a = Analysis(
    [str(tool / 'inspector.py')],
    pathex=[str(tool), str(workspace / 'src')],
    binaries=[], datas=[],
    hiddenimports=['keyring.backends.Windows', 'campus_inspector.selfcheck'],
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=['tkinter', 'pytest', 'PySide6.QtQml', 'PySide6.QtQuick',
              'PySide6.QtWebEngineCore', 'PySide6.QtWebEngineWidgets'],
    noarchive=False, optimize=0,
)
allowed = [Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve(), windows.resolve()]
foreign = [Path(source).name for _, source, _ in a.binaries
           if not any(Path(source).resolve().is_relative_to(base) for base in allowed)]
if foreign:
    raise ValueError('Undeclared binary dependencies: ' + ', '.join(sorted(set(foreign))))
a.binaries = [entry for entry in a.binaries
              if Path(entry[0]).name.lower() != 'icuuc.dll'
              and not Path(entry[0]).name.lower().startswith(('api-ms-win-', 'ext-ms-win-'))]
pyz = PYZ(a.pure)
options = [('X utf8', None, 'OPTION')]
gui = EXE(
    pyz, a.scripts, options, exclude_binaries=True, name='CampusInspector',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    console=False, disable_windowed_traceback=True, uac_admin=False,
)
cli = EXE(
    pyz, a.scripts, options, exclude_binaries=True, name='CampusInspector-CLI',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    console=True, uac_admin=False,
)
collection = COLLECT(gui, cli, a.binaries, a.datas, strip=False, upx=False, name='CampusInspector-0.1.2-win-x64')
