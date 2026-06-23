# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for WP Guard (Windows). Run from build/windows/."""

import os

from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None
ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))

hiddenimports = [
    "runtime_paths",
    "dns",
    "dns.resolver",
    "dns.rdtypes",
    "dns.rdtypes.ANY",
    "dns.rdtypes.IN",
    "dns.btree",
    "dns.btreezone",
    "dns.e164",
    "dns.namedict",
    "dns.tsigkeyring",
    "dns.versioned",
    "engineio.async_drivers.eventlet",
    "eventlet.hubs.selects",
    "greenlet",
]
hiddenimports += collect_submodules("dns")
hiddenimports += collect_submodules("socketio")
hiddenimports += collect_submodules("engineio")

datas = [
    (os.path.join(ROOT, "templates"), "templates"),
    (os.path.join(ROOT, "static"), "static"),
    (os.path.join(ROOT, ".env.example"), "."),
]

binaries = []
for pkg in ("flask", "flask_socketio", "eventlet"):
    try:
        datas_pkg, binaries_pkg, hidden_pkg = collect_all(pkg)
        datas += datas_pkg
        binaries += binaries_pkg
        hiddenimports += hidden_pkg
    except Exception:
        pass

a = Analysis(
    [os.path.join(SPECPATH, "launcher.py")],
    pathex=[ROOT, SPECPATH],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["gunicorn", "pytest", "mypy", "IPython"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WPGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="WPGuard",
)
