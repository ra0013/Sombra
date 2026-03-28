# sombra.spec
# PyInstaller build specification for Sombra
#
# Usage:
#   pip install pyinstaller
#   pyinstaller sombra.spec
#
# Output: dist/sombra.exe (Windows) or dist/sombra (Linux)
#
# After building, hash the output and record in release notes:
#   Windows: Get-FileHash dist\sombra.exe -Algorithm SHA256
#   Linux:   sha256sum dist/sombra

import sys
from pathlib import Path

block_cipher = None

# Include profile JSON files as data
profiles_dir = Path('profiles')
profile_data = [
    (str(f), 'profiles')
    for f in profiles_dir.glob('*.json')
]

a = Analysis(
    ['sombra.py'],
    pathex=['.'],
    binaries=[],
    datas=profile_data,
    hiddenimports=[
        'rich',
        'rich.console',
        'rich.panel',
        'rich.table',
        'rich.text',
        'rich.box',
        'psutil',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='sombra',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,       # Keep console — Sombra is a terminal tool
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Icon — replace with your own .ico if desired
    # icon='assets/sombra.ico',
)
