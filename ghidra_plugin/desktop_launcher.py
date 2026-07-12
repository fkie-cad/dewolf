"""Create a double-clickable desktop launcher for the dewolf Ghidra window.

``dewolf-install-launcher`` (run once after ``pip install``) writes an OS-native launcher that starts
Ghidra-with-dewolf through the ``dewolf-ghidra`` entry point -- so the user opens it from a normal
desktop icon instead of a terminal. The launcher runs the same interpreter dewolf is installed in.

Because GUI launches don't inherit a shell environment, we bake an absolute launch command and,
when available, ``GHIDRA_INSTALL_DIR`` into the launcher (otherwise dewolf autodetects it at runtime).
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

_INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>dewolf</string>
    <key>CFBundleDisplayName</key><string>dewolf for Ghidra</string>
    <key>CFBundleIdentifier</key><string>de.fkie.dewolf.ghidra</string>
    <key>CFBundleExecutable</key><string>dewolf</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>1.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
</dict>
</plist>
"""


def _launcher_command() -> list[str]:
    """The command that starts Ghidra-with-dewolf, preferring the installed console script."""
    bindir = Path(sys.executable).parent  # venv bin/Scripts, where console scripts live
    candidates = [shutil.which("dewolf-ghidra"), bindir / "dewolf-ghidra", bindir / "dewolf-ghidra.exe"]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return [str(candidate)]
    # Fall back to the module entry with the current interpreter (same environment either way).
    return [sys.executable, "-m", "ghidra_plugin"]


def _quote(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def _install_macos(command: list[str], ghidra_install_dir: str | None) -> Path:
    app = Path.home() / "Applications" / "dewolf.app"
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True, exist_ok=True)
    export = f"export GHIDRA_INSTALL_DIR={shlex.quote(ghidra_install_dir)}\n" if ghidra_install_dir else ""
    stub = macos / "dewolf"
    stub.write_text(f'#!/bin/bash\n{export}exec {_quote(command)} "$@"\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    (app / "Contents" / "Info.plist").write_text(_INFO_PLIST)
    return app


def _install_linux(command: list[str], ghidra_install_dir: str | None) -> Path:
    apps = Path.home() / ".local" / "share" / "applications"
    apps.mkdir(parents=True, exist_ok=True)
    exec_parts = ["env", f"GHIDRA_INSTALL_DIR={ghidra_install_dir}", *command] if ghidra_install_dir else command
    desktop = apps / "dewolf-ghidra.desktop"
    desktop.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=dewolf for Ghidra\n"
        "Comment=Open Ghidra with the dewolf decompiler window\n"
        f"Exec={_quote(exec_parts)}\n"
        "Terminal=false\n"
        "Categories=Development;\n"
    )
    desktop.chmod(desktop.stat().st_mode | stat.S_IEXEC)
    return desktop


def _ps_quote(value: str) -> str:
    """Quote a string as a PowerShell single-quoted literal."""
    return "'" + value.replace("'", "''") + "'"


def _install_windows(command: list[str], ghidra_install_dir: str | None) -> Path:
    lnk = Path.home() / "Desktop" / "dewolf for Ghidra.lnk"
    target, arguments = command[0], _quote(command[1:])
    # A .lnk can't set environment variables and can't hold multiple arguments cleanly, so when we
    # need either, point the shortcut at a small generated .cmd wrapper instead.
    if ghidra_install_dir or len(command) > 1:
        wrapper_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "dewolf"
        wrapper_dir.mkdir(parents=True, exist_ok=True)
        wrapper = wrapper_dir / "dewolf-ghidra.cmd"
        lines = ["@echo off"]
        if ghidra_install_dir:
            lines.append(f'set "GHIDRA_INSTALL_DIR={ghidra_install_dir}"')
        lines.append(" ".join(f'"{part}"' for part in command) + " %*")
        wrapper.write_text("\r\n".join(lines) + "\r\n")
        target, arguments = str(wrapper), ""
    script = (
        f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut({_ps_quote(str(lnk))});"
        f"$s.TargetPath={_ps_quote(target)};$s.Arguments={_ps_quote(arguments)};$s.Save()"
    )
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], check=True)
    return lnk


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="dewolf-install-launcher", description=__doc__.splitlines()[0])
    parser.add_argument(
        "--ghidra-install-dir",
        default=os.environ.get("GHIDRA_INSTALL_DIR"),
        help="Bake this GHIDRA_INSTALL_DIR into the launcher (default: $GHIDRA_INSTALL_DIR, else autodetect at launch)",
    )
    args = parser.parse_args(argv)

    command = _launcher_command()
    installers = {"darwin": _install_macos, "win32": _install_windows, "cygwin": _install_windows}
    installer = installers.get(sys.platform, _install_linux if sys.platform.startswith("linux") else None)
    if installer is None:
        raise SystemExit(f"unsupported platform: {sys.platform}")

    path = installer(command, args.ghidra_install_dir)
    print(f"Installed dewolf launcher: {path}")
    print(f"  runs: {' '.join(command)}")
    print(f"  GHIDRA_INSTALL_DIR: {args.ghidra_install_dir or 'autodetected at launch'}")


if __name__ == "__main__":
    main()
