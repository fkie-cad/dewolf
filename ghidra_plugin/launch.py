"""Launch the Ghidra GUI with the dewolf decompiler plugin installed and connected.

Usage (from the dewolf repository, inside its virtualenv):

    python -m ghidra_plugin [--install-dir /path/to/ghidra_XX.X_PUBLIC]

The Java plugin source in ghidra_plugin/java is compiled and installed as a Ghidra
extension by PyGhidra at launch time (re-compiled automatically whenever the Java
source changes), and a dewolf backend is registered before the GUI starts so the
"dewolf Decompiler" window can decompile in-process.

Both steps are the ``pyghidra.setup`` / ``pyghidra.pre_launch`` hooks in ``hooks.py`` (also used
via entry points when dewolf is installed as a package), so this launcher and an installed
``pyghidraRun`` behave identically.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from ghidra_plugin.hooks import REPO_ROOT, install_extension, register_backend


def _resolve_install_dir(cli_value: str | None) -> Path | None:
    if cli_value:
        return Path(cli_value)
    if env_value := os.environ.get("GHIDRA_INSTALL_DIR"):
        return Path(env_value)
    from decompiler.frontend.ghidra.frontend import GhidraFrontend

    detected = GhidraFrontend._autodetect_install_dir()
    return Path(detected) if detected else None


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m ghidra_plugin", description=__doc__.splitlines()[0])
    parser.add_argument(
        "--install-dir",
        dest="install_dir",
        default=None,
        help="Ghidra installation directory (defaults to $GHIDRA_INSTALL_DIR or auto-detection)",
    )
    args = parser.parse_args(argv)

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    from pyghidra.launcher import GuiPyGhidraLauncher

    class DewolfGuiLauncher(GuiPyGhidraLauncher):
        def _launch(self):
            # Runs after the JVM is up and the extension jar is on the class path,
            # right before the Swing GUI starts.
            register_backend()
            super()._launch()

    launcher = DewolfGuiLauncher(install_dir=_resolve_install_dir(args.install_dir))
    install_extension(launcher)
    launcher.start()


if __name__ == "__main__":
    main()
