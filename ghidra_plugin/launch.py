"""Launch the Ghidra GUI with the dewolf decompiler plugin installed and connected.

Usage (from the dewolf repository, inside its virtualenv):

    python -m ghidra_plugin [--install-dir /path/to/ghidra_XX.X_PUBLIC]

The Java plugin source in ghidra_plugin/java is compiled and installed as a Ghidra
extension by PyGhidra at launch time (re-compiled automatically whenever the Java
source changes), and a dewolf backend is registered before the GUI starts so the
"dewolf Decompiler" window can decompile in-process.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
JAVA_SRC = Path(__file__).resolve().parent / "java"

# Keep a reference to the JPype proxy so it cannot be garbage collected while the
# Java side still uses it.
_backend = None


def _plugin_version() -> str:
    """Hash the Java sources; a changed hash makes pyghidra reinstall the extension."""
    digest = hashlib.sha1()
    for source in sorted(JAVA_SRC.glob("**/*.java")):
        digest.update(source.read_bytes())
    return digest.hexdigest()[:12]


def _resolve_install_dir(cli_value: str | None) -> Path | None:
    if cli_value:
        return Path(cli_value)
    if env_value := os.environ.get("GHIDRA_INSTALL_DIR"):
        return Path(env_value)
    from decompiler.frontend.ghidra.frontend import GhidraFrontend

    detected = GhidraFrontend._autodetect_install_dir()
    return Path(detected) if detected else None


def _register_backend() -> None:
    global _backend
    # pyghidra removes the current working directory from sys.path when starting the
    # JVM, which strips the repo root when launching from inside the repository —
    # re-add it so dewolf stays importable.
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    from ghidra_plugin.backend import DewolfPythonBackend
    from jpype import JClass

    _backend = DewolfPythonBackend()
    JClass("dewolfghidra.DewolfBackendRegistry").setBackend(_backend)


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

    import pyghidra
    from pyghidra.launcher import GuiPyGhidraLauncher

    class DewolfGuiLauncher(GuiPyGhidraLauncher):
        def _launch(self):
            # Runs after the JVM is up and the extension jar is on the class path,
            # right before the Swing GUI starts.
            _register_backend()
            super()._launch()

    launcher = DewolfGuiLauncher(install_dir=_resolve_install_dir(args.install_dir))
    launcher.install_plugin(
        JAVA_SRC,
        pyghidra.ExtensionDetails(
            name="dewolf",
            description="dewolf decompiler window for Ghidra",
            author="dewolf",
            plugin_version=_plugin_version(),
        ),
    )
    launcher.start()


if __name__ == "__main__":
    main()
