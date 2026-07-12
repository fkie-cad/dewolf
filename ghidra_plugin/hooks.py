"""pyghidra entry-point hooks that activate the dewolf Ghidra plugin.

These are registered under the ``pyghidra.setup`` and ``pyghidra.pre_launch`` entry-point groups
(see ``pyproject.toml``), so launching Ghidra through pyghidra -- via the shipped ``dewolf-ghidra``
launcher or Ghidra's own ``pyghidraRun`` -- installs the Java extension and connects the dewolf
backend automatically. ``launch.py`` calls the same two functions directly, so a source checkout
(where the entry points are not installed) behaves identically.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
JAVA_SRC = Path(__file__).resolve().parent / "java"

# Keep a reference to the JPype proxy so it cannot be garbage collected while the Java side uses it.
_backend = None


def plugin_version() -> str:
    """Hash the Java sources; a changed hash makes pyghidra reinstall the extension."""
    digest = hashlib.sha1()
    for source in sorted(JAVA_SRC.glob("**/*.java")):
        digest.update(source.read_bytes())
    return digest.hexdigest()[:12]


def install_extension(launcher) -> None:
    """``pyghidra.setup`` hook: queue the dewolf Ghidra extension for compilation and install.

    Runs before the JVM starts (pyghidra passes the launcher). pyghidra compiles the Java under
    ``java/`` and installs it as the ``dewolf`` extension, reinstalling whenever the source hash
    (``plugin_version``) changes.
    """
    from pyghidra import ExtensionDetails

    launcher.install_plugin(
        JAVA_SRC,
        ExtensionDetails(
            name="dewolf",
            description="dewolf decompiler window for Ghidra",
            author="dewolf",
            plugin_version=plugin_version(),
        ),
    )


def register_backend() -> None:
    """``pyghidra.pre_launch`` hook: connect the Python dewolf backend to the Java plugin.

    Runs after the JVM and Ghidra are initialized. Registers a ``DewolfPythonBackend`` in the
    Java-side ``DewolfBackendRegistry`` so the "dewolf Decompiler" window can decompile in-process.
    """
    global _backend
    # pyghidra removes the current working directory from sys.path when starting the JVM, which
    # strips the repo root when launching from inside a source checkout -- re-add it so dewolf imports.
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    from ghidra_plugin.backend import DewolfPythonBackend
    from jpype import JClass

    _backend = DewolfPythonBackend()
    JClass("dewolfghidra.DewolfBackendRegistry").setBackend(_backend)
