"""Detect whether the Ghidra frontend can actually run in this environment.

Used to skip the Ghidra end-to-end / plugin tests (rather than error) when ``pyghidra`` is not
installed or no Ghidra installation can be located -- e.g. in the Binary Ninja CI image or on a
developer machine without Ghidra. Importing this module never imports ``pyghidra`` or starts a JVM.
"""

from __future__ import annotations

import importlib.util
import os
from functools import lru_cache
from typing import Optional


@lru_cache(maxsize=1)
def ghidra_unavailable_reason() -> Optional[str]:
    """Return a human-readable reason the Ghidra frontend is unavailable, or ``None`` if it is available."""
    if importlib.util.find_spec("pyghidra") is None:
        return "pyghidra is not installed"

    if os.environ.get("GHIDRA_INSTALL_DIR"):
        return None

    # fall back to the frontend's own autodetection (common install locations)
    try:
        from decompiler.frontend.ghidra.frontend import GhidraFrontend

        if GhidraFrontend._autodetect_install_dir():
            return None
    except Exception:  # noqa: BLE001 -- any import/detection failure just means "unavailable"
        pass
    return "no Ghidra installation found (set GHIDRA_INSTALL_DIR)"
