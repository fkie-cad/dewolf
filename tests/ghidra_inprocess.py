"""In-process Ghidra decompilation for the sample tests.

The Ghidra frontend starts a JVM *in this process*. Spawning ``decompile.py`` as a subprocess per
function (as the Binary Ninja sample tests do) is unreliable on CI: a fresh process re-initialises
pyghidra, and pyghidra's import hook recurses infinitely (``_GhidraBundleFinder.find_spec`` imports
``ghidra.framework`` on every lookup) if the JVM does not come up cleanly. Lifting in-process avoids
that entirely, and is much faster -- a single JVM, each binary analysed once and reused across its
functions.

A binary is analysed lazily and cached; when the next function belongs to a different binary the
previous program is closed (the test ids are sorted, so a binary's functions run consecutively and
only one program is open at a time).
"""

from __future__ import annotations

import tempfile
import traceback

CRASH_MARKER = "Decompilation Failed"

_current: dict = {"sample": None, "decompiler": None}


def _close_current() -> None:
    decompiler = _current["decompiler"]
    if decompiler is not None:
        frontend = getattr(decompiler, "_frontend", None)
        if frontend is not None and hasattr(frontend, "close"):
            try:
                frontend.close()
            except Exception:  # noqa: BLE001 -- best-effort teardown
                pass
    _current["sample"] = None
    _current["decompiler"] = None


def _decompiler_for(sample: str):
    """Return a Ghidra-backed decompiler for ``sample``, analysing (and caching) it on first use."""
    from decompile import Decompiler

    if _current["sample"] != sample:
        _close_current()
        options = Decompiler.create_options()
        options.set("pipeline.debug", True)  # re-raise the original stage exception so we can report it
        options.set("ghidra.project_location", tempfile.mkdtemp(prefix="dewolf_ghidra_proj_"))
        _current["decompiler"] = Decompiler.from_path(sample, options=options, frontend="ghidra")
        _current["sample"] = sample
    return _current["decompiler"]


def decompile_ghidra(sample, function_name: str) -> tuple[bool, str]:
    """Decompile ``function_name`` of ``sample`` in-process via the Ghidra frontend.

    Returns ``(ok, detail)`` where ``detail`` is a readable failure report (empty on success).
    """
    sample = str(sample)
    try:
        task, code = _decompiler_for(sample).decompile(function_name)
    except Exception:  # noqa: BLE001 -- report any lift/pipeline error as a test failure
        return False, f"{sample}::{function_name}\n{traceback.format_exc()}"
    if getattr(task, "failed", False):
        return False, f"{sample}::{function_name} failed during stage: {task.failure_origin}"
    if CRASH_MARKER in code:
        return False, f"{sample}::{function_name}\n{code}"
    return True, ""


def close_ghidra_decompilers() -> None:
    """Release the open Ghidra program/JVM resources (call at session teardown)."""
    _close_current()
