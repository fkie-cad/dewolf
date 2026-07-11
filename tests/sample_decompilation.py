"""Shared helper for the sample-binary decompilation tests (both frontends).

``decompile.py`` used to be invoked ad-hoc and a crash was reported as a bare assertion failure --
you then had to re-run the sample by hand to find out *why* it failed. This helper runs the
decompiler with ``--debug`` (which re-raises the original exception instead of swallowing it into a
generic "Decompilation Failed!" line) and, on failure, returns a readable report containing the
failing stage, the exception, and the traceback tail -- so CI shows the actual error inline.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from decompiler.backend.codegenerator import FAIL_MESSAGE

CRASH_DIR = Path("crash_reports")

# dewolf logs this on a stage failure (see DecompilerTask.fail); it carries the real exception.
_FAIL_LINE = re.compile(r"^.*Failed to decompile .*$", re.MULTILINE)


def run_decompilation(sample, function_name: str, frontend: str | None = None) -> tuple[bool, str]:
    """Decompile ``function_name`` of ``sample`` in a subprocess.

    Returns ``(ok, detail)`` where ``ok`` is True on success and ``detail`` is a human-readable
    failure report (empty on success). ``frontend`` selects the disassembler frontend (None => the
    dewolf default, i.e. Binary Ninja if installed).
    """
    cmd = ["python", "decompile.py", str(sample), function_name, "--debug"]
    project_dir: str | None = None
    if frontend:
        cmd += ["--frontend", frontend]
        if frontend == "ghidra":
            # Give every decompilation its own throwaway Ghidra project. Ghidra names a project after
            # the binary, so distinct samples with the same file name (e.g. 64/0/test_loop and
            # 64/1/test_loop) would otherwise share one project directory and collide.
            project_dir = tempfile.mkdtemp(prefix="dewolf_ghidra_proj_")
            cmd += ["--ghidra-project-location", project_dir]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    finally:
        if project_dir:
            shutil.rmtree(project_dir, ignore_errors=True)
    failed = proc.returncode != 0 or FAIL_MESSAGE in proc.stdout
    return (not failed), (_failure_report(cmd, proc) if failed else "")


def _failure_report(cmd: list[str], proc: subprocess.CompletedProcess) -> str:
    """Build a compact, readable failure report from a completed decompile subprocess."""
    parts = [f"$ {' '.join(cmd)}", f"exit code: {proc.returncode}"]

    # the ERROR line dewolf logs names the failing stage and the exception
    if fail_lines := _FAIL_LINE.findall(proc.stderr):
        parts.append("error: " + fail_lines[-1].strip())

    # with --debug the original exception is re-raised, so stderr ends in the real traceback
    if stderr_tail := [line for line in proc.stderr.strip().splitlines() if line][-25:]:
        parts.append("--- traceback (tail) ---")
        parts.extend(stderr_tail)

    # fall back to the generic failure block from stdout if there was no traceback at all
    if FAIL_MESSAGE in proc.stdout and not proc.stderr.strip():
        parts.append(proc.stdout.split(FAIL_MESSAGE, 1)[1].strip())

    return "\n".join(parts)


def record_crash(sample, function_name: str) -> None:
    """Copy a crashing sample into ``crash_reports/`` (uploaded as a CI artifact)."""
    sample = Path(sample)
    if not sample.is_file():  # e.g. the sample was never compiled -- nothing to archive
        return
    CRASH_DIR.mkdir(exist_ok=True)
    output_file = CRASH_DIR / ("_".join(sample.parts[3:]) + "_" + function_name)
    shutil.copy(sample, output_file)
