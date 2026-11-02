"""Crash-safe file I/O.

Every result the pipeline produces is written atomically (temp file + ``os.replace``), so a file
either exists complete or not at all. Resume logic therefore only has to ask "does a valid file
exist?" to know whether a unit of work is finished.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict


def write_json_atomic(path: str | Path, data: Any) -> None:
    """Write ``data`` as JSON to ``path`` so that a kill mid-write never leaves a truncated file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp_path, path)


def write_text_atomic(path: str | Path, text: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(text)
    os.replace(tmp_path, path)


def read_json(path: str | Path) -> Any:
    with open(path, "r") as f:
        return json.load(f)


def is_valid_json(path: str | Path) -> bool:
    """True if ``path`` exists and parses. Files from older or interrupted runs that are cut off
    count as missing, so the work that produced them is simply redone."""
    try:
        read_json(path)
        return True
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False


class FunctionCheckpoint:
    """Append-only JSON-lines log (``<output>.partial``) of per-function progress inside one binary.

    Resume logic: before a function is analyzed a "start" record is written, afterwards a "done"
    record carrying its result; both are flushed immediately. When a worker dies (native crash,
    out of memory, per-binary timeout) and the binary is rerun, every "done" function is reused.
    A function that was started but never finished is retried once - it may simply have been
    running when the binary timeout hit. If it was started ``MAX_ATTEMPTS`` times without
    finishing, it evidently kills the worker and is recorded as "crashed" instead of being retried
    forever. The log is deleted once the binary's final JSON has been written.
    """

    MAX_ATTEMPTS = 2

    def __init__(self, output_path: str | Path) -> None:
        self.path = Path(str(output_path) + ".partial")
        self.done: Dict[str, Dict[str, Any]] = {}
        self.attempts: DefaultDict[str, int] = defaultdict(int)
        needs_newline = False
        if self.path.exists():
            content = self.path.read_text()
            needs_newline = bool(content) and not content.endswith("\n")
            for line in content.splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue  # the last line may have been cut off by the kill
                if record.get("event") == "start":
                    self.attempts[record["name"]] += 1
                elif record.get("event") == "done":
                    self.done[record["name"]] = record["entry"]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.path, "a")
        if needs_newline:
            self._file.write("\n")

    def killed_too_often(self, name: str) -> bool:
        return name not in self.done and self.attempts[name] >= self.MAX_ATTEMPTS

    def start(self, name: str) -> None:
        self.attempts[name] += 1
        self._write({"event": "start", "name": name})

    def finish(self, name: str, entry: Dict[str, Any]) -> None:
        self.done[name] = entry
        self._write({"event": "done", "name": name, "entry": entry})

    def close(self) -> None:
        self._file.close()

    def close_and_remove(self) -> None:
        self._file.close()
        self.path.unlink(missing_ok=True)

    def _write(self, record: Dict[str, Any]) -> None:
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()


def partial_size(output_path: str | Path) -> int:
    """Size of a binary's checkpoint log, -1 if there is none. Used to detect whether a killed
    binary made progress since the last attempt (see workers.run_jobs)."""
    path = Path(str(output_path) + ".partial")
    return path.stat().st_size if path.exists() else -1
