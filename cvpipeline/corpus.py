"""Reading the project folder, fingerprinting every function and deduplicating across projects.

Folder layout (unchanged from the legacy scripts): ``<projects>/<project>/<binary>``, every file
directly inside a project folder is an ELF binary with DWARF info.

Functions are identified throughout the pipeline by a ``FunctionKey`` string
``"<project>/<binary>::<function>"``.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from cvpipeline.config import BN_LOAD_OPTIONS
from cvpipeline.logs import append_worker_error, get_logger
from cvpipeline.storage import read_json, write_json_atomic
from cvpipeline.workers import Job, PoolSettings, run_jobs

log = get_logger("corpus")

FunctionKey = str


def make_key(project: str, binary: str, function: str) -> FunctionKey:
    return f"{project}/{binary}::{function}"


def parse_key(key: FunctionKey) -> Tuple[str, str, str]:
    """Inverse of make_key -> (project, binary, function). Function names may contain "::"
    (C++), project and binary names never contain "/" or "::"."""
    location, function = key.split("::", 1)
    project, binary = location.split("/", 1)
    return project, binary, function


def discover_projects(projects_dir: str | Path) -> List[str]:
    root = Path(projects_dir)
    projects = sorted(entry.name for entry in root.iterdir() if entry.is_dir())
    if not projects:
        raise ValueError(f"No project subfolders found in {root}")
    return projects


def list_binaries(projects_dir: str | Path, project: str) -> List[str]:
    folder = Path(projects_dir) / project
    return sorted(entry.name for entry in folder.iterdir() if entry.is_file())


# --------------------------------------------------------------------------------------------- #
# Fingerprinting (one worker job per binary, result cached per binary)
# --------------------------------------------------------------------------------------------- #


def fingerprint_binary(binary_path: str, output_path: str, error_log: str) -> None:
    """Worker: write ``{"functions": {name: fingerprint | null}, "load_error": str | null}``.

    A function whose fingerprint cannot be computed (e.g. BinaryNinja produced no MLIL for it)
    gets ``null``; it is then always kept, never deduplicated.
    """
    import binaryninja
    from decompiler.util.function_corpus import is_enumerable_function
    from decompiler.util.function_fingerprint_mlil import function_fingerprint

    fingerprints: Dict[str, Optional[str]] = {}
    load_error = None
    try:
        bv = binaryninja.load(binary_path, options=dict(BN_LOAD_OPTIONS))
    except Exception:
        bv = None
    if bv is None:
        load_error = "not a loadable binary"
        append_worker_error(error_log, f"fingerprinting {binary_path}: {load_error}")
    else:
        try:
            for function in bv.functions:
                if not is_enumerable_function(function):
                    continue
                try:
                    fingerprints[function.name] = function_fingerprint(function)
                except Exception:
                    fingerprints[function.name] = None
                    append_worker_error(error_log, f"fingerprinting {binary_path}::{function.name}: {traceback.format_exc()}")
        finally:
            bv.file.close()
    write_json_atomic(output_path, {"functions": fingerprints, "load_error": load_error})


def fingerprint_path(work_dir: Path, project: str, binary: str) -> Path:
    return work_dir / "fingerprints" / project / f"{binary}.json"


def fingerprint_corpus(projects_dir: Path, work_dir: Path, settings: PoolSettings, error_log: str) -> Dict[str, Dict[str, dict]]:
    """Fingerprint every binary (cached per binary) and return {project: {binary: result}}.
    Binaries whose job never finished are left out with an error in the log."""
    projects = discover_projects(projects_dir)
    jobs = []
    for project in projects:
        for binary in list_binaries(projects_dir, project):
            output = fingerprint_path(work_dir, project, binary)
            jobs.append(
                Job(
                    label=f"{project}/{binary}",
                    output_path=str(output),
                    func=fingerprint_binary,
                    args=(str(projects_dir / project / binary), str(output), error_log),
                )
            )
    run_jobs(jobs, settings, "fingerprinting")

    results: Dict[str, Dict[str, dict]] = {project: {} for project in projects}
    for project in projects:
        for binary in list_binaries(projects_dir, project):
            path = fingerprint_path(work_dir, project, binary)
            if not path.exists():
                log.error(f"no fingerprints for {project}/{binary}; the binary is left out")
                continue
            result = read_json(path)
            if result["load_error"] is None:
                results[project][binary] = result["functions"]
    return results


# --------------------------------------------------------------------------------------------- #
# Deduplication (pure, testable without BinaryNinja)
# --------------------------------------------------------------------------------------------- #


@dataclass
class DedupResult:
    kept: List[FunctionKey]  # sorted
    excluded: Dict[FunctionKey, FunctionKey]  # duplicate -> the kept representative
    unfingerprinted: int  # kept functions that had no fingerprint

    def to_json(self) -> dict:
        return {"kept": self.kept, "excluded": self.excluded, "unfingerprinted": self.unfingerprinted}

    @classmethod
    def from_json(cls, data: dict) -> "DedupResult":
        return cls(kept=data["kept"], excluded=data["excluded"], unfingerprinted=data["unfingerprinted"])


def deduplicate(fingerprints: Dict[str, Dict[str, Dict[str, Optional[str]]]]) -> DedupResult:
    """One representative per fingerprint across the whole corpus.

    Projects are processed in sorted order, binaries and functions sorted as well; the first
    function seen with a fingerprint is kept, every later one is excluded as its duplicate. This
    matches the legacy semantics: a fingerprint claimed by an earlier project is never kept again
    in a later one (otherwise identical code shared by two projects could land in the training
    blocks *and* the holdout blocks), and within a project the alphabetically first member wins.
    Functions without a fingerprint are always kept.
    """
    representative: Dict[str, FunctionKey] = {}
    kept: List[FunctionKey] = []
    excluded: Dict[FunctionKey, FunctionKey] = {}
    unfingerprinted = 0
    for project in sorted(fingerprints):
        for binary in sorted(fingerprints[project]):
            for function, fingerprint in sorted(fingerprints[project][binary].items()):
                key = make_key(project, binary, function)
                if fingerprint is None:
                    unfingerprinted += 1
                    kept.append(key)
                elif fingerprint in representative:
                    excluded[key] = representative[fingerprint]
                else:
                    representative[fingerprint] = key
                    kept.append(key)
    return DedupResult(kept=sorted(kept), excluded=excluded, unfingerprinted=unfingerprinted)


def load_or_deduplicate(projects_dir: Path, work_dir: Path, settings: PoolSettings, error_log: str) -> DedupResult:
    """Cached in ``<work>/dedup.json``; recomputed only if that file is missing."""
    dedup_path = work_dir / "dedup.json"
    if dedup_path.exists():
        log.info(f"reusing {dedup_path}")
        return DedupResult.from_json(read_json(dedup_path))
    result = deduplicate(fingerprint_corpus(projects_dir, work_dir, settings, error_log))
    log.info(
        f"deduplication: {len(result.kept)} functions kept, {len(result.excluded)} duplicates excluded, "
        f"{result.unfingerprinted} kept without fingerprint"
    )
    write_json_atomic(dedup_path, result.to_json())
    return result


def group_by_binary(keys: Iterable[FunctionKey]) -> Dict[Tuple[str, str], List[str]]:
    """{(project, binary): [function, ...]} with sorted function lists."""
    grouped: Dict[Tuple[str, str], List[str]] = {}
    for key in keys:
        project, binary, function = parse_key(key)
        grouped.setdefault((project, binary), []).append(function)
    return {location: sorted(functions) for location, functions in sorted(grouped.items())}
