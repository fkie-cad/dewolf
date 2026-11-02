"""Process pool for per-binary jobs.

Every expensive unit of work (fingerprinting, feature extraction, evaluation) is one *binary*:
opening a BinaryView is costly, so a job opens it once and handles all requested functions of
that binary, checkpointing per function (storage.FunctionCheckpoint).

Workers are started with the "spawn" context (BinaryNinja's native threads do not survive a
fork) and recycled after every job (``max_tasks=1``), so native memory a BinaryView leaks is
returned to the OS. Each worker gets an address-space limit, each job a wall-clock timeout.
"""

from __future__ import annotations

import multiprocessing
import resource
import traceback
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from typing import Any, Callable, List, Sequence, Tuple

import pebble
from pebble import ProcessExpired

from cvpipeline.logs import get_logger
from cvpipeline.storage import is_valid_json, partial_size

log = get_logger("workers")


@dataclass
class Job:
    """One unit of work. ``func(*args)`` must write ``output_path`` atomically when it finishes."""

    label: str
    output_path: str
    func: Callable[..., Any]
    args: Tuple[Any, ...]
    progress: int = field(default=-1, compare=False)

    def is_done(self) -> bool:
        return is_valid_json(self.output_path)


@dataclass(frozen=True)
class PoolSettings:
    workers: int = 4
    mem_limit_gb: float = 10.0
    job_timeout_s: float = 4 * 3600


def _set_memory_limit(limit_bytes: int) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def run_jobs(jobs: Sequence[Job], settings: PoolSettings, description: str) -> List[Job]:
    """Run all unfinished jobs; returns the jobs that are still unfinished afterwards.

    Resume logic: jobs whose output already exists are skipped. A job whose worker died
    (crash, OOM, timeout) is retried in a further round, but only as long as its checkpoint log
    grew since the previous attempt - a function that kills the worker repeatedly is eventually
    marked "crashed" by the checkpoint and skipped, so every round either finishes a binary or gets
    further, and the loop always terminates.
    """
    pending = [job for job in jobs if not job.is_done()]
    skipped = len(jobs) - len(pending)
    log.info(f"{description}: {len(jobs)} jobs, {skipped} already done, {len(pending)} to run")
    for job in pending:
        job.progress = partial_size(job.output_path)

    round_number = 1
    while pending:
        if round_number > 1:
            log.info(f"{description}: round {round_number}, resuming {len(pending)} killed jobs that made progress")
        _run_round(pending, settings, description)

        resumable = []
        for job in pending:
            if job.is_done():
                continue
            progress = partial_size(job.output_path)
            if progress > job.progress:
                job.progress = progress
                resumable.append(job)
            else:
                log.error(f"{description}: giving up on {job.label} (no progress since last attempt)")
        pending = resumable
        round_number += 1

    unfinished = [job for job in jobs if not job.is_done()]
    if unfinished:
        log.warning(f"{description}: {len(unfinished)} jobs did not finish, see logs/errors.log")
    return unfinished


def _run_round(jobs: Sequence[Job], settings: PoolSettings, description: str) -> None:
    context = multiprocessing.get_context("spawn")
    with pebble.ProcessPool(
        max_workers=settings.workers,
        max_tasks=1,
        initializer=_set_memory_limit,
        initargs=[int(settings.mem_limit_gb * 1024**3)],
        context=context,
    ) as pool:
        futures = [(job, pool.schedule(job.func, args=list(job.args), timeout=settings.job_timeout_s)) for job in jobs]
        for done, (job, future) in enumerate(futures, 1):
            try:
                future.result()
            except KeyboardInterrupt:
                pool.stop()
                log.warning("Interrupted. Rerun the same command to resume; finished work is kept.")
                raise
            except FutureTimeoutError:
                log.error(f"{description}: TIMEOUT after {settings.job_timeout_s}s: {job.label}")
            except ProcessExpired as error:
                log.error(f"{description}: worker died (exit code {error.exitcode}): {job.label}")
            except Exception:
                log.error(f"{description}: {job.label} raised:\n{traceback.format_exc()}")
            if done % 10 == 0 or done == len(futures):
                log.info(f"{description}: {done}/{len(futures)} jobs processed")
