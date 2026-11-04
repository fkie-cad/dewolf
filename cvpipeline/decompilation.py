"""Running the dewolf pipeline up to out-of-SSA for selected functions of one binary.

Only used inside worker processes. Nothing in ``decompiler/`` is modified: weights are injected by
replacing a module-level name (see ``install_conditional_weights``), and the BinaryView is closed
by reaching into the frontend's ``_bv`` from here.
"""

from __future__ import annotations

import functools
import logging
import signal
import threading
import traceback
from contextlib import contextmanager
from typing import Any, Callable, Dict, Generator, Iterable

import decompiler.pipeline.ssa.outofssatranslation as out_of_ssa_module
from decompiler.frontend.binaryninja.frontend import BinaryninjaFrontend
from decompiler.pipeline.default import CFG_STAGES
from decompiler.pipeline.pipeline import PREPROCESSING_STAGES, DecompilerPipeline
from decompiler.pipeline.ssa.conditional_out_of_SSA import ConditionalOutOfSSA
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

from cvpipeline import config
from cvpipeline.logs import append_worker_error
from cvpipeline.storage import FunctionCheckpoint, write_json_atomic

# Captured at import, so repeated installs inside one process never wrap a partial in a partial.
_ORIGINAL_CONDITIONAL_OUT_OF_SSA = ConditionalOutOfSSA

# Statuses a function entry can have. "success" means the analysis callback produced a result.
SUCCESS = "success"
FAILED = "failed"  # the dewolf pipeline marked the task failed at some stage
DECOMPILATION_ERROR = "decompilation-error"  # the pipeline raised
ANALYSIS_ERROR = "analysis-error"  # the callback raised on a successfully decompiled task
TIMEOUT = "timeout"
CRASHED = "crashed"  # killed the worker process FunctionCheckpoint.MAX_ATTEMPTS times

# analyze(name, task) -> JSON-serializable result for a successfully decompiled function
Analyzer = Callable[[str, DecompilerTask], Any]


def install_conditional_weights(coefficients: list[float], intercept: float, strategy: int) -> None:
    """Make every ConditionalOutOfSSA created in this process use the given weights and
    variable-class strategy (ConditionalVariableRenamer.create_variable_classes).

    OutOfSsaTranslation._conditional_out_of_ssa looks ``ConditionalOutOfSSA`` up in its module's
    globals at call time, so rebinding that module attribute to a partial with fixed keyword
    arguments overrides the hard-coded defaults in conditional_out_of_SSA.py without editing it.
    """
    out_of_ssa_module.ConditionalOutOfSSA = functools.partial(
        _ORIGINAL_CONDITIONAL_OUT_OF_SSA, parms=list(coefficients), intercept=float(intercept), strategy=int(strategy)
    )


def make_options(out_of_ssa_mode: str) -> Options:
    """Default dewolf options with the given out-of-SSA mode, loading binaries without Binary Ninja's
    debug-info import (config.BN_LOAD_OPTIONS)."""
    options = Options.load_default_options()
    options.update(
        {
            "out-of-ssa-translation.mode": out_of_ssa_mode,
            "binaryninja.use_debug_info": config.BN_LOAD_OPTIONS["analysis.debugInfo.internal"],
        }
    )
    return options


def build_pipeline(options: Options) -> DecompilerPipeline:
    """Preprocessing + the CFG stages selected by ``pipeline.cfg_stages`` (same selection and
    order as decompile.py) + out-of-SSA. The restructuring/AST stages run after out-of-SSA and do
    not influence it, so they are skipped."""
    stage_by_name = {stage.name: stage for stage in CFG_STAGES}
    cfg_stages = [stage_by_name[name] for name in options.getlist("pipeline.cfg_stages") if name in stage_by_name]
    return DecompilerPipeline(PREPROCESSING_STAGES.copy() + cfg_stages + [OutOfSsaTranslation])


class FunctionTimeout(BaseException):
    """Raised by the per-function alarm. A BaseException so that dewolf's ``except Exception``
    handlers cannot swallow it and misreport a timeout as a stage failure."""


@contextmanager
def time_limit(seconds: float | None) -> Generator[None, None, None]:
    """Raise FunctionTimeout after ``seconds`` (None/0: no limit). SIGALRM-based, so it only works
    in the main thread - true for pool workers. A stage stuck in native code is only interrupted
    once it returns to Python; the per-binary job timeout is the backstop for that."""
    if not seconds or threading.current_thread() is not threading.main_thread():
        yield
        return

    def _raise_timeout(_signum, _frame):
        raise FunctionTimeout()

    previous = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@contextmanager
def open_frontend(binary_path: str, options: Options) -> Generator[BinaryninjaFrontend, None, None]:
    """Open a binary and always close its BinaryView again (it otherwise leaks native memory)."""
    frontend = BinaryninjaFrontend.from_path(binary_path, options)
    try:
        yield frontend
    finally:
        frontend._bv.file.close()


def _entry(status: str, message: str | None = None, result: Any = None) -> Dict[str, Any]:
    return {"status": status, "message": message, "result": result}


def _analyze_one(
    name: str,
    frontend: BinaryninjaFrontend,
    options: Options,
    analyze: Analyzer,
    timeout_s: float | None,
    prepare: Callable[[str], None] | None,
) -> Dict[str, Any]:
    """Decompile one function and hand the finished task to ``analyze``. Never raises for a
    function-level problem; every outcome becomes a status."""
    try:
        with time_limit(timeout_s):
            if prepare is not None:
                prepare(name)
            task = DecompilerTask(name, name, options)
            try:
                frontend.lift(task)
                build_pipeline(options).run(task)
            except Exception as error:  # includes MemoryError from the worker's address-space limit
                return _entry(DECOMPILATION_ERROR, f"{type(error).__name__}: {error}")
            if task.failed:
                return _entry(FAILED, f"failed at stage {task.failure_origin}")
            try:
                return _entry(SUCCESS, result=analyze(name, task))
            except Exception as error:
                return _entry(ANALYSIS_ERROR, f"{type(error).__name__}: {error}")
    except FunctionTimeout:
        return _entry(TIMEOUT, f"exceeded {timeout_s}s")


def process_binary(
    binary_path: str,
    functions: Iterable[str],
    output_path: str,
    options: Options,
    analyze: Analyzer,
    timeout_s: float | None,
    error_log: str,
    metadata: Dict[str, Any],
    prepare: Callable[[str], None] | None = None,
) -> None:
    """Analyze ``functions`` of one binary and write ``{**metadata, "functions": {name: entry}}``.

    ``prepare(name)`` runs right before a function is decompiled (e.g. to point a pipeline stage
    at a per-function output file). Progress is checkpointed per function, so a rerun after a
    kill continues where it stopped (see storage.FunctionCheckpoint). The final JSON is written
    atomically.
    """
    logging.getLogger().setLevel(logging.ERROR)  # dewolf stages log a lot of noise at WARNING
    wanted = sorted(set(functions))
    checkpoint = FunctionCheckpoint(output_path)
    try:
        with open_frontend(binary_path, options) as frontend:
            available = set(frontend.get_all_function_names())
            for name in wanted:
                if name in checkpoint.done:
                    continue
                if name not in available:
                    checkpoint.finish(name, _entry(DECOMPILATION_ERROR, "function not found in binary"))
                    continue
                if checkpoint.killed_too_often(name):
                    message = f"killed the worker {checkpoint.attempts[name]} times; skipped"
                    append_worker_error(error_log, f"{binary_path}::{name}: {message}")
                    checkpoint.finish(name, _entry(CRASHED, message))
                    continue
                checkpoint.start(name)
                entry = _analyze_one(name, frontend, options, analyze, timeout_s, prepare)
                if entry["status"] != SUCCESS:
                    append_worker_error(error_log, f"{binary_path}::{name}: {entry['status']}: {entry['message']}")
                checkpoint.finish(name, entry)
    except Exception:
        # e.g. the binary cannot be loaded at all: record it for every function so the binary
        # counts as finished instead of being retried forever.
        message = traceback.format_exc()
        append_worker_error(error_log, f"{binary_path}: {message}")
        for name in wanted:
            if name not in checkpoint.done:
                checkpoint.finish(name, _entry(DECOMPILATION_ERROR, f"binary could not be processed: {message.splitlines()[-1]}"))

    write_json_atomic(output_path, {**metadata, "functions": {name: checkpoint.done[name] for name in wanted}})
    checkpoint.close_and_remove()
