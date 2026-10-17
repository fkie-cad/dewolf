import argparse
import json
import multiprocessing
import os
import resource
import traceback
from concurrent.futures import TimeoutError as FutureTimeoutError
from pathlib import Path

import pebble
from eval_dedup import build_exclusion_list
from pebble import ProcessExpired
from report_variable_matching import main

# Per-binary limit for one worker run. With per-function checkpointing this is no longer the time a
# binary may take in total: a binary killed at this limit is resumed in the next round.
TASK_TIMEOUT_SECONDS = 4320


def set_memory_limit(limit_bytes):
    """Wird von Pebble bei JEDEM Worker-Start aufgerufen (auch bei Neustarts)."""
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def discover_projects(binary_folder: str) -> list[str]:
    return sorted(d for d in os.listdir(binary_folder) if os.path.isdir(os.path.join(binary_folder, d)))


def is_valid_json(path: str) -> bool:
    """False for files a killed worker left half-written (truncated or empty)."""
    try:
        with open(path, "r") as f:
            json.load(f)
        return True
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return False


def partial_size(output_path: str) -> int:
    """Size of report_variable_matching's per-function checkpoint log; -1 if there is none."""
    path = output_path + ".partial"
    return os.path.getsize(path) if os.path.exists(path) else -1


def log_error(error_log_path: str, message: str) -> None:
    with open(error_log_path, "a") as error_log:
        error_log.write(message + "\n")


def remove_if_truncated(output_path: str) -> None:
    """Results written by older versions of (before the atomic write) can
    be cut off by a kill. Remove such a file so the binary gets rescheduled instead of skipped."""
    if os.path.exists(output_path) and not is_valid_json(output_path):
        os.remove(output_path)


def run_round(tasks: list[dict], max_workers: int, mem_limit_gb: float, error_log_path: str, stats: dict) -> bool:
    """Run one batch of tasks. Returns True if interrupted with Ctrl+C."""
    spawn_context = multiprocessing.get_context("spawn")
    with pebble.ProcessPool(
        max_workers=max_workers,
        max_tasks=1,
        initializer=set_memory_limit,
        initargs=(int(mem_limit_gb * 1024 * 1024 * 1024),),
        context=spawn_context,
    ) as pool:
        futures = [(task, pool.schedule(main, args=(task["argv"],), timeout=TASK_TIMEOUT_SECONDS)) for task in tasks]

        for done, (task, fut) in enumerate(futures, 1):
            try:
                fut.result()
            except KeyboardInterrupt:
                pool.stop()
                print("\n--- Interrupted. Rerun to resume; finished functions are kept. ---")
                return True
            except FutureTimeoutError:
                stats["timed_out"] += 1
                log_error(error_log_path, f"TIMEOUT after {TASK_TIMEOUT_SECONDS}s: {task['label']}")
                remove_if_truncated(task["output_path"])
            except ProcessExpired as e:
                stats["crashed"] += 1
                log_error(error_log_path, f"WORKER DIED (exit code {e.exitcode}): {task['label']}")
                remove_if_truncated(task["output_path"])
            except Exception:
                stats["raised"] += 1
                log_error(error_log_path, f"Task {task['label']} raised an exception: {traceback.format_exc()}")
                remove_if_truncated(task["output_path"])
            print(f"{done}/{len(futures)} tasks completed.\r", end="", flush=True)
    print()
    return False


def report_incomplete_binaries(binary_folder: str, output: str, projects: list[str], algos: list[str]) -> None:
    """plot_dwarf.py only compares binaries that every algorithm finished, so a binary missing
    for even one algorithm silently drops out of the comparison for all of them. List those
    binaries here so the loss is visible."""
    incomplete: dict[str, list[str]] = {}
    total = 0
    for project in projects:
        project_binary_folder = os.path.join(binary_folder, project)
        for file in sorted(os.listdir(project_binary_folder)):
            if not os.path.isfile(os.path.join(project_binary_folder, file)):
                continue
            total += 1
            missing = [algo for algo in algos if not os.path.exists(os.path.join(output, project, algo, file + ".json"))]
            if missing:
                incomplete[f"{project}/{file}"] = missing

    report_path = os.path.join(output, "incomplete_binaries.json")
    with open(report_path, "w") as f:
        json.dump(incomplete, f, indent=2)

    if incomplete:
        print(
            f"--- WARNING: {len(incomplete)}/{total} binaries have no result for at least one algorithm "
            f"and will be left out of the plots for ALL algorithms. Details: {report_path} ---"
        )
    else:
        print(f"--- All {total} binaries have results for every algorithm. ---")


def frankfurtAmMAIN():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binaryFolder", help="Path to the folder containing one subfolder per project", required=True)
    parser.add_argument("-o", "--output", help="Path to the output folder", required=True)
    parser.add_argument("--max-workers", "-m", default=4, type=int, help="Maximum number of worker processes")
    parser.add_argument("--mem-limit", "-l", default=8, type=float, help="Memory limit per worker in GB.")
    parser.add_argument("--ssa-algos", "-a", nargs="+", default=["conditional"], help="SSA elimination algorithms to evaluate")
    parser.add_argument(
        "--function-timeout",
        "-t",
        default=600,
        type=float,
        help="Per-function time limit in seconds; slower functions are recorded as 'timeout' and the binary continues.",
    )

    args = parser.parse_args()

    args.output = args.output.rstrip("/")  # Remove trailing slash if present
    args.binaryFolder = args.binaryFolder.rstrip("/")  # Remove trailing slash if present
    os.makedirs(args.output, exist_ok=True)
    error_log_path = os.path.join(args.output, "error_log.txt")

    projects = discover_projects(args.binaryFolder)
    print(f"--- Found {len(projects)} projects: {', '.join(projects)} ---")

    tasks: list[dict] = []
    for project in projects:
        project_binary_folder = os.path.join(args.binaryFolder, project)
        project_output = os.path.join(args.output, project)

        # intialize sturcture in the output folder
        for algo in args.ssa_algos:
            Path(project_output + "/" + algo).mkdir(parents=True, exist_ok=True)

        print(f"--- [{project}] Building exclusion list ---")
        exclusion = build_exclusion_list(project_binary_folder, error_log_path)
        exclusion_path = os.path.join(project_output, "exclusion.json")
        with open(exclusion_path, "w") as f:
            json.dump(exclusion, f, indent=2)

        print(f"--- [{project}] Start collecting tasks from {project_binary_folder} ---")
        rescheduled = 0
        for algo in args.ssa_algos:
            for file in os.listdir(project_binary_folder):
                input_path = project_binary_folder + "/" + file
                output_path = project_output + "/" + algo + "/" + file + ".json"
                if not os.path.isfile(input_path):
                    continue
                if os.path.exists(output_path):
                    if is_valid_json(output_path):
                        continue
                    # Left half-written by a worker killed in an earlier run: redo it.
                    os.remove(output_path)
                    rescheduled += 1
                tasks.append(
                    {
                        "label": f"{project}/{algo}/{file}",
                        "output_path": output_path,
                        "argv": [
                            input_path,
                            "",
                            output_path,
                            "--ssa-algo",
                            algo,
                            "--exclude-file",
                            exclusion_path,
                            "--function-timeout",
                            str(args.function_timeout),
                            "-q",
                        ],
                        "progress": partial_size(output_path),
                    }
                )
        if rescheduled:
            print(f"--- [{project}] {rescheduled} truncated result files from an earlier run removed and rescheduled. ---")

    print(f"--- Found {len(tasks)} tasks to process. ---")
    print(f"--- Start processing tasks with SSA algorithms: {', '.join(args.ssa_algos)} and {args.max_workers} workers. ---")

    # A binary whose worker gets killed (native crash, out of memory, per-binary timeout) keeps every
    # function it finished in its checkpoint log. Resume such binaries in further rounds as long as
    # each attempt made progress; report_variable_matching marks a function that kills the worker
    # twice as "crashed" and moves past it, so every round either finishes a binary or gets further.
    stats = {"timed_out": 0, "crashed": 0, "raised": 0}
    pending = tasks
    round_number = 1
    while pending:
        if round_number > 1:
            print(f"--- Round {round_number}: resuming {len(pending)} binaries that were killed but made progress. ---")
        if run_round(pending, args.max_workers, args.mem_limit, error_log_path, stats):
            break

        resumable = []
        for task in pending:
            if os.path.exists(task["output_path"]):
                continue
            progress = partial_size(task["output_path"])
            if progress > task["progress"]:
                task["progress"] = progress
                resumable.append(task)
        pending = resumable
        round_number += 1

    if any(stats.values()):
        print(
            f"--- {stats['timed_out']} worker timeouts, {stats['crashed']} worker crashes, {stats['raised']} raised exceptions "
            f"(counted per attempt). See {error_log_path}. ---"
        )

    report_incomplete_binaries(args.binaryFolder, args.output, projects, args.ssa_algos)


if __name__ == "__main__":
    frankfurtAmMAIN()
