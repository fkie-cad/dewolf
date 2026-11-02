#!/usr/bin/env python3
import argparse
import multiprocessing
import os
import resource
import traceback

import pebble
from decompiler.frontend.binaryninja.frontend import BinaryninjaFrontend
from decompiler.util.options import Options
from pebble import ProcessFuture
from report_variable_matching import OutOfSsaDecompiler


def set_memory_limit(limit_bytes):
    """Called by Pebble on EVERY worker start (also on restarts)."""
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def workerFunction(binary_path: str, function_name: str, inter_path: str, dep_path: str, error_log_path: str) -> None:
    """Decompiles a single function in 'cond-export' mode. The decompiler
    itself pickles the resulting graphs to the paths in ConditionalInterPath and ConditionalDepPath."""

    os.environ["ConditionalInterPath"] = str(inter_path)
    os.environ["ConditionalDepPath"] = str(dep_path)

    options = Options.load_default_options()
    options.update({"out-of-ssa-translation.mode": "cond-export"})
    frontend = BinaryninjaFrontend.from_path(binary_path, options)
    try:
        decompiler = OutOfSsaDecompiler(frontend, options)

        try:
            decompiler.run(function_name)
        except Exception as e:
            message = f"decompiling {binary_path}::{function_name} raised {traceback.format_exc()}: {e}"
            with open(error_log_path, "a") as error_log:
                error_log.write(message + "\n")
    finally:
        frontend._bv.file.close()


def collect_tasks(binary_folder: str, output_folder: str, error_log_path: str) -> list:
    """Builds one task per function per binary. Each task writes its pickled
    graphs to <output_folder>/inter/<binary>/<function>.pkl and <output_folder>/dep/<binary>/<function>.pkl"""

    tasks = []

    inter_folder = os.path.join(output_folder, "inter")
    dep_folder = os.path.join(output_folder, "dep")

    for file in os.listdir(binary_folder):
        input_path = os.path.join(binary_folder, file)

        binary_inter_folder = os.path.join(inter_folder, file)
        binary_dep_folder = os.path.join(dep_folder, file)

        # Create target directories if they do not exist
        os.makedirs(binary_inter_folder, exist_ok=True)
        os.makedirs(binary_dep_folder, exist_ok=True)

        options = Options.load_default_options()
        frontend = BinaryninjaFrontend.from_path(input_path, options)

        try:
            for func in frontend.get_all_function_names():
                inter_path = os.path.join(binary_inter_folder, str(func) + ".pkl")
                dep_path = os.path.join(binary_dep_folder, str(func) + ".pkl")

                # Add to tasks if at least one of the output files is missing
                if os.path.exists(input_path) and (not os.path.exists(inter_path) or not os.path.exists(dep_path)):
                    tasks.append([input_path, str(func), inter_path, dep_path, error_log_path])
        finally:
            frontend._bv.file.close()

    return tasks


def ConditionalExportRunner():
    """Main entry point: collects one task per function per binary and runs
    them in parallel workers, each exporting pickled inter-procedural and dependency graphs."""

    parser = argparse.ArgumentParser(description="Run the conditional inter-procedural graph export.")
    parser.add_argument("--binaryFolder", "-b", required=True, help="Input path of the binaries to be analyzed.")
    parser.add_argument("--output", "-o", required=True, help="Output directory where the pickled graphs will be stored.")
    parser.add_argument("--max_workers", "-w", type=int, default=4, help="Maximum number of workers to use for processing.")
    parser.add_argument("--mem_limit", "-m", type=float, default=12, help="Memory limit per worker in GB.")
    args = parser.parse_args()

    # Ensure root output directory exists
    os.makedirs(args.output, exist_ok=True)

    error_log_path = os.path.join(args.output, "error_log.txt")

    print(f"--- Start collecting tasks from {args.binaryFolder} ---")
    tasks = collect_tasks(args.binaryFolder, args.output, error_log_path)
    print(f"--- Found {len(tasks)} tasks to process. ---")

    print(f"--- Start processing tasks with {args.max_workers} workers. ---")
    futures = []
    spawn_context = multiprocessing.get_context("spawn")
    with pebble.ProcessPool(
        max_workers=args.max_workers,
        max_tasks=4,
        initializer=set_memory_limit,
        initargs=(int(args.mem_limit * 1024**3),),
        context=spawn_context,
    ) as pool:
        for arg in tasks:
            try:
                future = pool.schedule(workerFunction, args=arg, timeout=4320)
                futures.append(future)
            except Exception as e:
                with open(error_log_path, "a") as error_log:
                    error_log.write(f"Error while scheduling task {arg}: {e}\n")

        for fut in futures:
            try:
                fut: ProcessFuture
                fut.result()
            except KeyboardInterrupt:
                pool.stop()
                break
            except Exception:
                with open(error_log_path, "a") as error_log:
                    error_log.write(f"Task raised an exception: {traceback.format_exc()}\n")
                continue

    print("--- Finished processing tasks. ---")


if __name__ == "__main__":
    ConditionalExportRunner()
