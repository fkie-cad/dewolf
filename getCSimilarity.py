from report_variable_matching import main
import argparse
import os
from pathlib import Path
import pebble
import traceback
import resource
import time

SSA_Algos = ["min","boissinot2008"] #["conditional", "sreedhar", "boissinot2008", "min"]

def set_memory_limit(limit_bytes):
    """Wird von Pebble bei JEDEM Worker-Start aufgerufen (auch bei Neustarts)."""
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def frankfurtAmMAIN():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b","--binaryFolder", help="Path to the binary folder", required=True)
    parser.add_argument("-o","--output", help="Path to the output folder", required=True)
    parser.add_argument("--max-workers", "-m", default=4, type=int, help="Maximum number of worker processes")

    args = parser.parse_args()

    args.output = args.output.rstrip("/")  # Remove trailing slash if present
    args.binaryFolder = args.binaryFolder.rstrip("/")  # Remove trailing slash if present

    # intialize sturcture in the output folder
    for algo in SSA_Algos:
        Path(args.output + "/" + algo).mkdir(parents=True, exist_ok=True)

    print(f"--- Start collecting tasks form {args.binaryFolder} ---")
    tasks = []
    for algo in SSA_Algos:
        for file in os.listdir(args.binaryFolder):
            output_path = args.output + "/" + algo + "/" + file + ".json"
            input_path = args.binaryFolder + "/" + file
            if os.path.exists(input_path) and not os.path.exists(output_path):
                tasks.append([input_path, "", output_path, "--ssa-algo", algo, "-q"])
                #main(argv= [input_path, "", output_path, "--ssa-algo", algo])
    print(f"--- Found {len(tasks)} tasks to process. ---")
    print(f"--- Start processing tasks with SSA algorithms: {', '.join(SSA_Algos)} and {args.max_workers}. ---")

    futures = []
    with pebble.ProcessPool(max_workers=args.max_workers,max_tasks=1, initializer=set_memory_limit, initargs=(8 * 1024 * 1024 * 1024,)) as pool:
        for arg in tasks:
            future = pool.schedule(main, args=(arg,), timeout=4320)
            futures.append(future)
        for fut in futures:
            try:
                print(f"{len(futures)}\t/{len(futures)} tasks completed.\r", end="")
                time.sleep(1)  # Add a small delay to allow the print statement to be visible
                fut.result()
            except Exception as e:
                with open("error_log.txt", "a") as error_log:
                    error_log.write(f"Task raised an exception: {traceback.format_exc()}\n")
                continue
            except KeyboardInterrupt:
                pool.stop()
                break


if __name__ == "__main__":
    frankfurtAmMAIN()