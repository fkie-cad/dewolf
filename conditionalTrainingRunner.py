import argparse
import json
import math
import multiprocessing
import os
import random
import resource
import sys
import traceback

import pandas as pd
import pebble
from decompiler.frontend.binaryninja.frontend import BinaryninjaFrontend
from decompiler.task import DecompilerTask
from decompiler.util.function_corpus import build_function_groups
from decompiler.util.options import Options
from pebble import ProcessFuture
from report_variable_matching import DecompilationResult, OutOfSsaDecompiler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score


def set_memory_limit(limit_bytes):
    """Wird von Pebble bei JEDEM Worker-Start aufgerufen (auch bei Neustarts)."""
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def workerFunction(binary_path: str, function_name: str, output_path: str, error_log_path: str, fingerprint: str | None) -> None:

    os.environ["ConditionalResultPath"] = str(output_path)
    os.environ["ConditionalErrorLogPath"] = str(error_log_path)
    options = Options.load_default_options()
    options.update({"out-of-ssa-translation.mode": "conditional_training"})
    frontend = BinaryninjaFrontend.from_path(binary_path, options)
    decompiler = OutOfSsaDecompiler(frontend, options)

    failed = False
    try:
        result = decompiler.run(function_name)

    except Exception as e:
        message = f"decompiling {binary_path}::{function_name} raised {traceback.format_exc()}: {e}"
        with open(error_log_path, "a") as error_log:
            error_log.write(message + "\n")

        dct = DecompilerTask(function_name, function_name)
        result = DecompilationResult(dct, [])
        failed = True

    if failed:
        message = f"decompiling {binary_path}::{function_name} failed at stage {result.task.failure_origin}"
        with open(error_log_path, "a") as error_log:
            error_log.write(message + "\n")
        path = f"{os.environ['ConditionalResultPath']}" + ".fail" + ".noTrainingData"
        with open(path, "w"):
            pass
        return

    if os.path.exists(output_path) and fingerprint is not None:
        with open(output_path + ".fingerprint", "w") as fp_file:
            fp_file.write(fingerprint)


def discover_projects(binary_folder: str) -> list[str]:
    """Each subdirectory of binary_folder is one project (e.g. util-linux, coreutils)"""
    return sorted(d for d in os.listdir(binary_folder) if os.path.isdir(os.path.join(binary_folder, d)))


def is_valid_training_json(json_path: str, error_log_path: str) -> bool:
    """True iff json_path exists and actually parses as JSON."""
    if not os.path.exists(json_path):
        return False
    try:
        with open(json_path, "r") as f:
            json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        with open(error_log_path, "a") as error_log:
            error_log.write(f"Error while validating {json_path}: {e}\n")
        return False
    return True


def compute_kept_members(
    groups: dict[str, list[str]], functions_by_binary: dict[str, list[str]], global_seen_fingerprints: set[str]
) -> set[str]:
    """Dedup for one project: one representative per fingerprint group is kept (first
    alphabetically). Functions that never fingerprinted are always kept, never deduplicated.
    A fingerprint already claimed by an earlier project is skipped here entirely, not
    re-kept under this project too. Without this, identical code shared between projects
    (e.g. a gnulib helper linked into both coreutils and findutils) would get its own
    independent representative in each project, and the exact same compiled function could
    end up in one project's training set and a different project's validation set"""
    kept: set[str] = set()
    for fingerprint, members in groups.items():
        if fingerprint in global_seen_fingerprints:
            continue
        global_seen_fingerprints.add(fingerprint)
        kept.add(sorted(members)[0])
    all_members = {f"{binary}::{func}" for binary, funcs in functions_by_binary.items() for func in funcs}
    grouped_members = {member for members in groups.values() for member in members}
    kept |= all_members - grouped_members
    return kept


def load_or_create_project_split(
    project_output: str,
    valid_members: list[str],
    training_percentage: float,
    skip_data_collection: bool,
) -> dict[str, list[str]]:
    """Split one project's confirmed-valid functions training_percentage/rest between train
    and validation, persisted to <project_output>/split.json so every later invocation reuses
    the exact same split. If a split.json is already there, it's returned as-is and
    valid_members/training_percentage are ignored."""

    split_path = os.path.join(project_output, "split.json")
    if os.path.exists(split_path):
        with open(split_path, "r") as f:
            split = json.load(f)
        if valid_members:
            already_split = set(split["train"]) | set(split["validation"])
            missing = set(valid_members) - already_split
            if missing:
                print(
                    f"--- WARNING [{project_output}]: {len(missing)} functions with valid training data are not "
                    f"part of the persisted split.json (likely from an earlier interrupted/partial run) and will "
                    "be silently excluded from both training and validation. Delete split.json to recompute the "
                    "split from the current full set if that's not intended. ---",
                    file=sys.stderr,
                )
        return split

    if skip_data_collection:
        raise RuntimeError(
            f"No split.json found in {project_output}, but --skipDataCollection was given. "
            "Run once without --skipDataCollection first so this project's split gets decided and persisted."
        )

    if len(valid_members) < 2:
        raise ValueError(f"Not enough functions with valid training data to split. Found only {len(valid_members)} in {project_output}.")

    members_sorted = sorted(valid_members)
    random.seed("\n".join(members_sorted))  # content-dependent, not just the count, for a genuinely fresh shuffle each time the set changes
    scored = sorted(((random.random(), member) for member in members_sorted), key=lambda x: x[0])
    numTrain = int(math.floor(len(scored) * training_percentage))
    train = sorted(member for _, member in scored[:numTrain])
    validation = sorted(member for _, member in scored[numTrain:])

    os.makedirs(project_output, exist_ok=True)
    split = {"train": train, "validation": validation}
    with open(split_path, "w") as f:
        json.dump(split, f, indent=2)
    return split


def FrankfurtAmMain():
    """This function is the main entry point for the conditional training runner. It collects tasks from the specified binary folder, extracts the specified attributes
    from the assignments in the functions, and trains a logistic regression model to predict the attribute coefficients. The results are saved to the specified folder.
    """
    parser = argparse.ArgumentParser(description="Run the conditional training runner.")
    parser.add_argument("--binaryFolder", "-b", required=True, help="Input path containing one subfolder per project.")
    parser.add_argument("--output", "-o", required=True, help="Output dicrectory where the results will be stored.")
    parser.add_argument("--max_workers", "-w", type=int, default=4, help="Maximum number of workers to use for processing.")
    parser.add_argument("--mem-limit", "-m", type=float, default=10, help="Memory limit per worker in GB.")
    parser.add_argument(
        "--trainingPercentage",
        "-t",
        type=float,
        default=0.7,
        help="Percentage of each project's deduplicated functions used for training (between 0 and 1).",
    )
    parser.add_argument(
        "--skipDataCollection", action="store_true", help="Skip the data collection phase and only perform training and testing."
    )
    args = parser.parse_args()

    if (float(args.trainingPercentage) <= 0) or (float(args.trainingPercentage) >= 1):
        raise ValueError(f"Training percentage must be between 0 and 1. Got {args.trainingPercentage}.")

    ERROR_LOG_PATH = os.path.join(args.output, "error_log.txt")
    os.makedirs(args.output, exist_ok=True)

    projects = discover_projects(args.binaryFolder)
    if not projects:
        raise ValueError(f"No project subfolders found in {args.binaryFolder}.")
    print(f"--- Found {len(projects)} projects: {', '.join(projects)} ---")

    all_train_members: dict[str, list[str]] = {}
    all_validation_members: dict[str, list[str]] = {}
    tasks = []
    project_kept_members: dict[str, set[str]] = {}

    if args.skipDataCollection:
        print(f"--- Skipping data collection phase. ---")
        for project in projects:
            project_output = os.path.join(args.output, project)
            split = load_or_create_project_split(project_output, [], args.trainingPercentage, True)
            all_train_members[project] = split["train"]
            all_validation_members[project] = split["validation"]
    else:
        # Shared across every project processed below: a fingerprint already claimed by an
        # earlier project is never kept again under a later one
        global_seen_fingerprints: set[str] = set()

        for project in projects:
            project_binary_folder = os.path.join(args.binaryFolder, project)
            project_output = os.path.join(args.output, project)
            os.makedirs(project_output, exist_ok=True)

            print(f"--- [{project}] Start collecting tasks from {project_binary_folder} ---")
            groups, functions_by_binary, failedFingerprints = build_function_groups(project_binary_folder, ERROR_LOG_PATH)
            kept = compute_kept_members(groups, functions_by_binary, global_seen_fingerprints)
            project_kept_members[project] = kept
            member_to_fingerprint = {member: fp for fp, members in groups.items() for member in members}

            grouped_members = {member for members in groups.values() for member in members}
            dedup_path = os.path.join(project_output, "dedup.json")
            with open(dedup_path, "w") as f:
                json.dump({"groups": groups, "kept": sorted(kept), "excluded": sorted(grouped_members - kept)}, f, indent=2)

            scheduled = 0
            for member in sorted(kept):
                binary, func_name = member.split("::", 1)
                binary_path = os.path.join(project_binary_folder, binary)
                os.makedirs(os.path.join(project_output, binary), exist_ok=True)

                output_path = os.path.join(project_output, binary, func_name + ".json")
                output_path_no_data = output_path + ".noTrainingData"
                output_path_failed = output_path + ".fail.noTrainingData"
                if os.path.exists(output_path) or os.path.exists(output_path_no_data) or os.path.exists(output_path_failed):
                    continue

                tasks.append([binary_path, func_name, output_path, ERROR_LOG_PATH, member_to_fingerprint.get(member)])
                scheduled += 1

            print(
                f"--- [{project}] {len(kept)} deduplicated functions "
                f"({len(grouped_members) - len(kept)} duplicates skipped, {failedFingerprints} failed to fingerprint); "
                f"{scheduled} new tasks scheduled. ---"
            )

        print(f"--- Found {len(tasks)} tasks to process. ---")
        print(f"--- Start processing tasks with {args.max_workers} workers. ---")

        # Decompile all found functions and extract the training data. The results will be stored in the output folder.
        futures = []
        spawn_context = multiprocessing.get_context("spawn")
        with pebble.ProcessPool(
            max_workers=args.max_workers,
            max_tasks=4,
            initializer=set_memory_limit,
            initargs=(int(args.mem_limit * 1024 * 1024 * 1024),),
            context=spawn_context,
        ) as pool:
            for arg in tasks:
                try:
                    future = pool.schedule(workerFunction, args=arg, timeout=4320)
                    futures.append(future)
                except Exception as e:
                    with open(ERROR_LOG_PATH, "a") as error_log:
                        error_log.write(f"Error while scheduling task {arg}: {e}\n")
            for fut in futures:
                try:
                    fut: ProcessFuture
                    fut.result()
                except Exception as e:
                    with open(ERROR_LOG_PATH, "a") as error_log:
                        error_log.write(f"Task raised an exception: {traceback.format_exc()}\n")
                    continue
                except KeyboardInterrupt:
                    pool.stop()
                    print(
                        "\nInterrupted: stopping worker pool. Not computing the train/validation split from "
                        "this partial run the set of functions that have finished so far is incomplete, and "
                        "locking that in now would silently and permanently drop every function that would have "
                        "finished afterwards. Rerun the same command (without --skipDataCollection) to resume and "
                        "complete data collection before a split gets written. ",
                        file=sys.stderr,
                    )
                    sys.exit(130)

        print(f"--- Finished processing tasks. ---")

        for project in projects:
            project_output = os.path.join(args.output, project)
            valid_members = []
            for member in project_kept_members[project]:
                binary, func_name = member.split("::", 1)
                json_path = os.path.join(project_output, binary, func_name + ".json")
                if not is_valid_training_json(json_path, ERROR_LOG_PATH):
                    continue
                valid_members.append(member)

            try:
                split = load_or_create_project_split(project_output, valid_members, args.trainingPercentage, False)
            except ValueError as e:
                print(f"--- WARNING [{project}]: skipping this project entirely -- {e} ---", file=sys.stderr)
                all_train_members[project] = []
                all_validation_members[project] = []
                continue

            all_train_members[project] = split["train"]
            all_validation_members[project] = split["validation"]
            print(
                f"--- [{project}] {len(valid_members)}/{len(project_kept_members[project])} deduplicated functions "
                f"produced valid training data; split {len(split['train'])}/{len(split['validation'])} train/validation. ---"
            )

    totalTrain = sum(len(m) for m in all_train_members.values())
    totalValidation = sum(len(m) for m in all_validation_members.values())
    print(
        f"--- Train/validation split across all projects: {totalTrain} training functions, " f"{totalValidation} validation functions. ---"
    )

    print(f"--- Start training the model on {totalTrain} functions across {len(projects)} projects. ---")
    # Training Phase: Read the training data from the output folder and train a logistic regression model to predict the attribute coefficients.

    # The Order in the FEATURES list has to be the SAME as in the dependency_graph.py file and in the extractTrainingData function in the conditionalSSATraining.py
    # Otherwise the results will be very confusing. XD
    # If the parameters get changed, this List needs to be adapted as well
    FEATURES = ["is_strong", "is_mid", "same_base_name", "same_storage", "def_by_usage", "func_call", "same_phi"] + [
        f"usage_{i+1}" for i in range(9)
    ]
    TARGET = "same_source"

    def collect_rows(members_by_project: dict[str, list[str]]) -> list[list]:
        """Reads every split member's training JSON (project/binary/function.json). Every
        member here was already confirmed to have produced valid training data before the
        split was decided (see load_or_create_project_split), so the validity check below is
        a defensive no-op in practice, not a real filter -- but it's what stops a file that
        somehow went bad *after* the split was written (e.g. --skipDataCollection pointed at
        an output directory that got partially corrupted or edited by hand) from crashing
        training outright with an unhandled JSONDecodeError."""
        rows = [[] for _ in range(len(FEATURES) + 1)]  # +1 for the target variable
        for project, members in members_by_project.items():
            project_output = os.path.join(args.output, project)
            for member in members:
                binary, func_name = member.split("::", 1)
                json_path = os.path.join(project_output, binary, func_name + ".json")
                if not is_valid_training_json(json_path, ERROR_LOG_PATH):
                    continue
                with open(json_path, "r") as f:
                    data = json.load(f)
                for key in data:
                    instructionVector = data[key]["parameters"]
                    trainingGoal = data[key]["goal"]
                    for i in range(len(FEATURES)):
                        rows[i].append(instructionVector[i])
                    rows[len(FEATURES)].append(trainingGoal)
        return rows

    trainingData = collect_rows(all_train_members)

    df = pd.DataFrame({feature: trainingData[i] for i, feature in enumerate(FEATURES)})
    df[TARGET] = trainingData[len(FEATURES)]

    model = LogisticRegression(C=1, max_iter=1000)  # Du noch viel lernen musst, junger Padawan. XD
    model.fit(df[FEATURES], df[TARGET])

    w = dict(zip(FEATURES, model.coef_[0]))
    b = model.intercept_[0]

    print(f"--- Finished training the model. ---")
    print(f"--- Weights: {w} ---")
    print(f"--- Intercept: {b} ---")
    print(f"--- Start testing the model on {totalValidation} functions across {len(projects)} projects. ---")
    # Testing Phase: Read the testing data from the output folder and evaluate the trained logistic regression model on it. The results will be saved to the output folder.

    testData = collect_rows(all_validation_members)

    dfTest = pd.DataFrame({feature: testData[i] for i, feature in enumerate(FEATURES)})
    dfTest[TARGET] = testData[len(FEATURES)]

    X_test = dfTest[FEATURES]
    y_test = dfTest[TARGET]

    proba_test = model.predict_proba(X_test)[:, 1]  # Gets probability for every sample to have same_source = 1

    auc = roc_auc_score(y_test, proba_test)
    n = len(y_test)

    print(f"--- AUC (Holdout): {auc:.4f}  (n={n}) ---")
    with open(os.path.join(args.output, "auc.txt"), "w") as f:
        f.write(f"{auc:.4f}  (n={n})\n")

    kalibrierung = pd.DataFrame(
        {
            "predicted_proba": proba_test,
            "same_source": y_test.values,
        }
    )

    kalibrierung["bin"] = pd.cut(kalibrierung["predicted_proba"], bins=10, include_lowest=True)

    kalibrierungs_tabelle = kalibrierung.groupby("bin").agg(
        n=("same_source", "size"),
        tatsaechlicher_anteil=("same_source", "mean"),
        mittlere_vorhersage=("predicted_proba", "mean"),
    )

    print(kalibrierungs_tabelle)

    with open(os.path.join(args.output, "kalibrierung.txt"), "w") as f:
        f.write(str(kalibrierungs_tabelle))
        f.write("\n")

    export = {
        "intercept": float(model.intercept_[0]),
        "coef": {feature: float(coef) for feature, coef in zip(FEATURES, model.coef_[0])},
    }

    print(export)

    with open(os.path.join(args.output, "koeffizienten.json"), "w") as f:
        json.dump(export, f, indent=2)


if __name__ == "__main__":
    FrankfurtAmMain()
