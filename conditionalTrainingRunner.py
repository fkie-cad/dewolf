import argparse
import json
import math
import multiprocessing
import os
import random
import resource
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

    # The fingerprint (the function's MLIL-SSA structural identity) was already computed
    # up-front during task collection, before this task was even scheduled -- see
    # FrankfurtAmMain. Just persist it next to the result; the aggregation phase still checks
    # it as a dedup safety net, even though collection should never have scheduled an actual
    # duplicate in the first place.
    if os.path.exists(output_path) and fingerprint is not None:
        with open(output_path + ".fingerprint", "w") as fp_file:
            fp_file.write(fingerprint)


def load_or_create_split(args) -> tuple[list[str], list[str]]:
    """Decides which binaries are train vs test, persisted to split.json so every later
    invocation (including --skipDataCollection reruns) uses the exact same split. The split
    has to be known before task collection now for the dedup to work."""

    split_path = os.path.join(args.output, "split.json")
    if os.path.exists(split_path):
        with open(split_path, "r") as f:
            split = json.load(f)
        return split["train"], split["test"]

    if args.skipDataCollection:
        raise RuntimeError(
            f"No split.json found in {args.output}, but --skipDataCollection was given. "
            "Run once without --skipDataCollection first so the train/test split gets decided and persisted."
        )

    binaries = sorted(f for f in os.listdir(args.binaryFolder) if os.path.isfile(os.path.join(args.binaryFolder, f)))
    if len(binaries) < 2:
        raise ValueError(f"Not enough binaries to train the model. Found only {len(binaries)} binaries in {args.binaryFolder}.")

    random.seed(len(binaries))
    scored = sorted(((random.random(), binary) for binary in binaries), key=lambda x: x[0])
    numTrain = int(math.floor(len(scored) * args.trainingPercentage))
    train = sorted(binary for _, binary in scored[:numTrain])
    test = sorted(binary for _, binary in scored[numTrain:])

    os.makedirs(args.output, exist_ok=True)
    with open(split_path, "w") as f:
        json.dump({"train": train, "test": test}, f, indent=2)
    return train, test


def pick_representatives(groups: dict[str, list[str]], side_of: dict[str, str]) -> set[str]:
    """For every fingerprint group, pick exactly one representative to actually decompile: a
    training-side member if one exists in that group, else a test-side member -- both picked
    deterministically (alphabetically) for reproducibility. This is the training-specific "train
    wins over test" rule; eval_dedup.py's own representative choice (first alphabetically,
    ignoring any train/test notion) doesn't apply here."""
    kept: set[str] = set()
    for members in groups.values():
        train_members = sorted(m for m in members if side_of.get(m.split("::", 1)[0]) == "train")
        kept.add(train_members[0] if train_members else sorted(members)[0])
    return kept


def FrankfurtAmMain():
    """This function is the main entry point for the conditional training runner. It collects tasks from the specified binary folder, extracts the specified attributes
    from the assignments in the functions, and trains a logistic regression model to predict the attribute coefficients. The results are saved to the specified folder.
    """
    parser = argparse.ArgumentParser(description="Run the conditional training runner.")
    parser.add_argument("--binaryFolder", "-b", required=True, help="Input Path of the binaries to be analyzed.")
    parser.add_argument("--output", "-o", required=True, help="Output dicrectory where the results will be stored.")
    parser.add_argument("--max_workers", "-w", type=int, default=4, help="Maximum number of workers to use for processing.")
    parser.add_argument("--trainingPercentage", "-t", type=float, default=0.7, help="Percentage of the data to be used for training (between 0 and 1).")
    parser.add_argument("--skipDataCollection", action="store_true", help="Skip the data collection phase and only perform training and testing.")
    args = parser.parse_args()

    if (float(args.trainingPercentage) <= 0) or (float(args.trainingPercentage) >= 1):
        raise ValueError(f"Training percentage must be between 0 and 1. Got {args.trainingPercentage}.")

    ERROR_LOG_PATH = os.path.join(args.output, "error_log.txt")
    os.makedirs(args.output, exist_ok=True)

    trainingsFolders, testFolders = load_or_create_split(args)
    print(f"--- Train/test split: {len(trainingsFolders)} training binaries, {len(testFolders)} test binaries. ---")

    if args.skipDataCollection:
        print(f"--- Skipping data collection phase. ---")
    else:
        print(f"--- Start collecting tasks form {args.binaryFolder} ---")

        # One shared scan (same one eval_dedup.py uses) decides which functions are duplicates
        # of which, *before* any decompilation -- groups only functions that fingerprinted
        # successfully; functions_by_binary is the complete per-binary function list regardless
        # of fingerprinting success, so a function that failed to fingerprint is never silently
        # dropped, just never deduplicated.
        groups, functions_by_binary, failedFingerprints = build_function_groups(args.binaryFolder, ERROR_LOG_PATH)

        side_of = {binary: "train" for binary in trainingsFolders} | {binary: "test" for binary in testFolders}
        kept = pick_representatives(groups, side_of)
        member_to_fingerprint = {member: fp for fp, members in groups.items() for member in members}
        all_grouped_members = set(member_to_fingerprint)

        dedup_path = os.path.join(args.output, "dedup.json")
        with open(dedup_path, "w") as f:
            json.dump({"groups": groups, "kept": sorted(kept), "excluded": sorted(all_grouped_members - kept)}, f, indent=2)

        # Create a list of tasks to be processed.
        tasks = []
        for file in trainingsFolders + testFolders:
            if file not in functions_by_binary:
                continue
            binary_path = os.path.join(args.binaryFolder, file)
            os.makedirs(os.path.join(args.output, file), exist_ok=True)

            for func_name in functions_by_binary[file]:
                member = f"{file}::{func_name}"
                if member in all_grouped_members and member not in kept:
                    continue  # duplicate of some other binary::function already kept elsewhere

                output_path = os.path.join(args.output, file, func_name + ".json")
                output_path_no_data = output_path + ".noTrainingData"
                output_path_failed = output_path + ".fail.noTrainingData"
                if os.path.exists(output_path) or os.path.exists(output_path_no_data) or os.path.exists(output_path_failed):
                    continue

                tasks.append([binary_path, func_name, output_path, ERROR_LOG_PATH, member_to_fingerprint.get(member)])

        print(
            f"--- Skipped {len(all_grouped_members) - len(kept)} duplicate functions before decompiling "
            f"(identical compiled code already resolved); {failedFingerprints} functions failed to fingerprint "
            "and were never deduplicated. ---"
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
            initargs=(10 * 1024 * 1024 * 1024,),
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
                    break

        print(f"--- Finished processing tasks. ---")

    print(f"--- Start training the model on {len(trainingsFolders)} binaries. ---")
    # Training Phase: Read the training data from the output folder and train a logistic regression model to predict the attribute coefficients.

    # The Order in the FEATURES list has to be the SAME as in the dependency_graph.py file and in the extractTrainingData function in the conditionalSSATraining.py
    # Otherwise the results will be very confusing. XD
    # If the parameters get changed, this List needs to be adapted as well
    FEATURES = ["is_strong", "is_mid", "same_base_name", "same_storage", "def_by_usage", "func_call", "same_phi"] + [
        f"usage_{i+1}" for i in range(9)
    ]
    TARGET = "same_source"

    # Functions can recur across different binaries (e.g. the same statically-linked
    # library routine). seen_fingerprints is shared across the training AND testing
    # aggregation below, so a function already used for training is never also used
    # for testing (no leakage across the split), and duplicates within one side are
    # collapsed to a single occurrence.
    seen_fingerprints: set[str] = set()
    duplicatesDroppedTrain = 0

    trainingData = [[] for _ in range(len(FEATURES) + 1)]  # +1 for the target variable
    for folder in trainingsFolders:
        for file in os.listdir(os.path.join(args.output, folder)):
            if file.endswith(".json"):
                fingerprint_path = os.path.join(args.output, folder, file + ".fingerprint")
                with open(fingerprint_path, "r") as fp_file:
                    fingerprint = fp_file.read()
                if fingerprint in seen_fingerprints:
                    duplicatesDroppedTrain += 1
                    continue
                seen_fingerprints.add(fingerprint)

                with open(os.path.join(args.output, folder, file), "r") as f:
                    data = json.load(f)
                    for key in data:
                        instructionVector = data[key]["parameters"]
                        trainingGoal = data[key]["goal"]

                        for i in range(len(FEATURES)):
                            trainingData[i].append(instructionVector[i])
                        trainingData[len(FEATURES)].append(trainingGoal)

    print(f"--- Dropped {duplicatesDroppedTrain} duplicate functions while aggregating training data. ---")

    df = pd.DataFrame({feature: trainingData[i] for i, feature in enumerate(FEATURES)})
    df[TARGET] = trainingData[len(FEATURES)]

    model = LogisticRegression(C=1, max_iter=1000)  # Du noch viel lernen musst, junger Padawan. XD
    model.fit(df[FEATURES], df[TARGET])

    w = dict(zip(FEATURES, model.coef_[0]))
    b = model.intercept_[0]

    print(f"--- Finished training the model. ---")
    print(f"--- Weights: {w} ---")
    print(f"--- Intercept: {b} ---")
    print(f"--- Start testing the model on {len(testFolders)} binaries. ---")
    # Testing Phase: Read the testing data from the output folder and evaluate the trained logistic regression model on it. The results will be saved to the output folder.

    duplicatesDroppedTest = 0

    testData = [[] for _ in range(len(FEATURES) + 1)]  # +1 for the target variable
    for folder in testFolders:
        for file in os.listdir(os.path.join(args.output, folder)):
            if file.endswith(".json"):
                fingerprint_path = os.path.join(args.output, folder, file + ".fingerprint")
                with open(fingerprint_path, "r") as fp_file:
                    fingerprint = fp_file.read()
                if fingerprint in seen_fingerprints:
                    # Either a duplicate within the test set, or a function that
                    # already occurred on the training side -- drop either way so
                    # no function in trainingsFolders also ends up in testFolders.
                    duplicatesDroppedTest += 1
                    continue
                seen_fingerprints.add(fingerprint)

                with open(os.path.join(args.output, folder, file), "r") as f:
                    data = json.load(f)
                    for key in data:
                        instructionVector = data[key]["parameters"]
                        trainingGoal = data[key]["goal"]

                        for i in range(len(FEATURES)):
                            testData[i].append(instructionVector[i])
                        testData[len(FEATURES)].append(trainingGoal)

    print(f"--- Dropped {duplicatesDroppedTest} duplicate/already-trained-on functions while aggregating test data. ---")

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
