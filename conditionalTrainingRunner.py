import os
import argparse
import resource
import pebble
import traceback
import math
import random
import json
import multiprocessing

import pandas as pd

from pebble import ProcessFuture
from sklearn.metrics import roc_auc_score
from sklearn.linear_model import LogisticRegression
from decompiler.frontend.binaryninja.frontend import BinaryninjaFrontend
from decompiler.util.options import Options
from decompiler.task import DecompilerTask
from report_variable_matching import OutOfSsaDecompiler, DecompilationResult

def set_memory_limit(limit_bytes):
    """Wird von Pebble bei JEDEM Worker-Start aufgerufen (auch bei Neustarts)."""
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))

def workerFunction(binary_path: str, function_name: str, output_path: str, error_log_path: str) -> None:

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

        dct = DecompilerTask(function_name,function_name)
        result = DecompilationResult(dct,[])
        failed= True

    if failed:
        message = f"decompiling {binary_path}::{function_name} failed at stage {result.task.failure_origin}"
        with open(error_log_path, "a") as error_log:
            error_log.write(message + "\n")
        path = f"{os.environ['ConditionalResultPath']}" + ".fail" + ".noTrainingData"
        with open(path,"w"):
            pass

def FrankfurtAmMain():
    """This function is the main entry point for the conditional training runner. It collects tasks from the specified binary folder, extracts the specified attributes
    from the assignments in the functions, and trains a logistic regression model to predict the attribute coefficients. The results are saved to the specified folder.
    """
    parser = argparse.ArgumentParser(description="Run the conditional training runner.")
    parser.add_argument("--binaryFolder", "-b", required=True, help="Input Path of the binaries to be analyzed.")
    parser.add_argument("--output", "-o", required=True, help="Output dicrectory where the results will be stored.")
    parser.add_argument("--max_workers", "-w", type=int, default=4, help="Maximum number of workers to use for processing.")
    parser.add_argument("--trainingPercentage", "-t", type=float, default=0.3, help="Percentage of the data to be used for training (between 0 and 1).")
    parser.add_argument("--skipDataCollection", action="store_true", help="Skip the data collection phase and only perform training and testing.")
    args = parser.parse_args()

    if (float(args.trainingPercentage) <= 0) or (float(args.trainingPercentage) >= 1):
        raise ValueError(f"Training percentage must be between 0 and 1. Got {args.trainingPercentage}.")

    ERROR_LOG_PATH = os.path.join(args.output, "error_log.txt")
    if args.skipDataCollection:
        print(f"--- Skipping data collection phase. ---")
    else:
        print(f"--- Start collecting tasks form {args.binaryFolder} ---")
        #Create a list of tasks to be processed. 
        tasks = []
        for file in os.listdir(args.binaryFolder):
            if not os.path.exists(os.path.join(args.output,file)):
                os.mkdir(os.path.join(args.output, file))
            options = Options.load_default_options()
            filePath = os.path.join(args.binaryFolder, file)
            frontend = BinaryninjaFrontend.from_path(filePath, options)
            input_path = os.path.join(args.binaryFolder, file)
            for func in frontend.get_all_function_names():
                output_path = os.path.join(args.output, file, str(func) + ".json")
                output_path_no_data = output_path + ".noTrainingData"
                if os.path.exists(input_path) and ((not os.path.exists(output_path)) and (not os.path.exists(output_path_no_data))):
                    tasks.append([input_path, str(func), output_path, ERROR_LOG_PATH])
            del options
            del frontend

        print(f"--- Found {len(tasks)} tasks to process. ---")
        print(f"--- Start processing tasks with {args.max_workers} workers. ---")
        #Decompile all found functions and extract the training data. The results will be stored in the output folder.
        futures = []
        spawn_context = multiprocessing.get_context("spawn")
        with pebble.ProcessPool(max_workers=args.max_workers, max_tasks=4, initializer=set_memory_limit, initargs=(10 * 1024 * 1024 * 1024,), context=spawn_context) as pool:
            for arg in tasks:
                try:
                    future = pool.schedule(workerFunction, args=arg, timeout=4320)
                    futures.append(future)
                except Exception as e:
                    with open(ERROR_LOG_PATH, "a") as error_log:
                        error_log.write(f"Error while scheduling task {arg}: {e}\n")
            for fut in futures:
                try:
                    fut : ProcessFuture
                    fut.result()
                except Exception as e:
                    with open(ERROR_LOG_PATH, "a") as error_log:
                        error_log.write(f"Task raised an exception: {traceback.format_exc()}\n")
                    continue
                except KeyboardInterrupt:
                    pool.stop()
                    break

        print(f"--- Finished processing tasks. ---")

    #Split the data into training and testing sets.
    folderList = []
    random.seed(sum([1 for entry in os.scandir(args.output) if entry.is_dir()]))
    for folder in os.scandir(args.output):
        if folder.is_dir() and (os.listdir(os.path.join(args.output,folder.name)) != []):
            folderList.append([random.random(),folder.name])

    if len(folderList) < 2:
        raise ValueError(f"Not enough data to train the model. Found only {len(folderList)} folders with training data.")
    folderList.sort(key=lambda x: x[0])
    numTrainFolder = int(math.floor(len(folderList) * args.trainingPercentage))

    trainingsFolders = [folder[1] for folder in folderList[:numTrainFolder]]
    testFolders = [folder[1] for folder in folderList[numTrainFolder:]]
    print(f"--- Start training the model on {len(trainingsFolders)} binaries. ---")
    #Training Phase: Read the training data from the output folder and train a logistic regression model to predict the attribute coefficients.

    #The Order in the FEATURES list has to be the SAME as in the dependency_graph.py file and in the extractTrainingData function in the conditionalSSATraining.py
    #Otherwise the results will be very confusing. XD
    #If the parameters get changed, this List needs to be adapted as well
    FEATURES = ["is_strong", "is_mid", "same_base_name", "same_storage", "def_by_usage", "func_call", "same_phi"] + [f"usage_{i+1}" for i in range(9)]
    TARGET = "same_source"

    trainingData = [[] for _ in range(len(FEATURES) + 1)] # +1 for the target variable
    for folder in trainingsFolders:
        for file in os.listdir(os.path.join(args.output,folder)):
            if file.endswith(".json"):
                with open(os.path.join(args.output,folder,file), "r") as f:
                    data = json.load(f)
                    for key in data:
                        instructionVector = data[key]["parameters"]
                        trainingGoal = data[key]["goal"]

                        for i in range(len(FEATURES)):
                            trainingData[i].append(instructionVector[i])
                        trainingData[len(FEATURES)].append(trainingGoal)

    df = pd.DataFrame({
        feature: trainingData[i] for i, feature in enumerate(FEATURES)
    })
    df[TARGET] = trainingData[len(FEATURES)]

    model = LogisticRegression(C=1,max_iter=1000) #Du noch viel lernen musst, junger Padawan. XD
    model.fit(df[FEATURES], df[TARGET])

    w = dict(zip(FEATURES, model.coef_[0]))
    b = model.intercept_[0]

    print(f"--- Finished training the model. ---")
    print(f"--- Weights: {w} ---")
    print(f"--- Intercept: {b} ---")
    print(f"--- Start testing the model on {len(testFolders)} binaries. ---")
    #Testing Phase: Read the testing data from the output folder and evaluate the trained logistic regression model on it. The results will be saved to the output folder.

    testData = [[] for _ in range(len(FEATURES) + 1)] # +1 for the target variable
    for folder in testFolders:
        for file in os.listdir(os.path.join(args.output, folder)):
            if file.endswith(".json"):
                with open(os.path.join(args.output, folder, file), "r") as f:
                    data = json.load(f)
                    for key in data:
                        instructionVector = data[key]["parameters"]
                        trainingGoal = data[key]["goal"]

                        for i in range(len(FEATURES)):
                            testData[i].append(instructionVector[i])
                        testData[len(FEATURES)].append(trainingGoal)

    dfTest = pd.DataFrame({
        feature: testData[i] for i, feature in enumerate(FEATURES)
    })
    dfTest[TARGET] = testData[len(FEATURES)]

    X_test = dfTest[FEATURES]
    y_test = dfTest[TARGET]

    proba_test = model.predict_proba(X_test)[:, 1] #Gets probability for every sample to have same_source = 1

    auc = roc_auc_score(y_test, proba_test)
    n = len(y_test)

    print(f"--- AUC (Holdout): {auc:.4f}  (n={n}) ---")
    with open(os.path.join(args.output,"auc.txt"), "w") as f:
        f.write(f"{auc:.4f}  (n={n})\n")


    kalibrierung = pd.DataFrame({
        "predicted_proba": proba_test,
        "same_source": y_test.values,
    })

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
        "coef": {
            feature: float(coef)
            for feature, coef in zip(FEATURES, model.coef_[0])
        },
    }

    print(export)

    with open(os.path.join(args.output, "koeffizienten.json"), "w") as f:
        json.dump(export, f, indent=2)


if __name__ == "__main__":
    FrankfurtAmMain()
