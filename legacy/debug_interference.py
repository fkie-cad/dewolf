#!/usr/bin/env python3
import argparse
import json
import os
import pickle
import traceback
from collections import defaultdict
from itertools import combinations, product

from networkx import Graph, MultiGraph


def analyze_function(func_name: str, func_data: dict, inter_graph: Graph, dep_graph: MultiGraph):
    """Computes undermerging, interference, and dependency stats for one function.

    Returns a tuple (func_result, rollup):
      - func_result: the minimal dict that gets saved into the output JSON
        for this function (function_name, undermerged_count, undermerged_sets).
      - rollup: binary-level accumulator info that is *not* saved directly,
        but is used by process_binary to compute the binary's
        overall_interference_density and largest_undermerged_set without
        having to store per-function pair totals in the JSON.
    """

    report = func_data.get("report") or {}
    variables = report.get("variables", [])

    empty_rollup = {
        "possible_pairs": 0,
        "interfering_pairs": 0,
        "largest_group_size": 0,
        "group_size_counts": {},
    }

    if not variables:
        return (
            {
                "function_name": func_name,
                "undermerged_count": 0,
                "group_size_counts": {},
                "undermerged_sets": [],
            },
            empty_rollup,
        )

    source_to_var = defaultdict(set)
    var_to_lifted = defaultdict(set)

    for v in variables:
        src = v.get("source", "UNKNOWN_SRC")
        var = v.get("variable")
        lifted = v.get("lifted")

        if src and var:
            source_to_var[src].add(var)
            if lifted:
                var_to_lifted[var].add(lifted)

    undermerged_sets = []
    undermerged_count = 0
    largest_group_size = 0
    group_size_counts = defaultdict(int)

    # Binary-level rollup accumulators (interference density needs these
    # totals, but the per-set/per-function breakdowns aren't saved).
    func_possible_pairs = 0
    func_interfering_pairs = 0

    for src, unique_vars in source_to_var.items():
        if len(unique_vars) <= 1:
            continue

        undermerged_count += 1
        group = sorted(unique_vars)
        group_size = len(group)
        possible_pairs = group_size * (group_size - 1) // 2
        lifted_vars = sum(len(var_to_lifted[v]) for v in group)

        interfering_pairs = 0
        dependent_pairs = 0

        for a, b in combinations(group, 2):
            unique_lifted_a = var_to_lifted[a]
            unique_lifted_b = var_to_lifted[b]

            found_inter = False
            found_dep = False

            for e1, e2 in product(unique_lifted_a, unique_lifted_b):
                if inter_graph is not None and inter_graph.has_edge(e1, e2):
                    found_inter = True

                if dep_graph is not None and dep_graph.has_edge(e1, e2):
                    found_dep = True

                # Once both are confirmed for this variable pair there's
                # nothing more to learn from the remaining lifted-node
                # combinations, since only the booleans are kept.
                if found_inter and found_dep:
                    break

            if found_inter:
                interfering_pairs += 1

            if found_dep:
                dependent_pairs += 1

        dependency_density = (
            dependent_pairs / possible_pairs
            if possible_pairs > 0
            else 0.0
        )

        has_interference = interfering_pairs > 0
        has_dependency = dependent_pairs > 0

        largest_group_size = max(largest_group_size, group_size)
        group_size_counts[group_size] += 1
        func_possible_pairs += possible_pairs
        func_interfering_pairs += interfering_pairs

        undermerged_sets.append({
            "source": src,
            "group_size": group_size,
            "has_interference": has_interference,
            "has_dependency": has_dependency,
            "dependency_density": dependency_density,
            "lifted_vars": lifted_vars,
        })

    func_result = {
        "function_name": func_name,
        "undermerged_count": undermerged_count,
        "group_size_counts": dict(group_size_counts),
        "undermerged_sets": undermerged_sets,
    }

    rollup = {
        "possible_pairs": func_possible_pairs,
        "interfering_pairs": func_interfering_pairs,
        "largest_group_size": largest_group_size,
        "group_size_counts": dict(group_size_counts),
    }

    return func_result, rollup


def load_graphs(graph_path: str, binary: str, func_name: str):
    """Loads both the pickled interference and dependency graphs for one function.
    Returns (inter_graph, dep_graph, error) where error is None on success."""

    inter_path = os.path.join(graph_path, "inter", binary, f"{func_name}.pkl")
    dep_path = os.path.join(graph_path, "dep", binary, f"{func_name}.pkl")

    if not os.path.exists(inter_path) or not os.path.exists(dep_path):
        return None, None, "graph_missing"

    try:
        with open(inter_path, "rb") as f:
            inter_graph = pickle.load(f)
        with open(dep_path, "rb") as f:
            dep_graph = pickle.load(f)
        return inter_graph, dep_graph, None
    except Exception:
        return None, None, "graph_load_error"


def process_binary(binary: str, json_path: str, graph_path: str):
    with open(json_path, "r") as f:
        data = json.load(f)

    functions_out = []
    skipped = []

    total_possible_pairs = 0
    total_interfering_pairs = 0
    largest_undermerged_set = 0
    binary_group_size_counts = defaultdict(int)

    for f_name, func_data in data.get("functions", {}).items():
        inter_graph, dep_graph, error = load_graphs(graph_path, binary, f_name)

        if error is not None:
            skipped.append({"function_name": f_name, "reason": error})
            continue

        try:
            func_result, rollup = analyze_function(f_name, func_data, inter_graph, dep_graph)
        except Exception:
            skipped.append({
                "function_name": f_name,
                "reason": "analysis_error",
                "detail": traceback.format_exc(),
            })
            continue

        functions_out.append(func_result)
        total_possible_pairs += rollup["possible_pairs"]
        total_interfering_pairs += rollup["interfering_pairs"]
        largest_undermerged_set = max(largest_undermerged_set, rollup["largest_group_size"])

        for size, count in rollup["group_size_counts"].items():
            binary_group_size_counts[size] += count

    function_count = len(functions_out)
    undermerged_count = sum(fr["undermerged_count"] for fr in functions_out)

    overall_interference_density = (
        total_interfering_pairs / total_possible_pairs
        if total_possible_pairs > 0
        else 0.0
    )

    result = {
        "binary": binary,
        "summary": {
            "function_count": function_count,
            "undermerged_count": undermerged_count,
            "overall_interference_density": overall_interference_density,
            "largest_undermerged_set": largest_undermerged_set,
            "group_size_counts": dict(binary_group_size_counts),
        },
        "functions": functions_out,
    }

    return result, len(skipped)


def main():
    parser = argparse.ArgumentParser(
        description="Collect undermerging/interference and dependency statistics per binary into structured JSON."
    )
    parser.add_argument("--output_folder", "-o", required=True, help="Directory to write {binary}.json result files to.")
    parser.add_argument("--json_folder", "-j", required=True, help="Directory containing {binary}.json recall debug files.")
    parser.add_argument("--graph_path", "-g", required=True, help="Base output directory of the previous graph generation script (containing 'inter' and 'dep').")
    args = parser.parse_args()

    if not os.path.exists(args.output_folder):
        os.makedirs(args.output_folder)

    json_files = [f for f in os.listdir(args.json_folder) if f.endswith(".json")]
    print(f"--- Found {len(json_files)} binary JSON files in {args.json_folder} ---")

    for json_file in json_files:
        binary = json_file[:-len(".json")]
        json_path = os.path.join(args.json_folder, json_file)

        try:
            result, skipped_count = process_binary(binary, json_path, args.graph_path)
        except Exception:
            print(f"[!] Failed to process binary {binary}: {traceback.format_exc()}")
            continue

        output_path = os.path.join(args.output_folder, f"{binary}.json")
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)

        summary = result["summary"]
        print(
            f"[-] {binary}: {summary['function_count']} functions, "
            f"{summary['undermerged_count']} undermerged sources, "
            f"{skipped_count} skipped "
            f"-> {output_path}"
        )

    print("--- Finished processing all binaries. ---")


if __name__ == "__main__":
    main()
