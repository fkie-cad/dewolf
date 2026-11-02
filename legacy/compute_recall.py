#!/usr/bin/env python3
import argparse
import json
import os
import pickle
import re
import traceback
from collections import defaultdict
from pathlib import Path
from typing import Optional



def calculate_function_recall(variables: list[dict]) -> float:
    """Calculates recall for a function's variable mappings. (unchanged logic)"""
    source_to_vars = defaultdict(list)

    for v in variables:
        source = v.get("source")
        var = v.get("variable")
        if source is not None and var is not None:
            source_to_vars[source].append(var)

    total = 0
    func_recall_sum = 0.0

    for source, var_list in source_to_vars.items():
        for class_var in var_list:
            total += 1
            func_recall_sum += var_list.count(class_var) / len(var_list)

    return (func_recall_sum / total) if total > 0 else 0.0


def safe_filename(name: str) -> str:
    """Turns a binary/function name into a filesystem-safe path component."""
    name = str(name).strip()
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name or "unnamed"


def analyze_variables(variables: list[dict]) -> dict:
    source_to_var = defaultdict(list)
    var_to_source = defaultdict(list)
    var_to_lifted = defaultdict(list)
    no_source_count = 0


    for v in variables:
        src = v.get("source")
        var = v.get("variable")
        lifted = v.get("lifted")

        if src is None:
            no_source_count += 1
            continue

        source_to_var[src].append(var)
        if lifted is not None:
            var_to_lifted[var].append(lifted)
        var_to_source[var].append(src)

    # source -> {lifted_var: occurrence_count}, only where the source is
    # split across more than one distinct lifted variable.
    undermerged = {}
    for src, lifted_list in source_to_var.items():
        unique = set(lifted_list)
        if len(unique) > 1:
            undermerged[src] = [(u, set(var_to_lifted[u])) for u in unique]

    return {
        "total": len(variables),
        "counted": sum(len(v) for v in source_to_var.values()),
        "no_source_count": no_source_count,
        "undermerged": undermerged,
    }


def load_graph(graphs_root: Path, kind: str, bin_name: str, func_name: str):
    """Loads the pickled NetworkX graph at
    graphs_root/{kind}/{bin_name}/{func_name}.pkl and returns it converted
    to an undirected graph (so edge direction is ignored regardless of how
    the graph was stored). kind is "dep" or "inter". Returns None if no
    graph file exists for this binary/function."""
    graph_path = graphs_root / kind / bin_name / f"{func_name}.pkl"
    if not graph_path.exists():
        return None

    with open(graph_path, "rb") as f:
        graph = pickle.load(f)

    return graph.to_undirected()


def analyze_undermerged_connectivity(undermerged: dict, dep_graph, inter_graph) -> dict:
    """For every undermerged source, checks each pair of lifted-variable
    entries (u_i, u_j) for edges between their lifted-variable sets in the
    dependency and interference graphs (both treated as undirected).

    Note that this checks the cross product lifted_i x lifted_j - i.e.
    every (v0, v1) with v0 in lifted_i and v1 in lifted_j - not whether
    u_i and u_j themselves are connected.

    Returns src -> list of per-pair results, each a dict with the two u
    entries being compared and the matching edges (if any) found in each
    graph. A graph value of None in the result means that graph wasn't
    available to check."""

    def edges_between(lifted_a, lifted_b, graph):
        if graph is None:
            return None
        return [
            (a, b)
            for a in lifted_a
            for b in lifted_b
            if graph.has_edge(a, b)
        ]

    connectivity = {}
    for src, entries in undermerged.items():
        pairs = []
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                u_a, lifted_a = entries[i]
                u_b, lifted_b = entries[j]
                pairs.append(
                    {
                        "u_a": u_a,
                        "u_b": u_b,
                        "dep_edges": edges_between(lifted_a, lifted_b, dep_graph),
                        "inter_edges": edges_between(lifted_a, lifted_b, inter_graph),
                    }
                )
        connectivity[src] = pairs

    return connectivity


def collect_results(json_path: Path) -> list[tuple[str, list[dict], float]]:
    """Loads the evaluation JSON and returns (func_name, variables, recall)
    tuples, sorted ascending by recall - this is the script's existing
    ranking/order, preserved as-is. Functions with an empty (or missing)
    "variables" list are excluded, since recall is undefined for them."""
    with open(json_path, "r") as f:
        data = json.load(f)

    functions = data.get("functions", {})
    results = []

    for func_name, func_data in functions.items():
        if func_data.get("status") == "failed":
            continue

        report = func_data.get("report") or {}
        variables = report.get("variables", []) 

        if len(variables) == 0:
            continue

        recall = calculate_function_recall(variables)
        results.append((func_name, variables, recall))

    results.sort(key=lambda x: x[2])
    return results


def format_recall_report(
    func_name: str,
    recall: float,
    variables: list[dict],
    bin_name: Optional[str] = None,
    graphs_root: Optional[Path] = None,
) -> str:
    """Builds a human-readable recall.txt report combining the recall score
    with a debugging breakdown. Sections with nothing to report are omitted
    entirely instead of printing filler "None found" text.

    When bin_name and graphs_root are both given, each undermerged source
    is additionally annotated with whether the lifted-variable pairs it
    covers are connected by an edge in the dependency and/or interference
    graph for this function (see analyze_undermerged_connectivity)."""
    a = analyze_variables(variables)
    undermerged = a["undermerged"]
    no_source = a["no_source_count"]

    lines = []
    lines.append(f"Function: {func_name}")
    lines.append(f"Recall: {recall:.4f}")
    lines.append(
        f"Variable entries: {a['total']} total, {a['counted']} counted toward recall"
    )
    lines.append("")

    # Flag the case that silently produces a low/zero recall with nothing
    # else looking wrong: entries that never had a "source" at all.
    if no_source:
        lines.append(
            f"NOTE: {no_source} of {a['total']} entries have no 'source' field"
        )
        lines.append("")

    if undermerged:
        lines.append(f"Undermerged sources ({len(undermerged)}):")
        lines.append("A source variable was lifted to more than one distinct variable")

        connectivity = None
        if graphs_root is not None and bin_name is not None:
            dep_graph = load_graph(graphs_root, "dep", bin_name, func_name)
            inter_graph = load_graph(graphs_root, "inter", bin_name, func_name)
            lines.append(
                f"  Dependency graph: {'loaded' if dep_graph is not None else 'not found'}"
            )
            lines.append(
                f"  Interference graph: {'loaded' if inter_graph is not None else 'not found'}"
            )
            connectivity = analyze_undermerged_connectivity(undermerged, dep_graph, inter_graph)

        for src, lv in undermerged.items():
            breakdown = ", ".join(
                f"{u}: [{', '.join(lifted)}]"
                for u, lifted in lv
            )
            lines.append(f"  - {src} -> {breakdown}")

            if connectivity is not None:
                for pair in connectivity[src]:
                    lines.append(f"      {pair['u_a']} <-> {pair['u_b']}:")

                    dep_edges = pair["dep_edges"]
                    if dep_edges is None:
                        lines.append("        dependency edges: graph unavailable")
                    elif dep_edges:
                        edges_str = ", ".join(f"{v0}-{v1}" for v0, v1 in dep_edges)
                        lines.append(f"        dependency edges: {edges_str}")
                    else:
                        lines.append("        dependency edges: (none)")

                    inter_edges = pair["inter_edges"]
                    if inter_edges is None:
                        lines.append("        interference edges: graph unavailable")
                    elif inter_edges:
                        edges_str = ", ".join(f"{v0}-{v1}" for v0, v1 in inter_edges)
                        lines.append(f"        interference edges: {edges_str}")
                    else:
                        lines.append("        interference edges: (none)")

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def has_debug_signal(variables: list[dict]) -> bool:
    """True if a function's analysis has anything actually worth looking at
    for debugging undermerging: an undermerged source, an overmerged lifted
    variable, a missing mapping, or entries with no source at all. A
    function with none of these is "clean" and isn't useful in the export -
    it's excluded so the output dir only holds functions worth debugging."""
    a = analyze_variables(variables)
    return bool(a["undermerged"])


def select_for_export(
    results: list[tuple[str, list[dict], float]], n: int
) -> list[tuple[str, list[dict], float]]:
    """Walks the ranked results (worst recall first) and picks the first n
    that have real debugging signal, skipping "clean" functions along the
    way so a clean function never takes up one of the n export slots."""
    selected = []
    for func_name, variables, recall in results:
        if len(selected) >= n:
            break
        if has_debug_signal(variables):
            selected.append((func_name, variables, recall))
    return selected


def find_binary(binary_folder: Path, bin_name: str) -> Path:
    """Locates the binary file matching bin_name inside binary_folder.
    Tries an exact filename match first, then falls back to matching on
    the file stem (name without extension)."""
    direct = binary_folder / bin_name
    if direct.exists():
        return direct

    matches = [p for p in binary_folder.iterdir() if p.is_file() and p.stem == bin_name]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise RuntimeError(
            f"Multiple candidate binaries found for '{bin_name}' in {binary_folder}: "
            f"{[str(m) for m in matches]}"
        )
    raise RuntimeError(f"Could not find binary '{bin_name}' in {binary_folder}")


def export_function_artifacts(
    binary_path: Path,
    bin_name: str,
    func_name: str,
    variables: list[dict],
    recall: float,
    index: int,
    output_root: Path,
    graphs_root: Path,
) -> None:
    """Runs the decompiler in cond-cfg-export mode for a single function and
    writes cfg/, recall.txt and decomp.txt under
    output_root/bin_name/{index}_{func_name}/. Raises RuntimeError with a
    clear message if any required artifact cannot be produced."""

    from decompiler.util.options import Options
    from decompile import Decompiler #type: ignore

    folder_name = f"{index}_{safe_filename(func_name)}"
    func_dir = output_root / safe_filename(bin_name) / folder_name
    cfg_dir = func_dir / "cfg"
    cfg_dir.mkdir(parents=True, exist_ok=True)

    os.environ["PATH_BEFORE_LIFT"] = str(cfg_dir / "before_lift")
    os.environ["PATH_AFTER_LIFT"] = str(cfg_dir / "after_lift")
    os.environ["PATH_AFTER_OUT_OF_SSA"] = str(cfg_dir / "after_out_of_ssa")

    options = Options.load_default_options()
    options.update({"out-of-ssa-translation.mode": "cond-cfg-export"})

    decompiled_code = None
    try:
        decompiler = Decompiler.from_path(str(binary_path))
        _, decompiled_code = decompiler.decompile(func_name, task_options = options)
    except Exception as ex:
        raise RuntimeError(
            f"Failed to decompile {bin_name}::{func_name}"
        ) from ex

    expected_cfg_files = [
        cfg_dir / "before_lift.png",
        cfg_dir / "before_lift.txt",
        cfg_dir / "after_lift.png",
        cfg_dir / "after_lift.txt",
        cfg_dir / "after_out_of_ssa.png",
        cfg_dir / "after_out_of_ssa.txt",
    ]
    missing = [str(p) for p in expected_cfg_files if not p.exists()]
    if missing:
        raise RuntimeError(
            f"Missing expected CFG artifact(s) for {bin_name}::{func_name}: "
            f"{', '.join(missing)}"
        )

    # Decompiled pseudo-code. The exact attribute name can differ between
    # decompiler versions, so try the common spots before giving up.

    if not decompiled_code:
        raise RuntimeError(
            f"Could not obtain decompiled code for {bin_name}::{func_name}"
        )

    (func_dir / "recall.txt").write_text(
        format_recall_report(func_name, recall, variables, bin_name, graphs_root)
    )
    (func_dir / "decomp.c").write_text(decompiled_code)

def get_single_function(json_path: Path, target_func: str) -> tuple[str, list[dict], float]:
    """Retrieves data specifically for a single function name."""
    with open(json_path, "r") as f:
        data = json.load(f)

    functions = data.get("functions", {})
    if target_func not in functions:
        raise ValueError(f"Function '{target_func}' not found in {json_path}")

    func_data = functions[target_func]
    if func_data.get("status") == "failed":
        raise ValueError(f"Function '{target_func}' is marked as failed in evaluation.")

    report = func_data.get("report") or {}
    variables = report.get("variables", [])
    recall = calculate_function_recall(variables)

    return target_func, variables, recall

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Calculate per-function recall for a binary evaluation JSON file. "
            "Optionally, export CFG/recall/decompiled-code artifacts for the "
            "top N results, using the script's existing ascending-recall "
            "ranking (worst recall first)."
        )
    )
    parser.add_argument("json_path", type=Path, help="Path to the binary JSON file")
    parser.add_argument(
        "-f",
        "--function",
        type=str,
        default=None,
        help="Export artifacts for a single specified function name.",
    )
    parser.add_argument(
        "-n",
        "--num-results",
        type=int,
        default=None,
        help=(
            "Number of top-ranked results (by the existing ascending-recall "
            "ordering) to export CFG/recall/decompiled-code artifacts for. "
            "If omitted, only the recall table is printed and no artifacts "
            "are exported."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help=(
            "Output directory in which to build the "
            "{bin_name}/{func_name}/{cfg/,recall.txt,decomp.txt} artifact "
            "tree. Created if it does not already exist. Required when "
            "--num-results is given."
        ),
    )
    parser.add_argument(
        "-b",
        "--binary-folder",
        type=Path,
        default=None,
        help=(
            "Folder containing the original binaries. Used to locate the "
            "binary corresponding to this JSON file's results so it can be "
            "re-decompiled in cond-cfg-export mode. Required when "
            "--num-results is given."
        ),
    )
    parser.add_argument(
        "-g",
        "--graphs-root",
        type=Path,
        default=None,
        help=(
            "Root directory containing pickled NetworkX dependency/interference "
            "graphs, used to check whether the lifted variables behind an "
            "undermerged source share an edge in either graph (both are "
            "treated as undirected). Expected structure: "
            "<graphs_root>/dep/<binary_name>/<func_name>.pkl for dependency "
            "graphs and <graphs_root>/inter/<binary_name>/<func_name>.pkl for "
            "interference graphs, one pickled graph per function. Required "
            "when --num-results is given."
        ),
    )
    args = parser.parse_args()

    if not args.json_path.exists():
        parser.error(f"File not found: {args.json_path}")

    if args.num_results is not None:
        if args.output is None or args.binary_folder is None or args.graphs_root is None:
            parser.error(
                "--output, --binary-folder, and --graphs-root are required "
                "when --num-results is given"
            )
        if not args.binary_folder.exists():
            parser.error(f"Binary folder not found: {args.binary_folder}")
        if not args.graphs_root.exists():
            parser.error(f"Graphs root not found: {args.graphs_root}")

    bin_name = args.json_path.stem

    # Single-Function Mode
    if args.function:
        try:
            binary_path = find_binary(args.binary_folder, bin_name)
            args.output.mkdir(parents=True, exist_ok=True)
            
            func_name, variables, recall = get_single_function(args.json_path, args.function)
            print(f"--- Exporting single function '{func_name}' (Recall: {recall:.4f}) ---")
            
            export_function_artifacts(
                binary_path=binary_path,
                bin_name=bin_name,
                func_name=func_name,
                variables=variables,
                recall=recall,
                index=0,
                output_root=args.output,
                graphs_root=args.graphs_root,
            )
            print(f"  [ok] 0_{func_name}")
        except Exception as ex:
            print(f"  [FAILED] {args.function}: {ex}")
            traceback.print_exc()
        return

    results = collect_results(args.json_path)

    for func_name, _, recall in results:
        print(f"{func_name}: {recall:.4f}")

    if args.num_results is None:
        return

    binary_path = find_binary(args.binary_folder, bin_name)

    # Handle an existing output directory gracefully - reuse it, don't fail.
    args.output.mkdir(parents=True, exist_ok=True)

    top_results = select_for_export(results, args.num_results)
    print(
        f"--- Exporting artifacts for {len(top_results)} result(s) with debug "
        f"signal (requested {args.num_results}) ---"
    )

    for index, (func_name, variables, recall) in enumerate(top_results):
        try:
            export_function_artifacts(
                binary_path,
                bin_name,
                func_name,
                variables,
                recall,
                index,
                args.output,
                args.graphs_root,
            )
            print(f"  [ok] {index}_{func_name}")
        except Exception as ex:
            print(f"  [FAILED] {index}_{func_name}: {ex}")
            traceback.print_exc()


if __name__ == "__main__":
    main()
