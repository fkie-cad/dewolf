#!/usr/bin/env python3
"""
plot_dwarf.py - Analyze and visualize variable-recovery evaluation results.

This script processes JSON files from a specific decompiler evaluation clip
and generates publication-quality plots using matplotlib.
"""

import argparse
import json
import warnings
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


def safe_len(obj) -> int:
    """Safely get the length of an object that might be None or a different type."""
    if isinstance(obj, (dict, list, str)):
        return len(obj)
    return 0


def get_unique(data: list[dict], key: str) -> list[str]:
    return sorted(set(r[key] for r in data if key in r))


def compute_micro_avg(df_group: list[dict]) -> float:
    """Compute overall micro-averaged match rate: sum(matched) / sum(total)."""
    total_matched = sum(row.get("matched", 0) for row in df_group)
    total_all = sum(row.get("total", 0) for row in df_group)
    return (total_matched / total_all * 100) if total_all > 0 else 0.0


def compute_kind_micro_avg(df_group: list[dict], kind: str) -> float:
    """Compute micro-averaged match rate for a specific kind."""
    total_matched = sum(row.get(f"kind_{kind}_matched", 0) for row in df_group)
    total_all = sum(row.get(f"kind_{kind}_total", 0) for row in df_group)
    return (total_matched / total_all * 100) if total_all > 0 else 0.0


def get_all_kinds(data: list[dict]) -> list[str]:
    """Extract all unique valid kind names observed in the data."""
    kinds = set()
    for row in data:
        for key in row.keys():
            if key.startswith("kind_") and key.endswith("_matched"):
                kind = key.replace("kind_", "").replace("_matched", "")
                if kind:
                    kinds.add(kind)
    return sorted(kinds)


def load_results(
    clip_path: Path, excluded: set[str] | None = None, project: str | None = None
) -> tuple[list[dict], list[dict], dict, dict, dict, dict]:
    """
    Load data for a single setup/clip directory.

    excluded: "binary::function" keys to drop entirely (from eval_dedup.py's exclusion list),
    applied identically across every algorithm so they're all compared on the same
    deduplicated function set -- a function that recurs across many binaries (e.g. the same
    statically-linked library routine) shouldn't dominate the aggregate stats.

    project: when given, prefixes every "binary" value (in the returned rows and in the
    precision/recall/inserted dict keys) with f"{project}/" -- so binaries with the same name
    in two different projects never collide when their data gets merged for an aggregated
    "overall" report.

    A function counts as successful only if its status is exactly "success". Every other
    status ("failed", "timeout", "unknown", ...) goes into failure_rows, so the row-based plots,
    the precision/recall dicts and the summary table all agree on the same function set.

    Returns:
        success_rows: Functions common and successful across all algorithms.
        failure_rows: All non-successful records encountered across algorithms.
        precision_dict, recall_dict, inserted_dict, total: per-call accumulator dicts (no
        module-level global state), structured as {algo: {binary: {function: {var: [...]}}}}
        for the first three, and {algo: [0, 0, total_variable_records, 0]} for `total` -- feed
        these into evaluate_precision_recall() to get a RESULT_DICT-shaped dict.

    Every success row also carries "out_vars_total" / "out_vars_matched": the function's
    distinct output (post-out-of-SSA) variable names, and how many of them have a source match
    through at least one of their SSA variables -- the per-variable view, as opposed to
    "matched"/"total", which count (output name, lifted SSA variable) records.
    """
    success_rows = []
    failure_rows = []
    excluded = excluded or set()
    precision_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
    recall_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
    inserted_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
    total = defaultdict(lambda: [0, 0, 0, 0])

    if not clip_path.exists() or not clip_path.is_dir():
        warnings.warn(f"Input directory not found or invalid: {clip_path}")
        return success_rows, failure_rows, precision_dict, recall_dict, inserted_dict, total

    clip_name = clip_path.name
    algorithms = sorted([d.name for d in clip_path.iterdir() if d.is_dir()])

    if not algorithms:
        warnings.warn(f"No algorithm subdirectories found in {clip_path}")
        return success_rows, failure_rows, precision_dict, recall_dict, inserted_dict, total

    algo_binaries = {}
    for algo in algorithms:
        algo_path = clip_path / algo
        algo_binaries[algo] = {p.stem: p for p in algo_path.glob("*.json")}

    common_binaries = set(algo_binaries[algorithms[0]].keys())
    for algo in algorithms[1:]:
        common_binaries.intersection_update(algo_binaries[algo].keys())

    if not common_binaries:
        warnings.warn(f"No common binaries found across algorithms {algorithms} in {clip_path}.")
        return success_rows, failure_rows, precision_dict, recall_dict, inserted_dict, total

    print(f"Folder '{clip_name}': Using {len(common_binaries)} common binaries across {len(algorithms)} algorithms.")

    total_common_funcs = 0
    commonFuncs = defaultdict(lambda: [])

    for binary_name in common_binaries:
        binary_algo_data = []
        read_failed = False
        for algo in algorithms:
            json_file = algo_binaries[algo][binary_name]
            try:
                with open(json_file, "r") as f:
                    binary_algo_data.append(json.load(f))
            except (json.JSONDecodeError, IOError) as e:
                warnings.warn(f"Failed to read {json_file}: {e}")
                read_failed = True
                break

        if read_failed:
            continue

        common_successful_funcs = None
        for algo_data in binary_algo_data:
            functions = algo_data.get("functions", {})

            successful_funcs = {
                func_name
                for func_name, func_data in functions.items()
                if func_data.get("status") == "success" and f"{binary_name}::{func_name}" not in excluded
            }

            if common_successful_funcs is None:
                common_successful_funcs = successful_funcs
            else:
                common_successful_funcs.intersection_update(successful_funcs)

        if not common_successful_funcs:
            continue

        total_common_funcs += len(common_successful_funcs)
        commonFuncs[binary_name] = sorted(common_successful_funcs)

    print(f"Found {total_common_funcs} common successful functions across all algorithms for {len(common_binaries)} common binaries.")

    for algo in algorithms:
        for binary_name in common_binaries:
            json_file = algo_binaries[algo][binary_name]
            try:
                with open(json_file, "r") as f:
                    content = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                warnings.warn(f"Failed to read {json_file}: {e}")
                continue

            functions = content.get("functions", {})
            for func_name, func_data in functions.items():
                if f"{binary_name}::{func_name}" in excluded:
                    continue

                status = func_data.get("status", "unknown")
                message = func_data.get("message") or ""

                # Failure stage: parsed from the message for "failed"; for any other
                # non-success status (e.g. "timeout") the status itself is the stage.
                fail_stage = "unknown"
                if status == "failed":
                    if "failed at stage " in message:
                        fail_stage = message.split("failed at stage ")[-1].strip()
                elif status != "success":
                    fail_stage = status

                binary_key_name = f"{project}/{binary_name}" if project else binary_name

                report = func_data.get("report") or {}
                row = {
                    "algorithm": algo,
                    "binary": binary_key_name,
                    "function": func_name,
                    "status": status,
                    "failure_stage": fail_stage,
                    "matched": report.get("matched", 0),
                    "total": report.get("total", 0),
                    "overmerged_count": safe_len(report.get("overmerged")),
                    "undermerged_count": safe_len(report.get("undermerged")),
                    "conflicts_count": safe_len(report.get("conflicts")),
                }

                # Everything that is not exactly "success" is a failure (Plot 7 + summary table)
                if status != "success":
                    failure_rows.append(row)
                    continue

                # Process only common successful functions for the main metrics
                if func_name not in commonFuncs[binary_name]:
                    continue

                variables = report.get("variables")
                by_kind = report.get("by_kind", {})

                # Output-variable view. Fallback when the variable records are missing: the report's
                # own per-output-name tally, whose kinds partition the names (unmatched ones under
                # "unmatched" with matched = 0), so summing over kinds gives the same two numbers.
                by_output_name = report.get("by_output_name") or {}
                row["out_vars_total"] = sum(t.get("total", 0) for t in by_output_name.values())
                row["out_vars_matched"] = sum(t.get("matched", 0) for t in by_output_name.values())

                if isinstance(variables, list) and len(variables) > 0 and isinstance(variables[0], dict):
                    calc_by_kind = defaultdict(lambda: {"matched": 0, "total": 0})
                    out_var_matched: dict[str, bool] = {}  # output name -> has any source match
                    for v in variables:
                        if v.get("variable") is not None:
                            out_var_matched[v["variable"]] = out_var_matched.get(v["variable"], False) or v.get("source") is not None
                        if (v.get("source") is not None) and (v.get("variable") is not None):
                            precision_dict[algo][binary_key_name][func_name][v.get("variable")].append(v.get("source"))
                            recall_dict[algo][binary_key_name][func_name][v.get("source")].append(v.get("variable"))
                        elif v.get("variable") is not None:
                            inserted_dict[algo][binary_key_name][func_name][v.get("variable")].append(v.get("lifted"))
                        total[algo][2] += 1

                        k = v.get("kind", "unknown")
                        calc_by_kind[k]["total"] += 1

                        is_matched = v.get("source") is not None
                        if is_matched:
                            calc_by_kind[k]["matched"] += 1

                    if any(k["total"] > 0 for k in calc_by_kind.values()):
                        by_kind = calc_by_kind
                    row["out_vars_total"] = len(out_var_matched)
                    row["out_vars_matched"] = sum(out_var_matched.values())

                for kind, kind_data in by_kind.items():
                    row[f"kind_{kind}_matched"] = kind_data.get("matched", 0)
                    row[f"kind_{kind}_total"] = kind_data.get("total", 0)

                success_rows.append(row)

    return success_rows, failure_rows, precision_dict, recall_dict, inserted_dict, total


def plot_overall_accuracy(data: list[dict], outdir: Path, clip_name: str, algorithms: list, algo_colors: dict) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    vals, colors = [], []
    for algo in algorithms:
        group = [r for r in data if r["algorithm"] == algo]
        vals.append(compute_micro_avg(group))
        colors.append(algo_colors[algo])

    x = np.arange(len(algorithms))
    bars = ax.bar(x, vals, color=colors, edgecolor="black", width=0.6)
    for bar in bars:
        yval = bar.get_height()
        if yval > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, yval + 1, f"{yval:.1f}%", ha="center", va="bottom", fontsize=10)

    ax.set_ylabel("Overall Match Rate (%)")
    ax.set_title(f"Overall Variable Recovery Accuracy\n(Folder: {clip_name})")
    ax.set_ylim(0, 110)
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms, rotation=15, ha="right")
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(outdir / "01_overall_accuracy.png", dpi=150, bbox_inches="tight")
    plt.close()


def plot_accuracy_by_kind(data: list[dict], outdir: Path, clip_name: str, algorithms: list, algo_colors: dict) -> None:
    kinds = get_all_kinds(data)
    if not kinds:
        return

    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(kinds))
    width = 0.8 / len(algorithms)

    for i, algo in enumerate(algorithms):
        group = [r for r in data if r["algorithm"] == algo]
        kind_vals = [compute_kind_micro_avg(group, k) for k in kinds]
        offset = (i - len(algorithms) / 2 + 0.5) * width

        ax.bar(x + offset, kind_vals, width, label=algo, color=algo_colors[algo], edgecolor="black")
        for j, v in enumerate(kind_vals):
            ax.text(x[j] + offset, v + 1, f"{v:.1f}%", ha="center", va="bottom", fontsize=8, rotation=90)

    ax.set_ylabel("Match Rate (%)")
    ax.set_title(f"Variable Recovery Accuracy by Variable Kind\n(Folder: {clip_name})")
    ax.set_xticks(x)
    ax.set_xticklabels(kinds, rotation=45, ha="right")
    ax.legend(title="Algorithm", bbox_to_anchor=(1.05, 1), loc="upper left")
    ax.set_ylim(0, 115)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(outdir / "02_accuracy_by_kind.png", dpi=150, bbox_inches="tight")
    plt.close()


def plot_per_function_distribution(data: list[dict], outdir: Path, clip_name: str, algorithms: list, algo_colors: dict) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    all_data = []

    for i, algo in enumerate(algorithms):
        group = [r for r in data if r["algorithm"] == algo]
        rates = [(r["matched"] / r["total"] * 100) for r in group if r.get("total", 0) > 0]
        all_data.append(rates)

        if rates:
            pos = i + 1
            x_jitter = np.random.normal(pos, 0.05, size=len(rates))
            ax.scatter(x_jitter, rates, alpha=0.2, s=15, color=algo_colors[algo], zorder=2)

    bp = ax.boxplot(all_data, positions=range(1, len(algorithms) + 1), widths=0.6, patch_artist=True, zorder=3, showfliers=False)
    for patch, algo in zip(bp["boxes"], algorithms):
        patch.set_facecolor("none")
        patch.set_edgecolor("black")
        patch.set_linewidth(1.5)

    for median in bp["medians"]:
        median.set(color="black", linewidth=2)

    ax.set_title(f"Distribution of Per-Function Match Rates\n(Folder: {clip_name})")
    ax.set_xticks(range(1, len(algorithms) + 1))
    ax.set_xticklabels(algorithms, rotation=15, ha="right")
    ax.set_ylabel("Per-Function Match Rate (%)")
    ax.set_ylim(-5, 105)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(outdir / "03_per_function_distribution.png", dpi=150, bbox_inches="tight")
    plt.close()


def plot_accuracy_vs_complexity(data: list[dict], outdir: Path, clip_name: str, algorithms: list, algo_colors: dict) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    for algo in algorithms:
        group = [r for r in data if r["algorithm"] == algo]
        x_vals, y_vals = [], []
        for r in group:
            if r.get("total", 0) > 0:
                x_vals.append(r["total"])
                y_vals.append(r["matched"] / r["total"] * 100)

        if not x_vals:
            continue

        color = algo_colors[algo]
        ax.scatter(x_vals, y_vals, alpha=0.3, s=20, color=color, edgecolor="none")

        if len(x_vals) > 5:
            try:
                z = np.polyfit(np.log10(x_vals), y_vals, 1)
                p = np.poly1d(z)
                slope = z[0]
                x_trend = np.logspace(np.log10(min(x_vals)), np.log10(max(x_vals)), 50)

                ax.plot(
                    x_trend, p(np.log10(x_trend)), color=color, linewidth=2.5, solid_capstyle="round", label=f"{algo} (slope: {slope:.1f})"
                )
            except np.linalg.LinAlgError:
                ax.plot([], [], color=color, label=f"{algo} (slope: N/A)")
        else:
            ax.plot([], [], color=color, label=f"{algo} (slope: N/A)")

    ax.set_xscale("log")
    ax.set_title(f"Accuracy Degradation vs. Function Complexity\n(Folder: {clip_name})")
    ax.set_xlabel("Function Variable Count (Log Scale)")
    ax.set_ylabel("Per-Function Match Rate (%)")
    ax.legend(title="Algorithm & Trendline Slope", bbox_to_anchor=(1.05, 1), loc="upper left")
    ax.set_ylim(-5, 105)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(outdir / "04_accuracy_vs_complexity.png", dpi=150, bbox_inches="tight")
    plt.close()


def plot_error_modes(data: list[dict], outdir: Path, clip_name: str, algorithms: list) -> None:
    error_colors = ["#d62728", "#9467bd", "#8c564b"]
    error_labels = ["Overmerged", "Undermerged", "Conflicts"]
    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(algorithms))
    width = 0.8 / 3

    overmerged = [sum(r.get("overmerged_count", 0) for r in data if r["algorithm"] == algo) for algo in algorithms]
    undermerged = [sum(r.get("undermerged_count", 0) for r in data if r["algorithm"] == algo) for algo in algorithms]
    conflicts = [sum(r.get("conflicts_count", 0) for r in data if r["algorithm"] == algo) for algo in algorithms]

    all_counts = [overmerged, undermerged, conflicts]
    max_val = max(max(overmerged, default=0), max(undermerged, default=0), max(conflicts, default=0), 1)

    for err_idx, (counts, color, label) in enumerate(zip(all_counts, error_colors, error_labels)):
        offset = (err_idx - 1) * width
        bars = ax.bar(x + offset, counts, width, label=label, color=color, edgecolor="black")
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + (max_val * 0.01), str(int(h)), ha="center", va="bottom", fontsize=8)

    ax.set_title(f"Structural Error Modes Across Algorithms\n(Folder: {clip_name})")
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms, rotation=15, ha="right")
    ax.set_ylabel("Total Occurrences (Absolute Count)")
    ax.set_ylim(0, max_val * 1.15)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.legend(title="Error Type")

    plt.subplots_adjust(bottom=0.20)
    plt.savefig(outdir / "05_error_modes.png", dpi=150, bbox_inches="tight")
    plt.close()


def plot_per_binary_heatmap(data: list[dict], outdir: Path, clip_name: str, algorithms: list) -> None:
    binaries = get_unique(data, "binary")
    if not binaries:
        return

    matrix = np.zeros((len(algorithms), len(binaries)))
    matrix[:] = np.nan

    for i, algo in enumerate(algorithms):
        for j, binary in enumerate(binaries):
            bin_data = [r for r in data if r["algorithm"] == algo and r["binary"] == binary]
            if bin_data:
                matrix[i, j] = compute_micro_avg(bin_data)

    fig_height = max(4, len(algorithms) * 1.0)
    fig_width = max(8, len(binaries) * 0.4)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))

    im = ax.imshow(matrix, cmap="viridis", aspect="auto", vmin=0, vmax=100)

    ax.set_xticks(np.arange(len(binaries)))
    ax.set_yticks(np.arange(len(algorithms)))
    ax.set_xticklabels(binaries, rotation=45, ha="right", fontsize=9)
    ax.set_yticklabels(algorithms, fontsize=10)

    for i in range(len(algorithms)):
        for j in range(len(binaries)):
            if not np.isnan(matrix[i, j]):
                color = "white" if matrix[i, j] < 50 else "black"
                ax.text(j, i, f"{matrix[i, j]:.0f}%", ha="center", va="center", color=color, fontsize=8)

    cbar = plt.colorbar(im, ax=ax, fraction=0.02, pad=0.04)
    cbar.set_label("Match Rate (%)")
    ax.set_title(f"Per-Binary Accuracy - {clip_name}")
    plt.tight_layout()
    plt.savefig(outdir / "06_per_binary_heatmap.png", dpi=150, bbox_inches="tight")
    plt.close()


def plot_failure_stages(data: list[dict], outdir: Path, clip_name: str, algorithms: list, algo_colors: dict) -> None:
    """Generate a grouped bar chart of failure stages by algorithm. Non-"failed" statuses
    (e.g. "timeout") show up as their own stage."""
    failed_data = [r for r in data if r["status"] != "success" and r["failure_stage"] != "unknown"]

    if not failed_data:
        print("  - Skipping 07_failure_stages.png (no parsable failures found)")
        return

    stages = get_unique(failed_data, "failure_stage")
    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(stages))
    width = 0.8 / len(algorithms)

    for i, algo in enumerate(algorithms):
        group = [r for r in failed_data if r["algorithm"] == algo]
        stage_counts = [sum(1 for r in group if r["failure_stage"] == stage) for stage in stages]

        offset = (i - len(algorithms) / 2 + 0.5) * width

        ax.bar(x + offset, stage_counts, width, label=algo, color=algo_colors[algo], edgecolor="black")
        for j, v in enumerate(stage_counts):
            if v > 0:
                ax.text(x[j] + offset, v + (max(stage_counts) * 0.01), str(v), ha="center", va="bottom", fontsize=8)

    ax.set_ylabel("Number of Failed Functions")
    ax.set_title(f"Function Failure Modes by Decompilation Stage\n(Folder: {clip_name})")
    ax.set_xticks(x)
    ax.set_xticklabels(stages, rotation=45, ha="right")
    ax.legend(title="Algorithm", bbox_to_anchor=(1.05, 1), loc="upper left")
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(outdir / "07_failure_stages.png", dpi=150, bbox_inches="tight")
    plt.close()


def print_summary_table(success_data: list[dict], failure_data: list[dict], clip_name: str, algorithms: list, outdir: Path) -> None:
    """Functions = common successful functions (identical across algorithms by construction);
    Failed = this algorithm's non-successful functions in the common binaries.
    Match % = matched (output name, SSA variable) records; Out vars / Out matched / Out % =
    distinct output variables, how many have a source match, and the ratio.
    Printed to the console and saved to <outdir>/summary.txt."""
    lines = ["=" * 140, f"VARIABLE RECOVERY EVALUATION SUMMARY - FOLDER: {clip_name}", "=" * 140]
    max_algo_len = max(len(a) for a in algorithms)
    algo_col_width = max(15, max_algo_len + 2)

    header = (
        f"{'Algorithm':<{algo_col_width}} {'Match %':>10} {'Binaries':>10} {'Functions':>10} {'Failed':>8} "
        f"{'Overmerge':>10} {'Undermerge':>10} {'Out vars':>10} {'Out matched':>12} {'Out %':>8}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    for algo in algorithms:
        success_group = [r for r in success_data if r["algorithm"] == algo]
        failed_group = [r for r in failure_data if r["algorithm"] == algo]
        if not success_group and not failed_group:
            continue

        total_bins = len(set(r["binary"] for r in success_group))
        total_funcs = len(success_group)
        failed_funcs = len(failed_group)
        total_overmerged = sum(r.get("overmerged_count", 0) for r in success_group)
        total_undermerged = sum(r.get("undermerged_count", 0) for r in success_group)
        match_rate = compute_micro_avg(success_group)
        out_total, out_matched, out_ratio = output_variable_stats(success_group)

        lines.append(
            f"{algo:<{algo_col_width}} {match_rate:>9.1f}% {total_bins:>10} "
            f"{total_funcs:>10} {failed_funcs:>8} {total_overmerged:>10} "
            f"{total_undermerged:>10} {out_total:>10} {out_matched:>12} {out_ratio:>7.1f}%"
        )
    lines.append("=" * 140)

    text = "\n".join(lines)
    print("\n" + text + "\n")
    with open(outdir / "summary.txt", "w") as f:
        f.write(text + "\n")


def output_variable_stats(rows: list[dict]) -> tuple[int, int, float]:
    """(output variables, output variables with a source match, match ratio in %) over the rows.
    Counts distinct out-of-SSA names per function -- not their SSA variables ("lifted")."""
    total = sum(r.get("out_vars_total", 0) for r in rows)
    matched = sum(r.get("out_vars_matched", 0) for r in rows)
    return total, matched, (matched / total * 100) if total > 0 else 0.0


def plot_output_variable_matching(data: list[dict], outdir: Path, clip_name: str, algorithms: list) -> None:
    """Per algorithm: number of output variables and how many of them have a source match (with ratio)."""
    counts = {algo: output_variable_stats([r for r in data if r["algorithm"] == algo]) for algo in algorithms}
    plot_grouped_metrics(
        data={algo: [total, matched] for algo, (total, matched, _) in counts.items()},
        totals={algo: [total, total] for algo, (total, _, _) in counts.items()},
        save_path=outdir / "21_output_variable_matching.png",
        title=f"Output Variables With a Source Match\n(Folder: {clip_name})",
        metric_names=["Output Variables", "With Source Match"],
        percent=False,
    )


def evaluate_precision_recall(precision_dict: dict, recall_dict: dict, inserted_dict: dict, total: dict) -> tuple[dict, dict]:
    """Pure version of the former global-mutating function: takes the accumulator dicts
    load_results() built (total already has [2] -- the raw variable-record count -- filled
    in; this function adds [0]/[1]) and returns a fresh RESULT_DICT-shaped dict plus the
    completed total, without touching any module state. Called once per project (for that
    project's own report) and once more on the merged cross-project dicts (for "overall")."""
    # Fixed-length [precision, overmergedVar, overmergedSSA, recall, f1, inserted,
    # undermergedSource, undermergedSSA] per binary, defaulted to 0 and overwritten by index
    # rather than conditionally appended -- a binary with e.g. only inserted/unmatched variables
    # and no matched ones must not end up with a short list whose values then get misread by
    # every downstream consumer (plot_heatmap, aggregateResults) that indexes it positionally.
    #
    # total per algorithm: [output variables with a match, matched SSA records, all variable
    # records, source variables] -- the denominators for the overmerged / inserted / undermerged
    # percentages.
    result_dict: dict = defaultdict(lambda: defaultdict(lambda: [0.0, 0, 0, 0.0, 0.0, 0, 0, 0]))
    total = defaultdict(lambda: [0, 0, 0, 0], {algo: (list(vals) + [0, 0, 0, 0])[:4] for algo, vals in total.items()})

    for algorithm in precision_dict.keys():
        for binary in precision_dict[algorithm].keys():
            binary_Precision = 0
            cnt = 0
            overmerged_countVariable = 0
            overmerged_countSSA = 0
            for function in precision_dict[algorithm][binary].keys():
                for variable in precision_dict[algorithm][binary][function].keys():
                    if len(set(precision_dict[algorithm][binary][function][variable])) >= 2:
                        overmerged_countVariable += 1
                        overmerged_countSSA += len(precision_dict[algorithm][binary][function][variable])
                    total[algorithm][0] += 1
                    total[algorithm][1] += len(precision_dict[algorithm][binary][function][variable])
                    for Classvar in precision_dict[algorithm][binary][function][variable]:
                        cnt += 1
                        binary_Precision += precision_dict[algorithm][binary][function][variable].count(Classvar) / len(
                            precision_dict[algorithm][binary][function][variable]
                        )
            if cnt > 0:
                binaryPrecision = binary_Precision / cnt
            else:
                binaryPrecision = 0
            result_dict[algorithm][binary][0] = binaryPrecision
            result_dict[algorithm][binary][1] = overmerged_countVariable
            result_dict[algorithm][binary][2] = overmerged_countSSA

    for algorithm in recall_dict.keys():
        for binary in recall_dict[algorithm].keys():
            binary_Recall = 0
            cnt = 0
            # Undermerge, the dual of overmerge: one source variable whose SSA variables ended up
            # under several output names (the renamer split what DWARF says is one variable).
            undermerged_countSource = 0
            undermerged_countSSA = 0
            for function in recall_dict[algorithm][binary].keys():
                for source in recall_dict[algorithm][binary][function].keys():
                    if len(set(recall_dict[algorithm][binary][function][source])) >= 2:
                        undermerged_countSource += 1
                        undermerged_countSSA += len(recall_dict[algorithm][binary][function][source])
                    total[algorithm][3] += 1
                    for Classvar in recall_dict[algorithm][binary][function][source]:
                        cnt += 1
                        binary_Recall += recall_dict[algorithm][binary][function][source].count(Classvar) / len(
                            recall_dict[algorithm][binary][function][source]
                        )
            if cnt > 0:
                binary_Recall = binary_Recall / cnt
            else:
                binary_Recall = 0
            result_dict[algorithm][binary][3] = binary_Recall
            result_dict[algorithm][binary][6] = undermerged_countSource
            result_dict[algorithm][binary][7] = undermerged_countSSA

    for algorithm in list(result_dict.keys()):
        for binary in list(result_dict[algorithm].keys()):
            precision, _, _, recall, *_ = result_dict[algorithm][binary]
            if (precision + recall) > 0:
                f1_score = 2 * (precision * recall) / (precision + recall)
            else:
                f1_score = 0
            result_dict[algorithm][binary][4] = f1_score

    for algorithm in inserted_dict.keys():
        for binary in inserted_dict[algorithm].keys():
            insertedCount = 0
            for function in inserted_dict[algorithm][binary].keys():
                for variable in inserted_dict[algorithm][binary][function].keys():
                    insertedCount += len(inserted_dict[algorithm][binary][function][variable])
            result_dict[algorithm][binary][5] = insertedCount

    return result_dict, total


def _bcubed_sum(cluster_dict: dict) -> tuple[float, int]:
    """Sum of per-element B-cubed scores and number of elements over
    {binary: {function: {cluster: [labels]}}}. Per element e in cluster C the score is
    |{x in C : label(x) == label(e)}| / |C| -- exactly what evaluate_precision_recall()
    computes per element, just summed over everything instead of averaged per binary."""
    score, count = 0.0, 0
    for functions in cluster_dict.values():
        for clusters in functions.values():
            for labels in clusters.values():
                n = len(labels)
                if n == 0:
                    continue
                score += sum(c * c for c in Counter(labels).values()) / n
                count += n
    return score, count


def compute_micro_metrics(precision_dict: dict, recall_dict: dict) -> dict:
    """Micro-averaged B-cubed precision/recall per algorithm: every matched SSA element
    weighs the same, regardless of which binary it is in. F1 is computed from the micro
    precision and recall. Returns {algo: [precision%, recall%, f1%]}."""
    res = {}
    for algo in sorted(set(precision_dict) | set(recall_dict)):
        p_sum, p_cnt = _bcubed_sum(precision_dict.get(algo, {}))
        r_sum, r_cnt = _bcubed_sum(recall_dict.get(algo, {}))
        p = p_sum / p_cnt if p_cnt else 0.0
        r = r_sum / r_cnt if r_cnt else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        res[algo] = [100 * p, 100 * r, 100 * f1]
    return res


def aggregateResults(result_dict: dict) -> dict:
    res = {}
    for algorithm in result_dict.keys():
        result = []
        total = 0
        for binary in result_dict[algorithm].keys():
            if len(result_dict[algorithm][binary]) == 8:
                result.append(result_dict[algorithm][binary])
                total += 1
        result = [sum(vals) for vals in zip(*result)]
        if total > 0:
            # rates are averaged over binaries, counts are summed
            result = [result[0] / total, result[1], result[2], result[3] / total, result[4] / total, result[5], result[6], result[7]]
        else:
            raise ValueError(f"No valid results found for algorithm '{algorithm}' to aggregate.")
        res[algorithm] = result
    return res


def plot_grouped_metrics(
    data: dict,
    save_path: str | Path,
    title: str,
    metric_names: list[str] | None = None,
    colors: list[str] | None = None,
    bar_width: float = 0.13,
    group_gap: float = 0.4,
    percent: bool = True,
    totals: dict | None = None,
) -> None:
    """
    Gruppierter Balkenplot: pro Algorithmus liegen alle zugehörigen Werte als eng
    beieinanderstehende Balken, zwischen den Algorithmen-Gruppen ist Abstand.

    Parameters
    ----------
    data : dict
        {algorithmus: [wert1, wert2, ..., wertN]} - alle Listen gleich lang.
    save_path : str oder Path
        Pfad (inkl. Dateiname), unter dem der Plot gespeichert wird.
    title : str
        Titel des Plots.
    metric_names : list[str], optional
        Beschriftung der N Werte in der Legende, in der Reihenfolge der Listen.
        Falls None: DEFAULT_METRIC_NAMES, sofern die Länge passt, sonst generische Namen.
    colors : list[str], optional
        Farben pro Metrik. Falls None: Matplotlib "tab10"-Farbzyklus.
    bar_width : float
        Breite eines einzelnen Balkens.
    group_gap : float
        Zusätzlicher Abstand zwischen den Algorithmen-Gruppen.
    percent : bool
        Nur relevant, wenn `totals` NICHT angegeben ist: ob die Balkenbeschriftung
        mit "%" versehen wird oder als reine Zahl (ohne Umrechnung).
    totals : dict, optional
        {algorithmus: [wert1, ..., wertN]} - zweite Werteliste in derselben Form wie
        `data` (gleiche Algorithmen, gleiche Anzahl Werte pro Algorithmus). Falls
        angegeben, wird an jedem Balken zusätzlich zum Absolutwert der prozentuale
        Anteil am jeweiligen Wert aus `totals` angezeigt, also
        data[algo][m] / totals[algo][m] * 100.
    """
    DEFAULT_METRIC_NAMES = [
        "Precision",
        "Overmerged Variables",
        "Overmerged SSA Variables",
        "Recall",
        "F1 Score",
        "Inserted Variables",
    ]
    algorithms = list(data.keys())
    if not algorithms:
        return

    n_metrics = len(next(iter(data.values())))
    for algo, values in data.items():
        if len(values) != n_metrics:
            raise ValueError(f"Alle Wertelisten müssen gleich lang sein, aber '{algo}' hat " f"{len(values)} statt {n_metrics} Werte.")

    if totals is not None:
        for algo in algorithms:
            if algo not in totals:
                raise ValueError(f"'{algo}' fehlt in totals.")
            if len(totals[algo]) != n_metrics:
                raise ValueError(f"totals['{algo}'] hat {len(totals[algo])} statt {n_metrics} Werte.")

    if metric_names is None:
        metric_names = DEFAULT_METRIC_NAMES if len(DEFAULT_METRIC_NAMES) == n_metrics else [f"Metrik {i + 1}" for i in range(n_metrics)]
    elif len(metric_names) != n_metrics:
        raise ValueError(f"metric_names hat {len(metric_names)} Einträge, aber die Daten haben " f"{n_metrics} Werte pro Algorithmus.")

    if colors is None:
        cmap = plt.get_cmap("tab10")
        colors = [cmap(i % 10) for i in range(n_metrics)]

    group_width = n_metrics * bar_width
    x_group_centers = np.arange(len(algorithms)) * (group_width + group_gap)

    fig_width = max(8, len(algorithms) * (group_width + group_gap) + 2)
    fig, ax = plt.subplots(figsize=(fig_width, 6))

    for m in range(n_metrics):
        offsets = x_group_centers + (m - (n_metrics - 1) / 2) * bar_width
        values = [data[algo][m] for algo in algorithms]
        bars = ax.bar(offsets, values, width=bar_width, label=metric_names[m], color=colors[m])

        if totals is not None:
            labels = []
            for algo, val in zip(algorithms, values):
                total_val = totals[algo][m]
                if total_val:
                    pct = val / total_val * 100
                    labels.append(f"{val:.0f}\n({pct:.2f}%)")
                else:
                    labels.append(f"{val:.0f}\n(n/a)")
            ax.bar_label(bars, labels=labels, rotation=0, padding=3, fontsize=7)
        elif percent:
            ax.bar_label(bars, fmt=lambda x: f"{x:.2f}%", rotation=0, padding=3, fontsize=7)
        else:
            ax.bar_label(bars, fmt=lambda x: f"{x:.0f}", rotation=0, padding=3, fontsize=7)

    ax.margins(y=0.2 if totals is not None else 0.15)
    ax.set_xticks(x_group_centers)
    ax.set_xticklabels(algorithms, rotation=45, ha="right")
    ax.set_title(title)
    ax.set_ylabel("Wert")
    if len(metric_names) > 1:
        ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1), borderaxespad=0)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_heatmap(
    data: dict,
    metric: str,
    save_path: str | Path,
    title: str | None = None,
    cmap: str = "viridis",
    values_are_fractions: bool = True,
) -> None:
    """
    Erzeugt eine farbcodierte Heatmap: Algorithmen (vertikal) x Binaries (horizontal)
    und speichert sie unter save_path.

    Parameters
    ----------
    data : dict
        {algorithmus: {binary: [precision, recall, f1]}}
    metric : str
        Welche der drei Metriken geplottet werden soll: "precision", "recall" oder "f1".
    save_path : str oder Path
        Pfad (inkl. Dateiname), unter dem die Grafik gespeichert wird.
    title : str, optional
        Titel der Grafik. Falls None, wird ein Standardtitel aus dem Metriknamen erzeugt.
    cmap : str
        Matplotlib-Colormap-Name.
    values_are_fractions : bool
        Falls True (Standard), werden die Werte in data als 0-1 angenommen und für die
        Darstellung mit *100 in Prozent umgerechnet. Falls die Werte in data bereits als
        Prozentzahlen (0-100) vorliegen, hier False übergeben.
    """

    METRIC_INDEX = {
        "precision": 0,
        "overmergedVariable": 1,
        "overmergedSSA": 2,
        "recall": 3,
        "f1": 4,
        "inserted": 5,
        "undermergedSource": 6,
        "undermergedSSA": 7,
    }
    METRIC_LABEL = {
        "precision": "Precision",
        "overmergedVariable": "Overmerged Variables",
        "overmergedSSA": "Overmerged SSA Variables",
        "recall": "Recall",
        "f1": "F1 Score",
        "inserted": "Inserted Variables (no DWARF match)",
        "undermergedSource": "Undermerged Source Variables",
        "undermergedSSA": "Undermerged SSA Variables",
    }
    # Metrics shown as raw values with an auto-scaled color range (counts, and F1 as 0-1),
    # as opposed to the percentage metrics on a fixed 0-100 scale.
    UNSCALED_METRICS = ("overmergedVariable", "overmergedSSA", "inserted", "f1", "undermergedSource", "undermergedSSA")

    if metric not in METRIC_INDEX:
        raise ValueError(f"metric muss einer von {list(METRIC_INDEX)} sein, nicht '{metric}'")
    if metric in UNSCALED_METRICS:
        values_are_fractions = False  # Overmerged is an absolute count, not a fraction
    idx = METRIC_INDEX[metric]
    scale = 100.0 if values_are_fractions else 1.0

    algorithms = list(data.keys())
    binaries = sorted({b for algo_dict in data.values() for b in algo_dict.keys()})
    if not binaries:
        return

    # Matrix aufbauen (NaN für fehlende Kombinationen)
    matrix = np.full((len(algorithms), len(binaries)), np.nan)
    for i, algo in enumerate(algorithms):
        for j, binary in enumerate(binaries):
            values = data[algo].get(binary)
            if values is not None and len(values) > idx:
                matrix[i, j] = values[idx] * scale

    # nan-aware: missing algorithm/binary combinations are NaN and must not poison min/max
    minimum = np.nanmin(matrix)
    maximum = np.nanmax(matrix)
    fig_height = max(4, len(algorithms) * 1.0)
    fig_width = max(8, len(binaries) * 0.5)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    if metric in UNSCALED_METRICS:
        im = ax.imshow(matrix, cmap=cmap, aspect="auto")
    else:
        im = ax.imshow(matrix, cmap=cmap, aspect="auto", vmin=0, vmax=100)

    ax.set_xticks(np.arange(len(binaries)))
    ax.set_yticks(np.arange(len(algorithms)))
    ax.set_xticklabels(binaries, rotation=45, ha="right", fontsize=9)
    ax.set_yticklabels(algorithms, fontsize=10)

    for i in range(len(algorithms)):
        for j in range(len(binaries)):
            if not np.isnan(matrix[i, j]):
                if metric in UNSCALED_METRICS:
                    color = "white" if matrix[i, j] < (minimum + ((maximum - minimum) / 2)) else "black"
                else:
                    color = "white" if matrix[i, j] < 50 else "black"
                if metric not in UNSCALED_METRICS:
                    ax.text(
                        j,
                        i,
                        f"{matrix[i, j]:.1f}%",
                        ha="center",
                        va="center",
                        color=color,
                        fontsize=8,
                    )
                elif metric == "f1":
                    ax.text(
                        j,
                        i,
                        f"{matrix[i, j]:.3f}",
                        ha="center",
                        va="center",
                        color=color,
                        fontsize=8,
                    )
                else:
                    ax.text(
                        j,
                        i,
                        f"{int(matrix[i, j])}",
                        ha="center",
                        va="center",
                        color=color,
                        fontsize=8,
                    )

    cbar = plt.colorbar(im, ax=ax, fraction=0.02, pad=0.04)
    if metric in UNSCALED_METRICS:
        cbar.set_label(f"{METRIC_LABEL[metric]}")
    else:
        cbar.set_label(f"{METRIC_LABEL[metric]} (%)")

    ax.set_title(title or f"{METRIC_LABEL[metric]} pro Algorithmus / Binary")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()


def discover_projects(indir: Path) -> list[Path]:
    """Each subdirectory of indir is one project's results folder, shaped exactly like the
    pre-multi-project flat layout (<algorithm>/<binary>.json)."""
    return sorted(d for d in indir.iterdir() if d.is_dir())


def load_exclusions(projects: list[Path]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Reads every project's exclusion.json once, up front.

    Returns two dicts keyed by project name:
      within: the project's own "excluded" list (duplicates inside that project) -- used for
              the per-project reports and the overall report.
      cross:  functions whose fingerprint was already seen in an alphabetically earlier
              project -- additionally excluded from the "overall" report only, so code shared
              between projects (gnulib, statically linked libc, ...) is counted once there.

    Cross-project dedup needs exclusion.json to contain "groups": {fingerprint: ["binary::func", ...]}
    covering every fingerprinted function, singleton groups included. Projects without "groups"
    are still evaluated, but can't be checked against other projects (a warning is printed).
    """
    within: dict[str, set[str]] = {}
    cross: dict[str, set[str]] = {}
    seen_fingerprints: dict[str, str] = {}  # fingerprint -> project that keeps it

    for project_dir in projects:
        project = project_dir.name
        within[project] = set()
        cross[project] = set()

        exclusion_path = project_dir / "exclusion.json"
        if not exclusion_path.exists():
            warnings.warn(f"[{project}] No exclusion.json found at {exclusion_path}; proceeding without dedup filtering.")
            continue

        with open(exclusion_path, "r") as f:
            content = json.load(f)

        within[project] = set(content.get("excluded", []))
        print(f"[{project}] Loaded {len(within[project])} excluded duplicate functions from {exclusion_path}.")

        groups = content.get("groups")
        if groups is None:
            warnings.warn(
                f"[{project}] exclusion.json has no 'groups' (fingerprint -> members); "
                "this project can't be deduplicated against other projects in the overall report."
            )
            continue

        for fingerprint, members in groups.items():
            if fingerprint in seen_fingerprints:
                cross[project].update(members)
            else:
                seen_fingerprints[fingerprint] = project

        if cross[project]:
            print(f"[{project}] {len(cross[project])} functions already represented in an earlier project; dropped from 'overall'.")

    return within, cross


def generate_plot_set(
    success_data: list[dict], failure_data: list[dict], outdir: Path, clip_name: str, algorithms: list, algo_colors: dict
) -> None:
    """The 7 row-based plots + the summary table, for one data set (one project, or the
    merged "overall" set) -- no logic changes from the original single-project main(), just
    factored out so it can be called once per project and once more for "overall"."""
    outdir.mkdir(parents=True, exist_ok=True)
    print_summary_table(success_data, failure_data, clip_name, algorithms, outdir)

    success_only = [row for row in success_data if row["status"] == "success"]

    print(f"Generating plots for '{clip_name}'...")
    plot_overall_accuracy(success_only, outdir, clip_name, algorithms, algo_colors)
    print("  - 01_overall_accuracy.png -> Coverage")

    plot_accuracy_by_kind(success_only, outdir, clip_name, algorithms, algo_colors)
    print("  - 02_accuracy_by_kind.png")

    plot_per_function_distribution(success_only, outdir, clip_name, algorithms, algo_colors)
    print("  - 03_per_function_distribution.png")

    plot_accuracy_vs_complexity(success_only, outdir, clip_name, algorithms, algo_colors)
    print("  - 04_accuracy_vs_complexity.png")

    plot_error_modes(success_only, outdir, clip_name, algorithms)
    print("  - 05_error_modes.png")

    plot_per_binary_heatmap(success_only, outdir, clip_name, algorithms)
    print("  - 06_per_binary_heatmap.png")

    plot_failure_stages(failure_data, outdir, clip_name, algorithms, algo_colors)
    print("  - 07_failure_stages.png")

    plot_output_variable_matching(success_only, outdir, clip_name, algorithms)
    print("  - 21_output_variable_matching.png")


def generate_dict_based_plots(result_dict: dict, total: dict, outdir: Path, precision_dict: dict, recall_dict: dict) -> None:
    """The 6 heatmaps + the grouped-metric plots, built from one evaluate_precision_recall()
    snapshot, plus the micro-averaged metrics computed straight from precision/recall dicts."""
    print("  - 08_precision_heatmap.png")
    plot_heatmap(
        data=result_dict, metric="precision", save_path=outdir / "08_precision_heatmap.png", title="Precision per Algorithm / Binary"
    )

    print("  - 09_recall_heatmap.png")
    plot_heatmap(data=result_dict, metric="recall", save_path=outdir / "09_recall_heatmap.png", title="Recall per Algorithm / Binary")

    print("  - 10_f1_heatmap.png")
    plot_heatmap(data=result_dict, metric="f1", save_path=outdir / "10_f1_heatmap.png", title="F1 Score per Algorithm / Binary")

    print("  - 11_overmergedVariable_heatmap.png")
    plot_heatmap(
        data=result_dict,
        metric="overmergedVariable",
        save_path=outdir / "11_overmergedVariable_heatmap.png",
        title="Overmerged Variables per Algorithm / Binary",
    )

    print("  - 12_overmergedSSA_heatmap.png")
    plot_heatmap(
        data=result_dict,
        metric="overmergedSSA",
        save_path=outdir / "12_overmergedSSA_heatmap.png",
        title="Overmerged SSA Variables per Algorithm / Binary",
    )

    print("  - 13_inserted_heatmap.png")
    plot_heatmap(
        data=result_dict,
        metric="inserted",
        save_path=outdir / "13_inserted_heatmap.png",
        title="Inserted SSA-Variables (no DWARF match) per Algorithm / Binary",
    )

    agregated_results = aggregateResults(result_dict)
    step1 = {algo: [100 * vals[0], 100 * vals[3], 100 * vals[4]] for algo, vals in agregated_results.items()}  # Precision, Recall, F1
    print("  - 14_average_metrics.png (macro: mean over binaries)")
    plot_grouped_metrics(
        data=step1,
        save_path=outdir / "14_average_metrics.png",
        title="Macro-Averaged Metrics per Algorithm (mean over binaries)",
        metric_names=["Precision", "Recall", "F1 Score"],
    )

    step2 = {algo: [vals[1]] for algo, vals in agregated_results.items()}  # Overmerged Variables
    totals_step2 = {algo: [vals[0]] for algo, vals in total.items()}
    print("  - 15_aggregated_overmerged.png")
    plot_grouped_metrics(
        data=step2,
        save_path=outdir / "15_aggregated_overmerged.png",
        title="Aggregated Overmerged Variables per Algorithm",
        metric_names=["Overmerged Variables"],
        percent=False,
        group_gap=0.01,
        totals=totals_step2,
    )

    step3 = {algo: [vals[5]] for algo, vals in agregated_results.items()}  # Inserted SSA-Variables
    step3_totals = {algo: [vals[2]] for algo, vals in total.items()}
    print("  - 16_aggregated_inserted.png")
    plot_grouped_metrics(
        data=step3,
        save_path=outdir / "16_aggregated_inserted.png",
        title="Aggregated Inserted SSA-Variables (no DWARF match) per Algorithm",
        metric_names=["Inserted SSA-Variables"],
        percent=False,
        group_gap=0.01,
        totals=step3_totals,
    )

    micro = compute_micro_metrics(precision_dict, recall_dict)
    print("  - 17_micro_average_metrics.png (micro: every SSA variable weighs the same)")
    plot_grouped_metrics(
        data=micro,
        save_path=outdir / "17_micro_average_metrics.png",
        title="Micro-Averaged Metrics per Algorithm (pooled over all SSA variables)",
        metric_names=["Precision", "Recall", "F1 Score"],
    )

    # Undermerge, analogous to 11 / 12 / 15 for overmerge.
    print("  - 18_undermergedSource_heatmap.png")
    plot_heatmap(
        data=result_dict,
        metric="undermergedSource",
        save_path=outdir / "18_undermergedSource_heatmap.png",
        title="Undermerged Source Variables per Algorithm / Binary",
    )

    print("  - 19_undermergedSSA_heatmap.png")
    plot_heatmap(
        data=result_dict,
        metric="undermergedSSA",
        save_path=outdir / "19_undermergedSSA_heatmap.png",
        title="Undermerged SSA Variables per Algorithm / Binary",
    )

    step4 = {algo: [vals[6]] for algo, vals in agregated_results.items()}  # Undermerged source variables
    step4_totals = {algo: [vals[3]] for algo, vals in total.items()}  # all matched source variables
    print("  - 20_aggregated_undermerged.png")
    plot_grouped_metrics(
        data=step4,
        save_path=outdir / "20_aggregated_undermerged.png",
        title="Aggregated Undermerged Source Variables per Algorithm",
        metric_names=["Undermerged Source Variables"],
        percent=False,
        group_gap=0.01,
        totals=step4_totals,
    )


def main():
    parser = argparse.ArgumentParser(description="Analyze and visualize variable-recovery evaluation results.")
    parser.add_argument(
        "--indir",
        type=Path,
        required=True,
        help="Path to the top-level results directory, containing one subfolder per project (each shaped like <algorithm>/<binary>.json).",
    )
    parser.add_argument("--outdir", type=Path, required=False, help="Output directory for plots")

    args = parser.parse_args()

    if not args.outdir:
        args.outdir = args.indir.parent / f"Plots"

    args.outdir.mkdir(parents=True, exist_ok=True)

    projects = discover_projects(args.indir)
    if not projects:
        print(f"No project subdirectories found in {args.indir}. Exiting.")
        return
    print(f"Found {len(projects)} projects: {', '.join(p.name for p in projects)}")

    within_excluded, cross_excluded = load_exclusions(projects)

    overall_success: list[dict] = []
    overall_failure: list[dict] = []
    overall_precision: dict = {}
    overall_recall: dict = {}
    overall_inserted: dict = {}
    overall_total: dict = {}
    cmap = plt.get_cmap("tab10")

    for project_dir in projects:
        project = project_dir.name
        excluded = within_excluded[project]

        print(f"Loading data for project '{project}' from {project_dir}...")
        success_data, failure_data, precision_dict, recall_dict, inserted_dict, total = load_results(project_dir, excluded, project=project)

        if not success_data:
            print(f"[{project}] No data found or processed. Skipping.")
            continue

        algorithms = get_unique(success_data, "algorithm")
        algo_colors = {algo: cmap(i % 10) for i, algo in enumerate(algorithms)}

        result_dict, project_total = evaluate_precision_recall(precision_dict, recall_dict, inserted_dict, total)

        generate_plot_set(success_data, failure_data, args.outdir / project, project, algorithms, algo_colors)
        generate_dict_based_plots(result_dict, project_total, args.outdir / project, precision_dict, recall_dict)

        # The per-project report keeps code shared with other projects; the overall report
        # drops it here so each shared function is counted only once (in the first project).
        if cross_excluded[project]:
            print(f"[{project}] Reloading without cross-project duplicates for the overall report...")
            success_data, failure_data, precision_dict, recall_dict, inserted_dict, total = load_results(
                project_dir, excluded | cross_excluded[project], project=project
            )

        overall_success.extend(success_data)
        overall_failure.extend(failure_data)
        for algo, bins in precision_dict.items():
            overall_precision.setdefault(algo, {}).update(bins)
        for algo, bins in recall_dict.items():
            overall_recall.setdefault(algo, {}).update(bins)
        for algo, bins in inserted_dict.items():
            overall_inserted.setdefault(algo, {}).update(bins)
        for algo, vals in total.items():
            overall_total.setdefault(algo, [0, 0, 0, 0])[2] += vals[2]

    if not overall_success:
        print("No data found across any project. Exiting.")
        return

    print("\nGenerating aggregated 'overall' report across all projects...")
    overall_algorithms = get_unique(overall_success, "algorithm")
    overall_algo_colors = {algo: cmap(i % 10) for i, algo in enumerate(overall_algorithms)}

    overall_result_dict, overall_total_final = evaluate_precision_recall(overall_precision, overall_recall, overall_inserted, overall_total)

    generate_plot_set(overall_success, overall_failure, args.outdir / "overall", "overall", overall_algorithms, overall_algo_colors)
    generate_dict_based_plots(overall_result_dict, overall_total_final, args.outdir / "overall", overall_precision, overall_recall)

    print(f"\nAll plots saved to {args.outdir}/!")


if __name__ == "__main__":
    main()
