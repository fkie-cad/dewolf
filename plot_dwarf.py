#!/usr/bin/env python3
"""
plot_dwarf.py - Analyze and visualize variable-recovery evaluation results.

This script processes JSON files from a specific decompiler evaluation clip
and generates publication-quality plots using matplotlib.
"""

from pathlib import Path
import argparse
import json
import matplotlib.pyplot as plt
import numpy as np
import warnings
from collections import defaultdict

PRECISION_DICT = defaultdict(lambda:defaultdict(lambda :defaultdict(lambda:defaultdict(lambda:[])))) #Key: variable, Value: source
RECALL_DICT = defaultdict(lambda:defaultdict(lambda :defaultdict(lambda:defaultdict(lambda:[])))) #Key: source, Value: variable
INSERTED_DICT = defaultdict(lambda:defaultdict(lambda :defaultdict(lambda:defaultdict(lambda:[])))) #Key: variable, Value: lifted
RESULT_DICT = defaultdict(lambda:defaultdict(lambda:[]))
TOTAL = defaultdict(lambda: [0, 0, 0])


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

def load_results(clip_path: Path) -> list[dict]:
    """
    Load data for a single setup/clip directory.
    Ensures that only binaries present across ALL algorithm subdirectories are loaded.
    """
    data_rows = []
    
    if not clip_path.exists() or not clip_path.is_dir():
        warnings.warn(f"Input directory not found or invalid: {clip_path}")
        return data_rows

    clip_name = clip_path.name
    # Dynamically discover all directories as algorithm names
    algorithms = sorted([d.name for d in clip_path.iterdir() if d.is_dir()])
    
    if not algorithms:
        warnings.warn(f"No algorithm subdirectories found in {clip_path}")
        return data_rows
        
    algo_binaries = {}
    for algo in algorithms:
        algo_path = clip_path / algo
        algo_binaries[algo] = {p.stem: p for p in algo_path.glob("*.json")}
    
    # Strictly intersect so we only compare functions that ALL algorithms processed
    common_binaries = set(algo_binaries[algorithms[0]].keys())
    for algo in algorithms[1:]:
        common_binaries.intersection_update(algo_binaries[algo].keys())
        
    if not common_binaries:
        warnings.warn(f"No common binaries found across algorithms {algorithms} in {clip_path}.")
        return data_rows
        
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
                func_name for func_name, func_data in functions.items()
                if func_data.get("status") != "failed"
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
                if func_name not in commonFuncs[binary_name]:
                    continue  # Skip functions not common across all algorithms
                report = func_data.get("report") or {}
                status = func_data.get("status", "unknown")
                message = func_data.get("message") or ""
                
                # Parse failure stage from message if it exists
                fail_stage = "unknown"
                if status == "failed" and "failed at stage " in message:
                    fail_stage = message.split("failed at stage ")[-1].strip()
                
                row = {
                    "algorithm": algo,
                    "binary": binary_name,
                    "function": func_name,
                    "status": status,
                    "failure_stage": fail_stage,
                    "matched": report.get("matched", 0),
                    "total": report.get("total", 0),
                    "overmerged_count": safe_len(report.get("overmerged")),
                    "undermerged_count": safe_len(report.get("undermerged")),
                    "conflicts_count": safe_len(report.get("conflicts")),
                }
                
                variables = report.get("variables") or func_data.get("variables", [])
                by_kind = report.get("by_kind", {})
                
                if isinstance(variables, list) and len(variables) > 0 and isinstance(variables[0], dict):
                    calc_by_kind = defaultdict(lambda: {"matched": 0, "total": 0})
                    for v in variables:
                        # collect data for precision and recall calculations
                        if (v.get("source") is not None) and (v.get("variable") is not None):
                            PRECISION_DICT[algo][binary_name][func_name][v.get("variable")].append(v.get("source"))
                            RECALL_DICT[algo][binary_name][func_name][v.get("source")].append(v.get("variable"))
                        elif (v.get("variable") is not None):
                            INSERTED_DICT[algo][binary_name][func_name][v.get("variable")].append(v.get("lifted"))
                        TOTAL[algo][2] += 1

                        # normal processing for statistics
                        k = v.get("kind", "unknown")
                        calc_by_kind[k]["total"] += 1
                        
                        # Match heuristics: counts as matched if "source" is not null
                        is_matched = (
                            #v.get("matched") is True or 
                            #v.get("is_matched") is True or 
                            #bool(v.get("matched_to")) or 
                            #v.get("status") in ("success", "matched") or
                            v.get("source") is not None
                        )
                        if is_matched:
                            calc_by_kind[k]["matched"] += 1
                    
                    if any(k["total"] > 0 for k in calc_by_kind.values()):
                        by_kind = calc_by_kind
                
                for kind, kind_data in by_kind.items():
                    row[f"kind_{kind}_matched"] = kind_data.get("matched", 0)
                    row[f"kind_{kind}_total"] = kind_data.get("total", 0)
                
                data_rows.append(row)
                
    return data_rows

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
            ax.text(bar.get_x() + bar.get_width()/2, yval + 1, f"{yval:.1f}%", ha="center", va="bottom", fontsize=10)
            
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
        offset = (i - len(algorithms)/2 + 0.5) * width
        
        ax.bar(x + offset, kind_vals, width, label=algo, color=algo_colors[algo], edgecolor="black")
        for j, v in enumerate(kind_vals):
            ax.text(x[j] + offset, v + 1, f"{v:.1f}%", ha="center", va="bottom", fontsize=8, rotation=90)
                
    ax.set_ylabel("Match Rate (%)")
    ax.set_title(f"Variable Recovery Accuracy by Variable Kind\n(Folder: {clip_name})")
    ax.set_xticks(x)
    ax.set_xticklabels(kinds, rotation=45, ha="right")
    ax.legend(title="Algorithm", bbox_to_anchor=(1.05, 1), loc='upper left')
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
        
    for median in bp['medians']:
        median.set(color='black', linewidth=2)
        
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
                
        if not x_vals: continue
        
        color = algo_colors[algo]
        ax.scatter(x_vals, y_vals, alpha=0.3, s=20, color=color, edgecolor="none")
        
        if len(x_vals) > 5:
            try:
                z = np.polyfit(np.log10(x_vals), y_vals, 1)
                p = np.poly1d(z)
                slope = z[0]
                x_trend = np.logspace(np.log10(min(x_vals)), np.log10(max(x_vals)), 50)
                
                ax.plot(x_trend, p(np.log10(x_trend)), color=color, linewidth=2.5, solid_capstyle='round', label=f"{algo} (slope: {slope:.1f})")
            except np.linalg.LinAlgError:
                ax.plot([], [], color=color, label=f"{algo} (slope: N/A)")
        else:
            ax.plot([], [], color=color, label=f"{algo} (slope: N/A)")
                
    ax.set_xscale("log")
    ax.set_title(f"Accuracy Degradation vs. Function Complexity\n(Folder: {clip_name})")
    ax.set_xlabel("Function Variable Count (Log Scale)")
    ax.set_ylabel("Per-Function Match Rate (%)")
    ax.legend(title="Algorithm & Trendline Slope", bbox_to_anchor=(1.05, 1), loc='upper left')
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
                ax.text(bar.get_x() + bar.get_width()/2, h + (max_val * 0.01), str(int(h)), ha="center", va="bottom", fontsize=8)
                
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
    if not binaries: return
        
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
    """Generate a grouped bar chart of failure stages by algorithm."""
    failed_data = [r for r in data if r["status"] == "failed" and r["failure_stage"] != "unknown"]
    
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
        
        offset = (i - len(algorithms)/2 + 0.5) * width
        
        ax.bar(x + offset, stage_counts, width, label=algo, color=algo_colors[algo], edgecolor="black")
        for j, v in enumerate(stage_counts):
            if v > 0:
                ax.text(x[j] + offset, v + (max(stage_counts)*0.01), str(v), ha="center", va="bottom", fontsize=8)

    ax.set_ylabel("Number of Failed Functions")
    ax.set_title(f"Function Failure Modes by Decompilation Stage\n(Folder: {clip_name})")
    ax.set_xticks(x)
    ax.set_xticklabels(stages, rotation=45, ha="right")
    ax.legend(title="Algorithm", bbox_to_anchor=(1.05, 1), loc='upper left')
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    
    plt.tight_layout()
    plt.savefig(outdir / "07_failure_stages.png", dpi=150, bbox_inches="tight")
    plt.close()

def print_summary_table(data: list[dict], clip_name: str, algorithms: list) -> None:
    print("\n" + "=" * 110)
    print(f"VARIABLE RECOVERY EVALUATION SUMMARY - FOLDER: {clip_name}")
    print("=" * 110)
    max_algo_len = max(len(a) for a in algorithms)
    algo_col_width = max(15, max_algo_len + 2)
    
    header = f"{'Algorithm':<{algo_col_width}} {'Match %':>10} {'Binaries':>10} {'Functions':>10} {'Failed':>8} {'Overmerge':>10} {'Undermerge':>10}"
    print(header)
    print("-" * len(header))
    
    for algo in algorithms:
        group = [r for r in data if r["algorithm"] == algo]
        if not group: continue
            
        success_group = [r for r in group if r["status"] == "success"]
        total_bins = len(set(r["binary"] for r in group))
        total_funcs = len(group)
        failed_funcs = sum(1 for r in group if r["status"] != "success")
        total_overmerged = sum(r.get("overmerged_count", 0) for r in group)
        total_undermerged = sum(r.get("undermerged_count", 0) for r in group)
        match_rate = compute_micro_avg(success_group)
        
        print(f"{algo:<{algo_col_width}} {match_rate:>9.1f}% {total_bins:>10} "
              f"{total_funcs:>10} {failed_funcs:>8} {total_overmerged:>10} "
              f"{total_undermerged:>10}")
    print("=" * 110 + "\n")

def evaluate_precision_recall() -> None:
    for algorithm in PRECISION_DICT.keys():
        for binary in PRECISION_DICT[algorithm].keys():
            binary_Precision = 0
            total = 0
            overmerged_countVariable = 0
            overmerged_countSSA = 0
            for function in PRECISION_DICT[algorithm][binary].keys():
                for variable in PRECISION_DICT[algorithm][binary][function].keys():
                    if len(set(PRECISION_DICT[algorithm][binary][function][variable])) >= 2:
                        overmerged_countVariable += 1
                        overmerged_countSSA += len(PRECISION_DICT[algorithm][binary][function][variable])
                    TOTAL[algorithm][0] += 1
                    TOTAL[algorithm][1] += len(PRECISION_DICT[algorithm][binary][function][variable])
                    for Classvar in PRECISION_DICT[algorithm][binary][function][variable]:
                        total += 1
                        binary_Precision += (PRECISION_DICT[algorithm][binary][function][variable].count(Classvar) / len(PRECISION_DICT[algorithm][binary][function][variable]))
            if total > 0:
                binaryPrecision = (binary_Precision / total)
            else: 
                binaryPrecision = 0
            RESULT_DICT[algorithm][binary].append(binaryPrecision)
            RESULT_DICT[algorithm][binary].append(overmerged_countVariable)
            RESULT_DICT[algorithm][binary].append(overmerged_countSSA)

    for algorithm in RECALL_DICT.keys():
        for binary in RECALL_DICT[algorithm].keys():
            binary_Recall = 0
            total = 0
            for function in RECALL_DICT[algorithm][binary].keys():
                for source in RECALL_DICT[algorithm][binary][function].keys():
                    for Classvar in RECALL_DICT[algorithm][binary][function][source]:
                        total += 1
                        binary_Recall += (RECALL_DICT[algorithm][binary][function][source].count(Classvar) / len(RECALL_DICT[algorithm][binary][function][source]))
            if total > 0:
                binary_Recall = (binary_Recall / total)
            else:
                binary_Recall = 0
            RESULT_DICT[algorithm][binary].append(binary_Recall)

    for algorithm in RESULT_DICT.keys():
        for binary in RESULT_DICT[algorithm].keys():
            if len(RESULT_DICT[algorithm][binary]) == 4:
                precision,_,_, recall = RESULT_DICT[algorithm][binary]
                if (precision + recall) > 0:
                    f1_score = 2 * (precision * recall) / (precision + recall)
                else:
                    f1_score = 0
                RESULT_DICT[algorithm][binary].append(f1_score)

    for algorithm in INSERTED_DICT.keys():
        for binary in INSERTED_DICT[algorithm].keys():
            insertedCount = 0
            for function in INSERTED_DICT[algorithm][binary].keys():
                for variable in INSERTED_DICT[algorithm][binary][function].keys():
                    insertedCount += len(INSERTED_DICT[algorithm][binary][function][variable])
            RESULT_DICT[algorithm][binary].append(insertedCount)

def aggregateResults() -> dict:
    res = {}
    for algorithm in RESULT_DICT.keys():
        result = []
        total = 0
        for binary in RESULT_DICT[algorithm].keys():
            if len(RESULT_DICT[algorithm][binary]) == 6:
                result.append(RESULT_DICT[algorithm][binary])
                total += 1
        result = [sum(vals) for vals in zip(*result)]
        if total > 0:
            result = [result[0]/total,result[1],result[2],result[3]/total,result[4]/total,result[5]]
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
            raise ValueError(
                f"Alle Wertelisten müssen gleich lang sein, aber '{algo}' hat "
                f"{len(values)} statt {n_metrics} Werte."
            )
 
    if totals is not None:
        for algo in algorithms:
            if algo not in totals:
                raise ValueError(f"'{algo}' fehlt in totals.")
            if len(totals[algo]) != n_metrics:
                raise ValueError(
                    f"totals['{algo}'] hat {len(totals[algo])} statt {n_metrics} Werte."
                )
 
    if metric_names is None:
        metric_names = (
            DEFAULT_METRIC_NAMES
            if len(DEFAULT_METRIC_NAMES) == n_metrics
            else [f"Metrik {i + 1}" for i in range(n_metrics)]
        )
    elif len(metric_names) != n_metrics:
        raise ValueError(
            f"metric_names hat {len(metric_names)} Einträge, aber die Daten haben "
            f"{n_metrics} Werte pro Algorithmus."
        )
 
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

    METRIC_INDEX = {"precision": 0, "overmergedVariable":1, "overmergedSSA":2, "recall": 3, "f1": 4, "inserted":5}
    METRIC_LABEL = {"precision": "Precision", "overmergedVariable": "Overmerged Variables", "overmergedSSA": "Overmerged SSA Variables", "recall": "Recall", "f1": "F1 Score", "inserted": "Inserted Variables (no DWARF match)"}

    if metric not in METRIC_INDEX:
        raise ValueError(
            f"metric muss einer von {list(METRIC_INDEX)} sein, nicht '{metric}'"
        )
    if metric in ("overmergedVariable", "overmergedSSA", "inserted", "f1"):
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
            if values is not None:
                matrix[i, j] = values[idx] * scale

    minimum = np.min(matrix)
    maximum = np.max(matrix)
    fig_height = max(4, len(algorithms) * 1.0)
    fig_width = max(8, len(binaries) * 0.5)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    if metric in ("f1","overmergedVariable", "overmergedSSA", "inserted"):
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
                if metric in ("overmergedVariable", "overmergedSSA", "inserted", "f1"):
                    color = "white" if matrix[i, j] < (minimum + ((maximum - minimum)/2)) else "black"
                else:
                    color = "white" if matrix[i, j] < 50 else "black"
                if metric not in ("overmergedVariable", "overmergedSSA", "inserted", "f1"):
                    ax.text(
                        j, i, f"{matrix[i, j]:.1f}%",
                        ha="center", va="center",
                        color=color, fontsize=8,
                    )
                elif metric == "f1":
                    ax.text(
                        j, i, f"{matrix[i, j]:.3f}",
                        ha="center", va="center",
                        color=color, fontsize=8,
                    )
                else:
                    ax.text(
                    j, i, f"{int(matrix[i, j])}",
                    ha="center", va="center",
                    color=color, fontsize=8,
                    )

 
    cbar = plt.colorbar(im, ax=ax, fraction=0.02, pad=0.04)
    if metric in ("overmergedVariable", "overmergedSSA", "inserted", "f1"):
        cbar.set_label(f"{METRIC_LABEL[metric]}")
    else:
        cbar.set_label(f"{METRIC_LABEL[metric]} (%)")
 
    ax.set_title(title or f"{METRIC_LABEL[metric]} pro Algorithmus / Binary")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Analyze and visualize variable-recovery evaluation results.")
    parser.add_argument("--indir", type=Path, required=True, help="Path to the input directory (e.g., Results/resLP)")
    parser.add_argument("--outdir", type=Path, required=False, help="Output directory for plots")
    
    args = parser.parse_args()

    if not args.outdir:
        args.outdir = args.indir.parent / f"Plots"

    args.outdir.mkdir(parents=True, exist_ok=True)
    
    print(f"Loading data from {args.indir}...")
    all_data = load_results(args.indir)
    
    if not all_data:
        print("No data found or processed. Exiting.")
        return
        
    clip_name = args.indir.name
    algorithms = get_unique(all_data, "algorithm")
    
    cmap = plt.get_cmap("tab10")
    algo_colors = {algo: cmap(i % 10) for i, algo in enumerate(algorithms)}
    
    print_summary_table(all_data, clip_name, algorithms)
    
    success_data = [row for row in all_data if row["status"] == "success"]
    
    print("Generating plots...")
    plot_overall_accuracy(success_data, args.outdir, clip_name, algorithms, algo_colors)
    print("  - 01_overall_accuracy.png -> Coverage")
    
    plot_accuracy_by_kind(success_data, args.outdir, clip_name, algorithms, algo_colors)
    print("  - 02_accuracy_by_kind.png")
    
    plot_per_function_distribution(success_data, args.outdir, clip_name, algorithms, algo_colors)
    print("  - 03_per_function_distribution.png")
    
    plot_accuracy_vs_complexity(success_data, args.outdir, clip_name, algorithms, algo_colors)
    print("  - 04_accuracy_vs_complexity.png")
    
    plot_error_modes(all_data, args.outdir, clip_name, algorithms)
    print("  - 05_error_modes.png")
    
    plot_per_binary_heatmap(success_data, args.outdir, clip_name, algorithms)
    print("  - 06_per_binary_heatmap.png")
    
    plot_failure_stages(all_data, args.outdir, clip_name, algorithms, algo_colors)
    print("  - 07_failure_stages.png")

    #print("Calculating precision and recall metrics...")
    evaluate_precision_recall()

    print("  - 08_precision_heatmap.png")
    plot_heatmap(data=RESULT_DICT, metric="precision", save_path=args.outdir / "08_precision_heatmap.png", title=f"Precision per Algorithm / Binary")
    
    print("  - 09_recall_heatmap.png")
    plot_heatmap(data=RESULT_DICT, metric="recall", save_path=args.outdir / "09_recall_heatmap.png", title=f"Recall per Algorithm / Binary")
    
    print("  - 10_f1_heatmap.png")
    plot_heatmap(data=RESULT_DICT, metric="f1", save_path=args.outdir / "10_f1_heatmap.png", title=f"F1 Score per Algorithm / Binary")

    print("  - 11_overmergedVariable_heatmap.png")
    plot_heatmap(data=RESULT_DICT, metric="overmergedVariable", save_path=args.outdir / "11_overmergedVariable_heatmap.png", title=f"Overmerged Variables per Algorithm / Binary")

    print("  - 12_overmergedSSA_heatmap.png")
    plot_heatmap(data=RESULT_DICT, metric="overmergedSSA", save_path=args.outdir / "12_overmergedSSA_heatmap.png", title=f"Overmerged SSA Variables per Algorithm / Binary")

    print("  - 13_inserted_heatmap.png")
    plot_heatmap(data=RESULT_DICT, metric="inserted", save_path=args.outdir / "13_inserted_heatmap.png", title=f"Inserted SSA-Variables (no DWARF match) per Algorithm / Binary")

    agregated_results = aggregateResults()
    step1 = {algo: [100 * vals[0], 100 * vals[3], 100 * vals[4]] for algo, vals in agregated_results.items()}  # Precision, Recall, F1
    print("  - 14_average_metrics.png")
    plot_grouped_metrics(data=step1, save_path=args.outdir / "14_average_metrics.png", title=f"Average Metrics per Algorithm", metric_names=["Precision", "Recall", "F1 Score"])

    step2 = {algo: [vals[1]] for algo, vals in agregated_results.items()}  # Overmerged Variables
    totals_step2 = {algo: [vals[0]] for algo, vals in TOTAL.items()}  
    print("  - 15_aggregated_overmerged.png")
    plot_grouped_metrics(data=step2, save_path=args.outdir / "15_aggregated_overmerged.png", title=f"Aggregated Overmerged Variables per Algorithm", metric_names=["Overmerged Variables"], percent=False,group_gap=0.01, totals=totals_step2)

    step3 = {algo: [vals[5]] for algo, vals in agregated_results.items()}  # Inserted SSA-Variables
    step3_totals = {algo: [vals[2]] for algo, vals in TOTAL.items()}
    print("  - 16_aggregated_inserted.png")
    plot_grouped_metrics(data=step3, save_path=args.outdir / "16_aggregated_inserted.png", title=f"Aggregated Inserted SSA-Variables (no DWARF match) per Algorithm", metric_names=["Inserted SSA-Variables"], percent=False,group_gap=0.01, totals=step3_totals)

    print(f"\nAll plots saved to {args.outdir}/!")

if __name__ == "__main__":
    main()
