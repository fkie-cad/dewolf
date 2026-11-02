#!/usr/bin/env python3
import argparse
import json
import os
import traceback
from collections import defaultdict
from typing import Optional

import matplotlib
matplotlib.use("Agg")  # headless/non-interactive backend
import matplotlib.pyplot as plt


DPI = 200

COLOR_INTERFERING = "#C44E52"
COLOR_NON_INTERFERING = "#4C72B0"
COLOR_DENSITY = "#55A868"
COLOR_DEPENDENCY = "#8172B2"

# 4-way breakdown colors: interference status x dependency status
COLOR_INTERFERING_DEPENDENT = "#C44E52"
COLOR_INTERFERING_ONLY = "#E8A0A6"
COLOR_NON_INTERFERING_DEPENDENT = "#4C72B0"
COLOR_NON_INTERFERING_ONLY = "#A9C2E0"


def parse_top_n(val: str) -> Optional[int]:
    """Accept either 'all' or a positive integer."""
    if val.lower() == "all":
        return None

    try:
        n = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid top_n value: '{val}'. Must be a positive integer or 'all'."
        )

    if n <= 0:
        raise argparse.ArgumentTypeError(
            "top_n must be a positive integer or 'all'."
        )

    return n

def find_json_files(input_folder: str) -> list:
    json_files = []

    for root, _dirs, files in os.walk(input_folder):
        for fname in files:
            if fname.endswith(".json"):
                json_files.append(os.path.join(root, fname))

    return sorted(json_files)


def load_all_data(input_folder: str):
    """Loads every {binary}.json under input_folder without modifying them.

    Returns:
        binaries: list of {"binary": name, "summary": {...}, "functions": [...], "path": path}
        sets_records: flattened list of dicts, one per undermerged set, using
            only the fields the generation script actually stores per set:
            source, group_size, has_interference, has_dependency,
            dependency_density.
    """
    binaries = []
    sets_records = []

    json_files = find_json_files(input_folder)
    print(f"--- Found {len(json_files)} JSON files under {input_folder} ---")

    for path in json_files:
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except Exception:
            print(
                f"[!] Skipping malformed JSON file {path}:\n"
                f"{traceback.format_exc()}"
            )
            continue

        binary = (
            data.get("binary")
            or os.path.splitext(os.path.basename(path))[0]
        )

        functions = data.get("functions", [])
        summary = data["summary"]

        function_count = summary["function_count"]
        undermerged_count = summary["undermerged_count"]

        # Skip the binary BEFORE flattening its undermerged sets.
        # This keeps `binaries` and `sets_records` consistent.
        if function_count == 0:
            print(
                f"[i] Skipping binary '{binary}' ({path}): "
                "no processed functions (function_count=0)."
            )
            continue

        if undermerged_count == 0:
            print(
                f"[i] Skipping binary '{binary}' ({path}): "
                "no undermerged sources found (undermerged_count=0)."
            )
            continue

        # Build this file's records separately. If flattening fails partway
        # through, none of the partial records are added to sets_records.
        file_sets = []

        try:
            for func in functions:
                func_name = func.get(
                    "function_name",
                    "UNKNOWN_FUNC",
                )

                for s in func.get("undermerged_sets", []):
                    file_sets.append({
                        "binary": binary,
                        "function": func_name,
                        "source": s.get(
                            "source",
                            "UNKNOWN_SRC",
                        ),
                        "group_size": s["group_size"],
                        "has_interference": s["has_interference"],
                        "has_dependency": s["has_dependency"],
                        "dependency_density": s["dependency_density"],
                        "lifted_vars": s["lifted_vars"],
                    })

        except Exception:
            print(
                f"[!] Error while flattening undermerged sets from {path}:\n"
                f"{traceback.format_exc()}"
            )
            continue

        # Only commit this file's records after successful flattening.
        sets_records.extend(file_sets)

        binaries.append({
            "binary": binary,
            "summary": summary,
            "functions": functions,
            "path": path,
        })

    return binaries, sets_records


# --------------------------------------------------------------------------
# Plot 1: undermerged group-size distribution (4-way breakdown)
# --------------------------------------------------------------------------

def plot_group_size_distribution(
    sets_records: list,
    binaries: list,
    output_folder: str,
):
    if not sets_records:
        print(
            "[!] No undermerged sets found; "
            "skipping group-size distribution plot."
        )
        return

    int_dep = [
        r["group_size"]
        for r in sets_records
        if r["has_interference"] and r["has_dependency"]
    ]

    int_only = [
        r["group_size"]
        for r in sets_records
        if r["has_interference"] and not r["has_dependency"]
    ]

    noint_dep = [
        r["group_size"]
        for r in sets_records
        if not r["has_interference"] and r["has_dependency"]
    ]

    noint_only = [
        r["group_size"]
        for r in sets_records
        if not r["has_interference"] and not r["has_dependency"]
    ]

    # The largest undermerged group size, per binary, is already computed
    # and stored by the generation script (summary["largest_undermerged_set"]).
    # The global max across all loaded binaries is just the max of those.
    max_size = max(
        b["summary"]["largest_undermerged_set"]
        for b in binaries
    )

    bins = list(range(2, max_size + 2))

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.hist(
        [
            noint_only,
            noint_dep,
            int_only,
            int_dep,
        ],
        bins=bins,
        label=[
            "Non-interfering only",
            "Non-interfering + dependent",
            "Interfering only",
            "Interfering + dependent",
        ],
        color=[
            COLOR_NON_INTERFERING_ONLY,
            COLOR_NON_INTERFERING_DEPENDENT,
            COLOR_INTERFERING_ONLY,
            COLOR_INTERFERING_DEPENDENT,
        ],
        align="left",
        rwidth=0.85,
    )

    ax.set_xlabel("Undermerged group size")
    ax.set_ylabel("Number of undermerged sets")
    ax.set_title(
        "Distribution of undermerged group sizes "
        "by interference and dependency status"
    )
    ax.legend(fontsize=9)

    fig.tight_layout()
    fig.savefig(
        os.path.join(
            output_folder,
            "undermerged_group_size_distribution.png",
        ),
        dpi=DPI,
    )
    plt.close(fig)


# --------------------------------------------------------------------------
# Plot 2: interference x dependency breakdown (counts + %)
# --------------------------------------------------------------------------

def plot_interference_dependency_breakdown(
    sets_records: list,
    binaries: list,
    output_folder: str,
):
    if not sets_records:
        print(
            "[!] No undermerged sets found; "
            "skipping interference/dependency breakdown plot."
        )
        return

    # Total undermerged sets across all loaded binaries is already stored
    # per binary (summary["undermerged_count"]); sum those instead of
    # re-deriving the count from the flattened records.
    total = sum(
        b["summary"]["undermerged_count"]
        for b in binaries
    )

    # The 4-way cross-tabulation (interfering x dependent) isn't stored
    # anywhere in the JSON -- only the per-set booleans are -- so this
    # still has to be tallied from the flattened records.
    n_int_dep = sum(
        1
        for r in sets_records
        if r["has_interference"] and r["has_dependency"]
    )

    n_int_only = sum(
        1
        for r in sets_records
        if r["has_interference"] and not r["has_dependency"]
    )

    n_noint_dep = sum(
        1
        for r in sets_records
        if not r["has_interference"] and r["has_dependency"]
    )

    n_noint_only = sum(
        1
        for r in sets_records
        if not r["has_interference"] and not r["has_dependency"]
    )

    labels = [
        "Interfering\n+ dependent",
        "Interfering\nonly",
        "Non-interfering\n+ dependent",
        "Non-interfering\nonly",
    ]

    counts = [
        n_int_dep,
        n_int_only,
        n_noint_dep,
        n_noint_only,
    ]

    colors = [
        COLOR_INTERFERING_DEPENDENT,
        COLOR_INTERFERING_ONLY,
        COLOR_NON_INTERFERING_DEPENDENT,
        COLOR_NON_INTERFERING_ONLY,
    ]

    fig, axes = plt.subplots(
        1,
        2,
        figsize=(12, 5.5),
    )

    ax = axes[0]

    bars = ax.bar(
        labels,
        counts,
        color=colors,
    )

    ax.set_ylabel("Number of undermerged sets")
    ax.set_title("Counts")

    for b in bars:
        ax.annotate(
            str(int(b.get_height())),
            (
                b.get_x() + b.get_width() / 2,
                b.get_height(),
            ),
            ha="center",
            va="bottom",
        )

    ax2 = axes[1]

    pcts = [
        100 * c / total if total else 0.0
        for c in counts
    ]

    bars2 = ax2.bar(
        labels,
        pcts,
        color=colors,
    )

    ax2.set_ylabel("Percentage of undermerged sets (%)")
    ax2.set_ylim(0, 100)
    ax2.set_title("Percentages")

    for b in bars2:
        ax2.annotate(
            f"{b.get_height():.1f}%",
            (
                b.get_x() + b.get_width() / 2,
                b.get_height(),
            ),
            ha="center",
            va="bottom",
        )

    for a in axes:
        a.tick_params(
            axis="x",
            labelsize=8,
        )

    fig.suptitle(
        "Undermerged sets by interference and dependency status"
    )

    fig.tight_layout()
    fig.savefig(
        os.path.join(
            output_folder,
            "interference_dependency_breakdown.png",
        ),
        dpi=DPI,
    )
    plt.close(fig)


# --------------------------------------------------------------------------
# Plots 3 & 4: largest non-interfering / interfering undermerged groups
# --------------------------------------------------------------------------

def _top_groups(
    sets_records: list,
    has_interference: bool,
    top_n: Optional[int],
) -> list:
    filtered = [
        r
        for r in sets_records
        if r["has_interference"] == has_interference
    ]

    filtered.sort(
        key=lambda r: r["group_size"],
        reverse=True,
    )

    return filtered[:top_n]


def plot_top_groups(
    sets_records: list,
    output_folder: str,
    has_interference: bool,
    filename: str,
    title_suffix: str,
    top_n: Optional[int] = None,
):
    top = _top_groups(
        sets_records,
        has_interference,
        top_n,
    )

    if not top:
        print(
            f"[!] No undermerged sets match "
            f"has_interference={has_interference}; "
            f"skipping '{filename}'."
        )
        return

    labels = [
        f"{r['binary']} :: {r['function']} :: {r['source']}"
        for r in top
    ]

    sizes = [
        r["group_size"]
        for r in top
    ]

    hatches = [
        "//" if r["has_dependency"] else None
        for r in top
    ]

    color = (
        COLOR_INTERFERING
        if has_interference
        else COLOR_NON_INTERFERING
    )

    fig_height = max(
        4.0,
        0.4 * len(top) + 1.5,
    )

    fig, ax = plt.subplots(
        figsize=(12, fig_height)
    )

    y_pos = range(len(top))

    bars = ax.barh(
        y_pos,
        sizes,
        color=color,
    )

    for bar, hatch in zip(bars, hatches):
        if hatch:
            bar.set_hatch(hatch)
            bar.set_edgecolor("black")

    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(
        labels,
        fontsize=7,
    )

    ax.invert_yaxis()

    ax.set_xlabel("Group size")

    header_title = (
        f"Top {len(top)}"
        if top_n is not None
        else f"All ({len(top)})"
    )

    ax.set_title(
        f"{header_title} {title_suffix}\n"
        "(hatched bars also have dependency)"
    )

    fig.tight_layout()
    fig.savefig(
        os.path.join(
            output_folder,
            filename,
        ),
        dpi=DPI,
    )
    plt.close(fig)


# --------------------------------------------------------------------------
# Plot 5a: per-binary breakdown (4-way)
# --------------------------------------------------------------------------

def plot_per_binary_breakdown(
    sets_records: list,
    binaries: list,
    output_folder: str,
):
    per_binary = {}

    for r in sets_records:
        name = r["binary"]

        bucket = per_binary.setdefault(
            name,
            {
                "int_dep": 0,
                "int_only": 0,
                "noint_dep": 0,
                "noint_only": 0,
            },
        )

        if r["has_interference"] and r["has_dependency"]:
            bucket["int_dep"] += 1
        elif r["has_interference"]:
            bucket["int_only"] += 1
        elif r["has_dependency"]:
            bucket["noint_dep"] += 1
        else:
            bucket["noint_only"] += 1

    if not per_binary:
        print(
            "[!] No binaries found; "
            "skipping per-binary breakdown plot."
        )
        return

    # Each binary's total undermerged-set count is already stored
    # (summary["undermerged_count"]); use it to rank binaries instead of
    # re-summing the 4-way buckets built above.
    totals_by_binary = {
        b["binary"]: b["summary"]["undermerged_count"]
        for b in binaries
    }

    names = sorted(
        per_binary.keys(),
        key=lambda n: totals_by_binary[n],
        reverse=True,
    )

    int_dep = [
        per_binary[n]["int_dep"]
        for n in names
    ]

    int_only = [
        per_binary[n]["int_only"]
        for n in names
    ]

    noint_dep = [
        per_binary[n]["noint_dep"]
        for n in names
    ]

    noint_only = [
        per_binary[n]["noint_only"]
        for n in names
    ]

    fig_width = max(
        8.0,
        0.5 * len(names) + 2,
    )

    fig, ax = plt.subplots(
        figsize=(fig_width, 6)
    )

    x = range(len(names))
    bottom = [0] * len(names)

    for vals, color, label in [
        (
            noint_only,
            COLOR_NON_INTERFERING_ONLY,
            "Non-interfering only",
        ),
        (
            noint_dep,
            COLOR_NON_INTERFERING_DEPENDENT,
            "Non-interfering + dependent",
        ),
        (
            int_only,
            COLOR_INTERFERING_ONLY,
            "Interfering only",
        ),
        (
            int_dep,
            COLOR_INTERFERING_DEPENDENT,
            "Interfering + dependent",
        ),
    ]:
        ax.bar(
            x,
            vals,
            bottom=bottom,
            label=label,
            color=color,
        )

        bottom = [
            b + v
            for b, v in zip(bottom, vals)
        ]

    ax.set_xticks(list(x))
    ax.set_xticklabels(
        names,
        rotation=45,
        ha="right",
        fontsize=8,
    )

    ax.set_ylabel("Number of undermerged sets")
    ax.set_title(
        "Undermerged sets per binary, "
        "by interference and dependency status"
    )

    ax.legend(fontsize=8)

    fig.tight_layout()
    fig.savefig(
        os.path.join(
            output_folder,
            "undermerging_per_binary.png",
        ),
        dpi=DPI,
    )
    plt.close(fig)


# --------------------------------------------------------------------------
# Plot 5b: per-function breakdown (4-way)
# --------------------------------------------------------------------------

def plot_per_function_breakdown(
    sets_records: list,
    binaries: list,
    output_folder: str,
    top_n: Optional[int] = None,
):
    per_func = {}

    for r in sets_records:
        name = f"{r['binary']} :: {r['function']}"

        bucket = per_func.setdefault(
            name,
            {
                "int_dep": 0,
                "int_only": 0,
                "noint_dep": 0,
                "noint_only": 0,
            },
        )

        if r["has_interference"] and r["has_dependency"]:
            bucket["int_dep"] += 1
        elif r["has_interference"]:
            bucket["int_only"] += 1
        elif r["has_dependency"]:
            bucket["noint_dep"] += 1
        else:
            bucket["noint_only"] += 1

    if not per_func:
        print(
            "[!] No functions found; "
            "skipping per-function breakdown plot."
        )
        return

    # Each function's total undermerged-set count is already stored
    # (functions[i]["undermerged_count"]); use it to rank functions instead
    # of re-summing the 4-way buckets built above.
    totals_by_func = {}

    for b in binaries:
        for fr in b["functions"]:
            key = f"{b['binary']} :: {fr['function_name']}"
            totals_by_func[key] = fr["undermerged_count"]

    names = sorted(
        per_func.keys(),
        key=lambda n: totals_by_func[n],
        reverse=True,
    )[:top_n]

    int_dep = [
        per_func[n]["int_dep"]
        for n in names
    ]

    int_only = [
        per_func[n]["int_only"]
        for n in names
    ]

    noint_dep = [
        per_func[n]["noint_dep"]
        for n in names
    ]

    noint_only = [
        per_func[n]["noint_only"]
        for n in names
    ]

    fig_width = max(
        8.0,
        0.45 * len(names) + 2,
    )

    fig, ax = plt.subplots(
        figsize=(fig_width, 6.5)
    )

    x = range(len(names))
    bottom = [0] * len(names)

    for vals, color, label in [
        (
            noint_only,
            COLOR_NON_INTERFERING_ONLY,
            "Non-interfering only",
        ),
        (
            noint_dep,
            COLOR_NON_INTERFERING_DEPENDENT,
            "Non-interfering + dependent",
        ),
        (
            int_only,
            COLOR_INTERFERING_ONLY,
            "Interfering only",
        ),
        (
            int_dep,
            COLOR_INTERFERING_DEPENDENT,
            "Interfering + dependent",
        ),
    ]:
        ax.bar(
            x,
            vals,
            bottom=bottom,
            label=label,
            color=color,
        )

        bottom = [
            b + v
            for b, v in zip(bottom, vals)
        ]

    ax.set_xticks(list(x))
    ax.set_xticklabels(
        names,
        rotation=45,
        ha="right",
        fontsize=7,
    )

    ax.set_ylabel("Number of undermerged sets")

    header = (
        f"Top {len(names)}"
        if top_n is not None
        else f"All ({len(names)})"
    )

    ax.set_title(
        f"{header} functions: "
        "Undermerged sets by interference and dependency status"
    )

    ax.legend(fontsize=8)

    fig.tight_layout()
    fig.savefig(
        os.path.join(
            output_folder,
            "undermerging_per_function.png",
        ),
        dpi=DPI,
    )
    plt.close(fig)


# --------------------------------------------------------------------------
# Plots 6a & 6b: undermerged group-size distribution per binary / function
# --------------------------------------------------------------------------

def _size_distribution_colors(sizes: list) -> dict:
    """Assigns a stable color to each distinct group size, using the same
    color for a given size across the counts and percentage subplots."""
    n = len(sizes)

    if n == 0:
        return {}

    return {
        size: plt.cm.viridis(i / max(n - 1, 1))
        for i, size in enumerate(sizes)
    }


def _plot_stacked_size_distribution(
    entries: list,
    output_folder: str,
    filename: str,
    suptitle: str,
):
    """Shared renderer for the per-binary / per-function size-distribution
    plots. `entries` is a list of (label, group_size_counts, total) tuples,
    where group_size_counts is {int size: count} and total is the entry's
    total undermerged-set count -- both read directly from the JSON, not
    recomputed from individual records.
    """

    if not entries:
        print(
            f"[!] No entries to plot for '{filename}'; skipping."
        )
        return

    all_sizes = sorted({
        size
        for _, counts, _ in entries
        for size in counts.keys()
    })

    colors = _size_distribution_colors(all_sizes)

    labels = [e[0] for e in entries]

    fig_width = max(10.0, 0.5 * len(labels) + 2)

    fig, axes = plt.subplots(
        1,
        2,
        figsize=(fig_width, 6.5),
    )

    x = range(len(labels))

    # ------------------------------------------------------------------
    # Subplot 1: absolute counts per size, stacked per entry.
    # ------------------------------------------------------------------

    ax = axes[0]
    bottom = [0] * len(labels)

    for size in all_sizes:
        vals = [
            counts.get(size, 0)
            for _, counts, _ in entries
        ]

        ax.bar(
            x,
            vals,
            bottom=bottom,
            color=colors[size],
            label=f"size {size}",
        )

        bottom = [
            b + v
            for b, v in zip(bottom, vals)
        ]

    ax.set_xticks(list(x))
    ax.set_xticklabels(
        labels,
        rotation=45,
        ha="right",
        fontsize=7,
    )
    ax.set_ylabel("Number of undermerged sets")
    ax.set_title("Counts")

    # ------------------------------------------------------------------
    # Subplot 2: same breakdown, normalized to 100% per entry.
    # ------------------------------------------------------------------

    ax2 = axes[1]
    bottom2 = [0.0] * len(labels)

    for size in all_sizes:
        vals = [
            100 * counts.get(size, 0) / total if total else 0.0
            for _, counts, total in entries
        ]

        ax2.bar(
            x,
            vals,
            bottom=bottom2,
            color=colors[size],
            label=f"size {size}",
        )

        bottom2 = [
            b + v
            for b, v in zip(bottom2, vals)
        ]

    ax2.set_xticks(list(x))
    ax2.set_xticklabels(
        labels,
        rotation=45,
        ha="right",
        fontsize=7,
    )
    ax2.set_ylabel("Percentage of undermerged sets (%)")
    ax2.set_ylim(0, 100)
    ax2.set_title("Percentages")

    handles, leg_labels = ax.get_legend_handles_labels()
    fig.legend(
        handles,
        leg_labels,
        loc="upper center",
        ncol=min(len(all_sizes), 12),
        fontsize=7,
        bbox_to_anchor=(0.5, 1.04),
    )

    fig.suptitle(suptitle, y=1.1)

    fig.tight_layout()
    fig.savefig(
        os.path.join(
            output_folder,
            filename,
        ),
        dpi=DPI,
        bbox_inches="tight",
    )
    plt.close(fig)


def plot_binary_size_distribution(
    binaries: list,
    output_folder: str,
):
    """For each binary: how many undermerged sets of each size it has, in
    both absolute counts and percentages. Reads each binary's
    `group_size_counts` and `undermerged_count` directly from its summary
    rather than re-tallying individual undermerged sets."""

    entries = [
        (
            b["binary"],
            {int(size): count for size, count in b["summary"]["group_size_counts"].items()},
            b["summary"]["undermerged_count"],
        )
        for b in binaries
    ]

    entries.sort(key=lambda e: e[2], reverse=True)

    _plot_stacked_size_distribution(
        entries,
        output_folder,
        "undermerged_size_distribution_per_binary.png",
        "Undermerged group-size distribution per binary",
    )


def plot_function_size_distribution(
    binaries: list,
    output_folder: str,
    top_n: Optional[int] = None,
):
    """For each function: how many undermerged sets of each size it has, in
    both absolute counts and percentages. Reads each function's
    `group_size_counts` and `undermerged_count` directly from the JSON
    rather than re-tallying individual undermerged sets."""

    entries = [
        (
            f"{b['binary']} :: {fr['function_name']}",
            {int(size): count for size, count in fr["group_size_counts"].items()},
            fr["undermerged_count"],
        )
        for b in binaries
        for fr in b["functions"]
        if fr["undermerged_count"] > 0
    ]

    entries.sort(key=lambda e: e[2], reverse=True)
    entries = entries[:top_n]

    header = (
        f"Top {len(entries)}"
        if top_n is not None
        else f"All ({len(entries)})"
    )

    _plot_stacked_size_distribution(
        entries,
        output_folder,
        "undermerged_size_distribution_per_function.png",
        f"{header} functions: undermerged group-size distribution",
    )


# --------------------------------------------------------------------------
# Plot 6c: average lifted_vars by undermerged group size
# --------------------------------------------------------------------------

def plot_avg_lifted_vars_by_size(
    sets_records: list,
    output_folder: str,
):
    """For each undermerged group size n, plots the average `lifted_vars`
    (sum over the group's variables of how many distinct lifted nodes each
    maps to) across all undermerged sets of that size, split into the same
    four interference/dependency categories used in the other breakdown
    plots.

    `lifted_vars`, `has_interference`, and `has_dependency` are all read
    directly per set (already computed by the generation script); only the
    grouping-by-size-and-category and the average within each group are
    computed here, since no binary's JSON knows about sets from other
    binaries of the same size/category.
    """

    if not sets_records:
        print(
            "[!] No undermerged sets found; "
            "skipping avg lifted_vars by size plot."
        )
        return

    categories = [
        (
            "int_dep",
            lambda r: r["has_interference"] and r["has_dependency"],
            COLOR_INTERFERING_DEPENDENT,
            "Interfering + dependent",
        ),
        (
            "int_only",
            lambda r: r["has_interference"] and not r["has_dependency"],
            COLOR_INTERFERING_ONLY,
            "Interfering only",
        ),
        (
            "noint_dep",
            lambda r: not r["has_interference"] and r["has_dependency"],
            COLOR_NON_INTERFERING_DEPENDENT,
            "Non-interfering + dependent",
        ),
        (
            "noint_only",
            lambda r: not r["has_interference"] and not r["has_dependency"],
            COLOR_NON_INTERFERING_ONLY,
            "Non-interfering only",
        ),
    ]

    by_size_category = defaultdict(lambda: defaultdict(list))

    for r in sets_records:
        for key, pred, _color, _label in categories:
            if pred(r):
                by_size_category[r["group_size"]][key].append(
                    r["lifted_vars"]
                )
                break

    sizes = sorted(by_size_category.keys())

    n_cats = len(categories)
    bar_width = 0.8 / n_cats
    x = list(range(len(sizes)))

    fig, ax = plt.subplots(
        figsize=(max(10.0, 1.2 * len(sizes) + 2), 6.5)
    )

    for i, (key, _, color, label) in enumerate(categories):
        avgs = []
        counts = []

        for s in sizes:
            vals = by_size_category[s].get(key, [])
            avgs.append(
                sum(vals) / len(vals)
                if vals
                else 0.0
            )
            counts.append(len(vals))

        offsets = [
            xi + (i - (n_cats - 1) / 2) * bar_width
            for xi in x
        ]

        bars = ax.bar(
            offsets,
            avgs,
            width=bar_width,
            color=color,
            label=label,
        )

        for bar, n in zip(bars, counts):
            if n > 0:
                ax.annotate(
                    f"n={n}",
                    (
                        bar.get_x() + bar.get_width() / 2,
                        bar.get_height(),
                    ),
                    ha="center",
                    va="bottom",
                    fontsize=6,
                    rotation=90,
                )

    ax.set_xticks(x)
    ax.set_xticklabels([str(s) for s in sizes])

    ax.set_xlabel("Undermerged group size")
    ax.set_ylabel("Average ssa variables")
    ax.set_title(
        "Average total ssa variable count (summed over the group) "
        "by undermerged group size\nand interference/dependency status"
    )
    ax.legend(fontsize=8)

    fig.tight_layout()
    fig.savefig(
        os.path.join(
            output_folder,
            "avg_lifted_vars_by_group_size.png",
        ),
        dpi=DPI,
    )
    plt.close(fig)


# --------------------------------------------------------------------------
# Plot 6: Overall Interference Density per Binary + Two Global Averages
# --------------------------------------------------------------------------

def plot_per_binary_interference_density(
    binaries: list,
    output_folder: str,
):
    """Plots interference density for each binary.

    Includes:
      - unweighted average across binaries
      - weighted average across binaries, weighted by undermerged_count

    Both averages are genuinely batch-level (they depend on which binaries
    were loaded together in this run), so they can't come from any single
    binary's JSON and are computed here. The per-binary density and weight
    values themselves are read directly from each binary's summary.
    """
    if not binaries:
        print(
            "[!] No binaries found; "
            "skipping per-binary interference density plot."
        )
        return

    names = [
        b["binary"]
        for b in binaries
    ]

    inter_densities = [
        b["summary"]["overall_interference_density"]
        for b in binaries
    ]

    weights = [
        b["summary"]["undermerged_count"]
        for b in binaries
    ]

    # Average giving every binary equal weight.
    unweighted_avg = (
        sum(inter_densities) / len(inter_densities)
        if inter_densities
        else 0.0
    )

    # Average giving binaries with more undermerged sets proportionally
    # more weight.
    total_weight = sum(weights)

    weighted_avg = (
        sum(
            density * weight
            for density, weight in zip(
                inter_densities,
                weights,
            )
        )
        / total_weight
        if total_weight
        else 0.0
    )

    fig_width = max(
        8.0,
        0.5 * len(names) + 2,
    )

    fig, ax = plt.subplots(
        figsize=(fig_width, 6)
    )

    x = list(range(len(names)))

    bars = ax.bar(
        x,
        inter_densities,
        width=0.45,
        color=COLOR_INTERFERING,
        label="Interference density",
    )

    # Unweighted average: each binary contributes equally.
    ax.axhline(
        unweighted_avg,
        color="gray",
        linestyle=":",
        linewidth=1.5,
        label=f"Avg across binaries ({unweighted_avg:.3f})",
    )

    # Weighted average: binaries contribute according to their number
    # of undermerged sets.
    ax.axhline(
        weighted_avg,
        color="black",
        linestyle="--",
        linewidth=1.5,
        label=f"Weighted avg ({weighted_avg:.3f})",
    )

    ax.set_xticks(x)

    ax.set_xticklabels(
        names,
        rotation=45,
        ha="right",
        fontsize=8,
    )

    ax.set_ylabel("Interference Density (0.0 - 1.0)")
    ax.set_ylim(0, 1.05)

    ax.set_title(
        "Overall Interference Density per Binary"
    )

    for b in bars:
        h = b.get_height()

        ax.annotate(
            f"{h:.2f}",
            (
                b.get_x() + b.get_width() / 2,
                h,
            ),
            ha="center",
            va="bottom",
            fontsize=7,
        )

    ax.legend(fontsize=8)

    fig.tight_layout()
    fig.savefig(
        os.path.join(
            output_folder,
            "per_binary_interference_density.png",
        ),
        dpi=DPI,
    )
    plt.close(fig)


# --------------------------------------------------------------------------
# Plot 7: Dependency Density of (Non-Interfering + Dependent) Sets
# --------------------------------------------------------------------------

def plot_non_interfering_dependent_density(
    sets_records: list,
    output_folder: str,
):
    """Analyzes dependency density specifically for
    'non-interfering + dependent' undermerged sets.

    Shows:
      - distribution of dependency density across qualifying sets
      - average dependency density per binary
      - overall average across qualifying sets
      - weighted average across binary averages

    None of these averages are restricted to this particular subset of
    sets anywhere in the generation script's output, so they have to be
    computed here from the per-set dependency_density values (which are
    read directly, not recomputed).
    """
    target_sets = [
        r
        for r in sets_records
        if not r["has_interference"] and r["has_dependency"]
    ]

    if not target_sets:
        print(
            "[!] No non-interfering + dependent sets found; "
            "skipping plot."
        )
        return

    densities = [
        r["dependency_density"]
        for r in target_sets
    ]

    # This is the direct average over all qualifying sets.
    overall_avg = sum(densities) / len(densities)

    # Group by binary.
    binary_densities = defaultdict(list)

    for r in target_sets:
        binary_densities[r["binary"]].append(
            r["dependency_density"]
        )

    binary_names = sorted(
        binary_densities.keys()
    )

    binary_avgs = [
        sum(binary_densities[b]) / len(binary_densities[b])
        for b in binary_names
    ]

    # Weight each binary's average by the number of qualifying
    # non-interfering + dependent sets in that binary.
    binary_weights = [
        len(binary_densities[b])
        for b in binary_names
    ]

    total_binary_weight = sum(binary_weights)

    weighted_binary_avg = (
        sum(
            avg * weight
            for avg, weight in zip(
                binary_avgs,
                binary_weights,
            )
        )
        / total_binary_weight
        if total_binary_weight
        else 0.0
    )

    fig, axes = plt.subplots(
        1,
        2,
        figsize=(13, 5.5),
    )

    # ------------------------------------------------------------------
    # Subplot 1: Distribution of dependency density across target sets.
    # ------------------------------------------------------------------

    ax1 = axes[0]

    ax1.hist(
        densities,
        bins=15,
        color=COLOR_NON_INTERFERING_DEPENDENT,
        edgecolor="black",
        alpha=0.8,
    )

    ax1.axvline(
        overall_avg,
        color="red",
        linestyle="--",
        linewidth=1.5,
        label=f"Overall avg ({overall_avg:.3f})",
    )

    ax1.set_xlabel("Dependency Density")
    ax1.set_ylabel("Number of Sets")

    ax1.set_title(
        "Distribution of Dependency Density\n"
        f"(Non-interfering + Dependent Sets, N={len(target_sets)})"
    )

    ax1.legend(fontsize=8)

    # ------------------------------------------------------------------
    # Subplot 2: Average dependency density per binary.
    # ------------------------------------------------------------------

    ax2 = axes[1]

    x = list(range(len(binary_names)))

    bars = ax2.bar(
        x,
        binary_avgs,
        color=COLOR_NON_INTERFERING_DEPENDENT,
        width=0.45,
        label="Avg dependency density",
    )

    # Direct average over all qualifying sets.
    ax2.axhline(
        overall_avg,
        color="red",
        linestyle="--",
        linewidth=1.5,
        label=f"Overall avg ({overall_avg:.3f})",
    )

    # Weighted average of binary averages. Since each binary is weighted
    # by its number of qualifying sets, this is mathematically equivalent
    # to the overall average above when every set contributes equally.
    ax2.axhline(
        weighted_binary_avg,
        color="black",
        linestyle=":",
        linewidth=1.5,
        label=f"Weighted avg ({weighted_binary_avg:.3f})",
    )

    ax2.set_xticks(x)

    ax2.set_xticklabels(
        binary_names,
        rotation=45,
        ha="right",
        fontsize=8,
    )

    ax2.set_ylabel("Avg Dependency Density")
    ax2.set_ylim(0, 1.05)

    ax2.set_title(
        "Avg Dependency Density per Binary\n"
        "(Non-interfering + Dependent Sets)"
    )

    for b in bars:
        h = b.get_height()

        ax2.annotate(
            f"{h:.2f}",
            (
                b.get_x() + b.get_width() / 2,
                h,
            ),
            ha="center",
            va="bottom",
            fontsize=7,
        )

    ax2.legend(fontsize=8)

    fig.tight_layout()
    fig.savefig(
        os.path.join(
            output_folder,
            "non_interfering_dependent_density.png",
        ),
        dpi=DPI,
    )
    plt.close(fig)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Plot undermerging/interference/dependency statistics "
            "collected from {binary}.json files."
        )
    )

    parser.add_argument(
        "--input_folder",
        "-i",
        required=True,
        help=(
            "Folder containing {binary}.json result files "
            "(searched recursively)."
        ),
    )

    parser.add_argument(
        "--output_folder",
        "-o",
        required=True,
        help=(
            "Folder to write the plot PNG files to."
        ),
    )

    parser.add_argument(
        "--top_n",
        type=parse_top_n,
        default=20,
        help=(
            "How many groups/functions to show in top-N plots "
            "(default: 20). Pass a positive integer or 'all'."
        ),
    )

    args = parser.parse_args()

    os.makedirs(
        args.output_folder,
        exist_ok=True,
    )

    binaries, sets_records = load_all_data(
        args.input_folder
    )

    print(
        f"--- Loaded {len(binaries)} binaries, "
        f"{len(sets_records)} undermerged sets total ---"
    )

    plot_group_size_distribution(
        sets_records,
        binaries,
        args.output_folder,
    )

    plot_interference_dependency_breakdown(
        sets_records,
        binaries,
        args.output_folder,
    )

    plot_top_groups(
        sets_records,
        args.output_folder,
        has_interference=False,
        filename="largest_non_interfering_groups.png",
        title_suffix="largest non-interfering undermerged groups",
        top_n=args.top_n,
    )

    plot_top_groups(
        sets_records,
        args.output_folder,
        has_interference=True,
        filename="largest_interfering_groups.png",
        title_suffix="largest interfering undermerged groups",
        top_n=args.top_n,
    )

    plot_per_binary_breakdown(
        sets_records,
        binaries,
        args.output_folder,
    )

    plot_per_function_breakdown(
        sets_records,
        binaries,
        args.output_folder,
        top_n=args.top_n,
    )

    plot_binary_size_distribution(
        binaries,
        args.output_folder,
    )

    plot_function_size_distribution(
        binaries,
        args.output_folder,
        top_n=args.top_n,
    )

    plot_avg_lifted_vars_by_size(
        sets_records,
        args.output_folder,
    )

    plot_per_binary_interference_density(
        binaries,
        args.output_folder,
    )

    plot_non_interfering_dependent_density(
        sets_records,
        args.output_folder,
    )

    print(
        f"--- Done. Plots written to {args.output_folder} ---"
    )


if __name__ == "__main__":
    main()
