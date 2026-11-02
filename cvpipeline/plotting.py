"""Plots for an evaluation directory.

Two input layouts are recognised automatically:
  * cross-validation: ``<eval>/split_*/<project>/conditional/<binary>.json`` plus
    ``<eval>/split_*/holdout.json`` and optionally ``<eval>/baselines/<project>/<algo>/...``.
    Metrics are computed per split - the baselines restricted to that split's holdout functions -
    and then averaged arithmetically over the splits (error bars: standard deviation).
  * single evaluation: ``<eval>/<project>/<algorithm>/<binary>.json`` (e.g. cv_evaluate.py output).
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List, Sequence

from cvpipeline.logs import get_logger
from cvpipeline.metrics import (
    AlgorithmMetrics,
    MetricSummary,
    average_over_splits,
    compute_metrics,
    load_results,
    merge,
    single,
)
from cvpipeline.storage import read_json, write_json_atomic

log = get_logger("plotting")


def split_dirs(eval_dir: Path) -> List[Path]:
    return sorted(p for p in eval_dir.iterdir() if p.is_dir() and p.name.startswith("split_") and (p / "holdout.json").exists())


def summarize(eval_dir: Path) -> Dict[str, MetricSummary]:
    splits = split_dirs(eval_dir)
    if not splits:
        log.info(f"{eval_dir}: no split folders, plotting a single evaluation")
        return single(compute_metrics(load_results(eval_dir)))

    log.info(f"{eval_dir}: averaging over {len(splits)} splits")
    per_split: List[Dict[str, AlgorithmMetrics]] = []
    for split in splits:
        # One split at a time, so only that split's results are in memory.
        holdout = set(read_json(split / "holdout.json")["functions"])
        results = merge(load_results(split, allowed=holdout), load_results(eval_dir / "baselines", allowed=holdout))
        metrics = compute_metrics(results)
        if not metrics:
            log.warning(f"{split.name}: no evaluable results, left out of the average")
            continue
        per_split.append(metrics)
        log.info(f"{split.name}: " + ", ".join(f"{a} micro-F1 {m.micro_f1:.2f}" for a, m in metrics.items()))
    return average_over_splits(per_split)


def write_tables(summaries: Dict[str, MetricSummary], output_dir: Path) -> None:
    write_json_atomic(
        output_dir / "metrics.json",
        {algorithm: {"splits": s.splits, "mean": s.mean, "std": s.std} for algorithm, s in summaries.items()},
    )
    keys = sorted(next(iter(summaries.values())).mean) if summaries else []
    with open(output_dir / "metrics.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["algorithm", "splits"] + [f"{key}_mean" for key in keys] + [f"{key}_std" for key in keys])
        for algorithm, s in summaries.items():
            writer.writerow([algorithm, s.splits] + [s.mean[key] for key in keys] + [s.std[key] for key in keys])


def _grouped_bars(
    summaries: Dict[str, MetricSummary],
    keys: Sequence[str],
    labels: Sequence[str],
    title: str,
    path: Path,
    ylabel: str,
    value_format: str = "%.2f",
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    algorithms = list(summaries)
    width = 0.8 / len(keys)
    x = np.arange(len(algorithms))
    fig, ax = plt.subplots(figsize=(max(6, 1.6 * len(algorithms) * len(keys)), 5))
    for i, (key, label) in enumerate(zip(keys, labels)):
        means = [summaries[a].mean[key] for a in algorithms]
        stds = [summaries[a].std[key] for a in algorithms]
        bars = ax.bar(x + (i - (len(keys) - 1) / 2) * width, means, width, yerr=stds, capsize=3, label=label)
        ax.bar_label(bars, fmt=value_format, padding=3, fontsize=7)
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms, rotation=20, ha="right")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.margins(y=0.15)
    if len(keys) > 1:
        ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1))
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def _subtitle(summaries: Dict[str, MetricSummary]) -> str:
    splits = max((s.splits for s in summaries.values()), default=0)
    return f"mean over {splits} splits (error bars: std)" if splits > 1 else "single evaluation"


def plot_all(summaries: Dict[str, MetricSummary], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not summaries:
        log.error("nothing to plot")
        return
    write_tables(summaries, output_dir)
    subtitle = _subtitle(summaries)
    prf = ["Precision", "Recall", "F1"]
    _grouped_bars(
        summaries,
        ["micro_precision", "micro_recall", "micro_f1"],
        prf,
        f"Micro B-Cubed metrics\n{subtitle}",
        output_dir / "micro_metrics.png",
        "%",
    )
    _grouped_bars(
        summaries,
        ["macro_precision", "macro_recall", "macro_f1"],
        prf,
        f"Averaged (macro over binaries) B-Cubed metrics\n{subtitle}",
        output_dir / "averaged_metrics.png",
        "%",
    )
    for key, title in (
        ("overmerged", "Overmerged output variables (≥2 distinct sources)"),
        ("undermerged", "Undermerged source variables (≥2 output variables)"),
        ("inserted", "Inserted variable records (no source)"),
    ):
        _grouped_bars(summaries, [f"{key}_pct"], [title], f"{title}\n{subtitle}", output_dir / f"{key}.png", "% of all")
    _grouped_bars(
        summaries,
        ["output_variables", "output_variables_matched"],
        ["Output variables", "With source match"],
        f"Output variables generated per algorithm (summed over all functions)\n{subtitle}",
        output_dir / "output_variables.png",
        "count",
        value_format="%.0f",
    )
    log.info(f"plots and metrics.json/metrics.csv written to {output_dir}")


def plot_eval_dir(eval_dir: Path, output_dir: Path) -> Dict[str, MetricSummary]:
    summaries = summarize(eval_dir)
    plot_all(summaries, output_dir)
    return summaries
