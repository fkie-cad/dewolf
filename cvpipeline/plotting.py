"""Plots for an evaluation directory.

Two input layouts are recognised automatically:
  * cross-validation: ``<eval>/split_*/<project>/conditional/<binary>.json`` plus
    ``<eval>/split_*/holdout.json`` and optionally ``<eval>/baselines/<project>/<algo>/...``.
    Metrics are computed per split - the conditional results come from that split's model on its
    holdout, the baselines are restricted to the same holdout functions. Written to
    ``<plots>/averaged/`` (arithmetic mean over the splits, error bars: standard deviation) and
    ``<plots>/splits/<split>/`` (that split alone; its blocks, AUC and params - read from
    ``<eval>/../params/<split>/params.json`` if present - appear in the titles and metrics.json).
  * single evaluation: ``<eval>/<project>/<algorithm>/<binary>.json`` (e.g. cv_evaluate.py output),
    plotted directly into ``<plots>/``.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

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


def per_split_metrics(eval_dir: Path) -> Dict[str, Dict[str, AlgorithmMetrics]]:
    """{split name: {algorithm: metrics}} on each split's holdout functions (splits without any
    evaluable result are left out)."""
    per_split: Dict[str, Dict[str, AlgorithmMetrics]] = {}
    for split in split_dirs(eval_dir):
        # One split at a time, so only that split's results are in memory.
        holdout = set(read_json(split / "holdout.json")["functions"])
        results = merge(load_results(split, allowed=holdout), load_results(eval_dir / "baselines", allowed=holdout))
        metrics = compute_metrics(results)
        if not metrics:
            log.warning(f"{split.name}: no evaluable results, left out")
            continue
        per_split[split.name] = metrics
        log.info(f"{split.name}: " + ", ".join(f"{a} micro-F1 {m.micro_f1:.2f}" for a, m in metrics.items()))
    return per_split


def split_info(eval_dir: Path, split: str) -> Dict[str, Any]:
    """Blocks of a split (holdout.json) and, if the params folder sits next to the eval folder,
    its AUC, intercept and coefficients."""
    holdout = read_json(eval_dir / split / "holdout.json")
    info: Dict[str, Any] = {"split": split, "train_blocks": holdout.get("train_blocks"), "holdout_blocks": holdout.get("holdout_blocks")}
    params_path = eval_dir.parent / "params" / split / "params.json"
    if params_path.exists():
        params = read_json(params_path)
        info.update(auc=params.get("auc"), intercept=params.get("intercept"), coef=params.get("coef"))
    return info


def _split_subtitle(info: Dict[str, Any]) -> str:
    text = f"{info['split']}: train blocks {info.get('train_blocks')}"
    if "auc" in info:
        text += ", AUC " + ("n/a" if info["auc"] is None else f"{info['auc']:.3f}")
    return text


def write_tables(summaries: Dict[str, MetricSummary], output_dir: Path, info: Optional[Dict[str, Any]] = None) -> None:
    table: Dict[str, Any] = {algorithm: {"splits": s.splits, "mean": s.mean, "std": s.std} for algorithm, s in summaries.items()}
    if info is not None:
        table["split"] = info
    write_json_atomic(output_dir / "metrics.json", table)
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


def plot_all(summaries: Dict[str, MetricSummary], output_dir: Path, info: Optional[Dict[str, Any]] = None) -> None:
    """All plots plus metrics.json/csv; ``info`` (a split's blocks/AUC/params) goes into the titles and metrics.json."""
    output_dir.mkdir(parents=True, exist_ok=True)
    if not summaries:
        log.error("nothing to plot")
        return
    write_tables(summaries, output_dir, info)
    subtitle = _split_subtitle(info) if info is not None else _subtitle(summaries)
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
    """Plot an evaluation folder (see the module docstring for the layouts and output folders).
    Returns the summaries that were plotted: the averaged ones for a cross-validation folder."""
    if not split_dirs(eval_dir):
        log.info(f"{eval_dir}: no split folders, plotting a single evaluation")
        summaries = single(compute_metrics(load_results(eval_dir)))
        plot_all(summaries, output_dir)
        return summaries

    per_split = per_split_metrics(eval_dir)
    log.info(f"{eval_dir}: averaging over {len(per_split)} splits")
    summaries = average_over_splits(list(per_split.values()))
    plot_all(summaries, output_dir / "averaged")
    for split, metrics in per_split.items():
        plot_all(single(metrics), output_dir / "splits" / split, split_info(eval_dir, split))
    return summaries
