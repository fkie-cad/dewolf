"""Orchestration of the k-fold cross-validation: dedup -> blocks -> features -> per split
training + AUC -> evaluation of every split's holdout (+ baselines once) -> averaged params.

Resume: every stage persists its result and is skipped if that result already exists -
``work/dedup.json``, ``work/blocks.json``, the per-binary feature and evaluation files (with
per-function checkpoints inside a binary) and ``params/<split>/params.json`` (written last for a
split, so its existence means the split is trained). The run manifest guards against resuming
with different parameters (config.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from cvpipeline import config, folds
from cvpipeline.corpus import DedupResult, FunctionKey, load_or_deduplicate
from cvpipeline.evaluation import Algorithm, make_jobs
from cvpipeline.features import extract_features, iter_rows
from cvpipeline.logs import error_log_path, get_logger
from cvpipeline.model import Params, auc, average, fit, mean_and_std, rows_to_arrays
from cvpipeline.storage import read_json, write_json_atomic, write_text_atomic
from cvpipeline.workers import PoolSettings, run_jobs

log = get_logger("crossval")


@dataclass(frozen=True)
class CrossValidationSettings:
    projects_dir: Path
    output_dir: Path
    k: int
    t: int
    seed: int = 0
    C: float = 1.0
    baselines: Sequence[str] = ()
    pool: PoolSettings = PoolSettings()
    function_timeout_s: Optional[float] = 600.0


class OutputLayout:
    """All paths below the output folder in one place."""

    def __init__(self, output_dir: Path) -> None:
        self.root = output_dir
        self.work = output_dir / "work"
        self.blocks = self.work / "blocks.json"
        self.params = output_dir / "params"
        self.averaged = self.params / "averaged.json"
        self.eval = output_dir / "eval"
        self.baselines = self.eval / "baselines"

    def split_params(self, split: folds.Split) -> Path:
        return self.params / split.name / "params.json"

    def split_auc(self, split: folds.Split) -> Path:
        return self.params / split.name / "auc.txt"

    def split_eval(self, split: folds.Split) -> Path:
        return self.eval / split.name

    def split_holdout(self, split: folds.Split) -> Path:
        return self.split_eval(split) / "holdout.json"


def run_cross_validation(settings: CrossValidationSettings) -> Params:
    """Run (or resume) the whole cross-validation and return the averaged params."""
    folds.validate_k_t(settings.k, settings.t)
    layout = OutputLayout(settings.output_dir)
    projects_dir = settings.projects_dir.resolve()
    config.check_or_write(
        settings.output_dir,
        config.RunConfig(projects_dir=str(projects_dir), k=settings.k, t=settings.t, seed=settings.seed, C=settings.C),
    )
    baselines = [Algorithm.baseline(name) for name in settings.baselines]  # validate early
    error_log = str(error_log_path(settings.output_dir))

    splits = folds.enumerate_splits(settings.k, settings.t)
    log.info(
        f"k={settings.k}, t={settings.t}: {len(splits)} splits (C({settings.k},{settings.t})); "
        f"every function is holdout in {folds.count_splits(settings.k - 1, settings.t)} of them"
    )

    dedup = load_or_deduplicate(projects_dir, layout.work, settings.pool, error_log)
    blocks = _load_or_assign_blocks(layout, dedup, settings.k, settings.seed)
    extract_features(projects_dir, layout.work, dedup.kept, settings.pool, error_log, settings.function_timeout_s)

    trained = {split: params for split in splits if (params := _load_or_train_split(layout, split, blocks, settings.C)) is not None}

    jobs = []
    for split, params in trained.items():
        holdout = folds.members_of(blocks, split.holdout_blocks)
        if not layout.split_holdout(split).exists():
            write_json_atomic(
                layout.split_holdout(split),
                {"split": split.name, "train_blocks": split.train_blocks, "holdout_blocks": split.holdout_blocks, "functions": holdout},
            )
        jobs += make_jobs(
            projects_dir,
            layout.split_eval(split),
            holdout,
            Algorithm.conditional(params),
            error_log,
            settings.function_timeout_s,
            label_prefix=f"{split.name}/",
        )
    for baseline in baselines:
        # Baselines do not depend on the split: evaluated once on everything, filtered per split
        # at plotting time (cv_plot.py reads each split's holdout.json).
        jobs += make_jobs(projects_dir, layout.baselines, dedup.kept, baseline, error_log, settings.function_timeout_s, "baselines/")
    run_jobs(jobs, settings.pool, "evaluation")

    return _write_averaged(layout, trained)


def _load_or_assign_blocks(layout: OutputLayout, dedup: DedupResult, k: int, seed: int) -> Dict[FunctionKey, int]:
    if layout.blocks.exists():
        return read_json(layout.blocks)["assignment"]
    assignment = folds.assign_blocks(dedup.kept, k, seed)
    sizes = [sum(1 for block in assignment.values() if block == b) for b in range(k)]
    log.info(f"block sizes: {sizes}")
    write_json_atomic(layout.blocks, {"k": k, "seed": seed, "sizes": sizes, "assignment": assignment})
    return assignment


def _load_or_train_split(layout: OutputLayout, split: folds.Split, blocks: Dict[FunctionKey, int], C: float) -> Optional[Params]:
    """Train on the split's training blocks, compute the AUC on its holdout blocks. Returns None
    (and logs) if the split cannot be trained, e.g. because a side has only one class."""
    if layout.split_params(split).exists():
        return Params.load(layout.split_params(split))

    train_keys = folds.members_of(blocks, split.train_blocks)
    holdout_keys = folds.members_of(blocks, split.holdout_blocks)
    train_rows = list(iter_rows(layout.work, train_keys))
    holdout_rows = list(iter_rows(layout.work, holdout_keys))
    X_train, y_train = rows_to_arrays(row for _, row in train_rows)
    X_holdout, y_holdout = rows_to_arrays(row for _, row in holdout_rows)
    try:
        params = fit(X_train, y_train, C)
    except ValueError as error:
        log.error(f"{split.name}: cannot train ({error}); split skipped")
        return None
    split_auc = auc(params, X_holdout, y_holdout)

    metadata = {
        "split": split.name,
        "train_blocks": list(split.train_blocks),
        "holdout_blocks": list(split.holdout_blocks),
        "auc": split_auc,
        "train_functions": len(train_keys),
        "train_functions_with_data": len({key for key, _ in train_rows}),
        "train_rows": len(train_rows),
        "holdout_functions": len(holdout_keys),
        "holdout_functions_with_data": len({key for key, _ in holdout_rows}),
        "holdout_rows": len(holdout_rows),
    }
    auc_text = "n/a (holdout has a single class)" if split_auc is None else f"{split_auc:.4f}"
    write_text_atomic(
        layout.split_auc(split), f"auc: {auc_text}\n" + "".join(f"{key}: {value}\n" for key, value in metadata.items() if key != "auc")
    )
    params.metadata = metadata
    params.save(layout.split_params(split))  # written last: its existence marks the split as trained
    log.info(f"{split.name}: train blocks {split.train_blocks}, AUC {auc_text} ({len(holdout_rows)} holdout rows)")
    return params


def _write_averaged(layout: OutputLayout, trained: Dict[folds.Split, Params]) -> Params:
    if not trained:
        raise RuntimeError("no split could be trained; see logs/errors.log")
    averaged = average(list(trained.values()))
    aucs: List[Optional[float]] = [params.metadata.get("auc") for params in trained.values()]
    auc_mean, auc_std = mean_and_std(aucs)
    averaged.metadata = {
        "auc_mean": auc_mean,
        "auc_std": auc_std,
        "splits": len(trained),
        "split_aucs": {split.name: params.metadata.get("auc") for split, params in trained.items()},
    }
    averaged.save(layout.averaged)
    log.info(f"averaged params over {len(trained)} splits written to {layout.averaged} (AUC {auc_mean:.4f} ± {auc_std:.4f})")
    return averaged
