"""Evaluation metrics, ported from legacy/plot_dwarf.py (same definitions, so numbers stay
comparable with earlier plots).

All metrics are B-Cubed over the matched variable records of a function:
  * precision clusters: one per output variable, labels = the DWARF sources of its records;
  * recall clusters: one per DWARF source, labels = the output variables carrying it.
For an element e of cluster C the score is |{x in C : label(x) = label(e)}| / |C|.

  * macro: per binary the mean element score, then the arithmetic mean over binaries
    (F1 per binary, then averaged - not recomputed from the mean P/R);
  * micro: all elements of the algorithm pooled, F1 from the micro P and R;
  * overmerged: precision clusters with >= 2 distinct sources (of all precision clusters);
  * undermerged: recall clusters with >= 2 distinct output variables (of all recall clusters);
  * inserted: records without any source (of all records);
  * output variables: distinct output names per function (summed), and how many of them have at
    least one source-matched record.

Only local variables are scored: records of globals and string constants (kinds "dwarf-global" and
"const-string") are left out. Out-of-SSA never renames those, so they would match perfectly for
every algorithm and only inflate the scores.

Only functions that succeeded for *every* algorithm being compared are used (and only binaries
present for every algorithm), so the algorithms are compared on identical code.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from cvpipeline.corpus import FunctionKey, make_key
from cvpipeline.logs import get_logger
from cvpipeline.storage import read_json

log = get_logger("metrics")

Record = Tuple[str, Optional[str]]  # (output variable, source or None)
BinaryId = Tuple[str, str]  # (project, binary)
# {algorithm: {(project, binary): {function: [records]}}}  -- successful functions only
Results = Dict[str, Dict[BinaryId, Dict[str, List[Record]]]]

# Record kinds (variable_matching.MatchKind) that are scored: matched locals and unmatched ("inserted") variables.
SCORED_KINDS = {"dwarf-local", "unmatched"}

# Folders that can sit next to project folders in an evaluation directory but are not projects.
NON_PROJECT_DIRS = {"work", "logs", "baselines", "plots"}


@dataclass
class AlgorithmMetrics:
    macro_precision: float
    macro_recall: float
    macro_f1: float
    micro_precision: float
    micro_recall: float
    micro_f1: float
    overmerged: int
    overmerged_total: int
    undermerged: int
    undermerged_total: int
    inserted: int
    inserted_total: int
    output_variables: int  # distinct output variable names the algorithm produced (per function, summed)
    output_variables_matched: int  # of those, names with at least one source-matched record
    binaries: int
    functions: int

    @property
    def overmerged_pct(self) -> float:
        return _pct(self.overmerged, self.overmerged_total)

    @property
    def undermerged_pct(self) -> float:
        return _pct(self.undermerged, self.undermerged_total)

    @property
    def inserted_pct(self) -> float:
        return _pct(self.inserted, self.inserted_total)

    def as_dict(self) -> Dict[str, float]:
        data = asdict(self)
        data.update(overmerged_pct=self.overmerged_pct, undermerged_pct=self.undermerged_pct, inserted_pct=self.inserted_pct)
        return data


def _pct(part: int, whole: int) -> float:
    return 100.0 * part / whole if whole else 0.0


# --------------------------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------------------------- #


def project_dirs(root: Path) -> List[Path]:
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir() and p.name not in NON_PROJECT_DIRS and not p.name.startswith("split_"))


def load_results(root: Path, allowed: Optional[Set[FunctionKey]] = None, algorithms: Optional[Set[str]] = None) -> Results:
    """Read ``<root>/<project>/<algorithm>/<binary>.json``, keeping only successful functions
    (and, if given, only functions in ``allowed`` / algorithms in ``algorithms``). Only the
    (variable, source) pairs of the scored kinds (SCORED_KINDS) are kept in memory."""
    results: Results = defaultdict(dict)
    for project_dir in project_dirs(root):
        for algorithm_dir in sorted(p for p in project_dir.iterdir() if p.is_dir()):
            if algorithms is not None and algorithm_dir.name not in algorithms:
                continue
            for path in sorted(algorithm_dir.glob("*.json")):
                try:
                    content = read_json(path)
                except Exception as error:
                    log.warning(f"skipping unreadable {path}: {error}")
                    continue
                binary = path.name[: -len(".json")]
                functions = {}
                for function, entry in content.get("functions", {}).items():
                    if entry.get("status") != "success":
                        continue
                    if allowed is not None and make_key(project_dir.name, binary, function) not in allowed:
                        continue
                    functions[function] = [(v["variable"], v["source"]) for v in entry["result"]["variables"]
                        if v.get("variable") is not None and v.get("kind") in SCORED_KINDS
                    ]
                results[algorithm_dir.name][(project_dir.name, binary)] = functions
    return dict(results)


def merge(*parts: Results) -> Results:
    merged: Results = {}
    for part in parts:
        for algorithm, binaries in part.items():
            merged.setdefault(algorithm, {}).update(binaries)
    return merged


def restrict_to_common(results: Results) -> Results:
    """Keep binaries present for every algorithm and, within them, functions that succeeded for
    every algorithm."""
    if not results:
        return {}
    algorithms = sorted(results)
    common_binaries = set.intersection(*(set(results[a]) for a in algorithms))
    restricted: Results = {a: {} for a in algorithms}
    for binary in sorted(common_binaries):
        common_functions = set.intersection(*(set(results[a][binary]) for a in algorithms))
        if not common_functions:
            continue
        for algorithm in algorithms:
            restricted[algorithm][binary] = {f: results[algorithm][binary][f] for f in sorted(common_functions)}
    return restricted


# --------------------------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------------------------- #


def _clusters(records: Iterable[Record]) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], int, int]:
    """-> (precision clusters, recall clusters, inserted records, all records) of one function."""
    precision: Dict[str, List[str]] = defaultdict(list)
    recall: Dict[str, List[str]] = defaultdict(list)
    inserted = total = 0
    for variable, source in records:
        total += 1
        if source is None:
            inserted += 1
        else:
            precision[variable].append(source)
            recall[source].append(variable)
    return precision, recall, inserted, total


def _bcubed(clusters: Dict[str, List[str]]) -> Tuple[float, int]:
    """(sum of element scores, number of elements)."""
    score, count = 0.0, 0
    for labels in clusters.values():
        n = len(labels)
        score += sum(c * c for c in Counter(labels).values()) / n
        count += n
    return score, count


def _ratio(score: float, count: int) -> float:
    return score / count if count else 0.0


def _f1(p: float, r: float) -> float:
    return 2 * p * r / (p + r) if p + r > 0 else 0.0


def compute_algorithm_metrics(binaries: Dict[BinaryId, Dict[str, List[Record]]]) -> Optional[AlgorithmMetrics]:
    if not binaries:
        return None

    per_binary: List[Tuple[float, float, float]] = []
    micro_p = [0.0, 0]
    micro_r = [0.0, 0]
    over = over_total = under = under_total = inserted = inserted_total = functions = 0
    output_variables = output_variables_matched = 0
    for function_records in binaries.values():
        bin_p = [0.0, 0]
        bin_r = [0.0, 0]
        for records in function_records.values():
            functions += 1
            precision, recall, n_inserted, n_total = _clusters(records)
            for accumulator, clusters in ((bin_p, precision), (bin_r, recall)):
                score, count = _bcubed(clusters)
                accumulator[0] += score
                accumulator[1] += count
            over += sum(1 for labels in precision.values() if len(set(labels)) >= 2)
            over_total += len(precision)
            under += sum(1 for labels in recall.values() if len(set(labels)) >= 2)
            under_total += len(recall)
            inserted += n_inserted
            inserted_total += n_total
            output_variables += len({variable for variable, _ in records})
            output_variables_matched += len({variable for variable, source in records if source is not None})
        p, r = _ratio(*bin_p), _ratio(*bin_r)
        per_binary.append((p, r, _f1(p, r)))
        micro_p = [micro_p[0] + bin_p[0], micro_p[1] + bin_p[1]]
        micro_r = [micro_r[0] + bin_r[0], micro_r[1] + bin_r[1]]

    n = len(per_binary)
    mp, mr = _ratio(*micro_p), _ratio(*micro_r)
    return AlgorithmMetrics(
        macro_precision=100 * sum(p for p, _, _ in per_binary) / n,
        macro_recall=100 * sum(r for _, r, _ in per_binary) / n,
        macro_f1=100 * sum(f for _, _, f in per_binary) / n,
        micro_precision=100 * mp,
        micro_recall=100 * mr,
        micro_f1=100 * _f1(mp, mr),
        overmerged=over,
        overmerged_total=over_total,
        undermerged=under,
        undermerged_total=under_total,
        inserted=inserted,
        inserted_total=inserted_total,
        output_variables=output_variables,
        output_variables_matched=output_variables_matched,
        binaries=n,
        functions=functions,
    )


def compute_metrics(results: Results) -> Dict[str, AlgorithmMetrics]:
    common = restrict_to_common(results)
    metrics = {}
    for algorithm, binaries in common.items():
        value = compute_algorithm_metrics(binaries)
        if value is None:
            log.warning(f"no common successful functions for '{algorithm}'")
        else:
            metrics[algorithm] = value
    return metrics


@dataclass
class MetricSummary:
    """Arithmetic mean (and standard deviation) of every metric over splits."""
    mean: Dict[str, float]
    std: Dict[str, float]
    splits: int


def average_over_splits(per_split: List[Dict[str, AlgorithmMetrics]]) -> Dict[str, MetricSummary]:
    import numpy as np

    summaries = {}
    for algorithm in sorted({a for split in per_split for a in split}):
        values = [split[algorithm].as_dict() for split in per_split if algorithm in split]
        keys = values[0].keys()
        summaries[algorithm] = MetricSummary(
            mean={key: float(np.mean([v[key] for v in values])) for key in keys},
            std={key: float(np.std([v[key] for v in values])) for key in keys},
            splits=len(values),
        )
    return summaries


def single(metrics: Dict[str, AlgorithmMetrics]) -> Dict[str, MetricSummary]:
    """Wrap a single evaluation's metrics in the same shape (std 0) so plotting is uniform."""
    return {a: MetricSummary(mean=m.as_dict(), std={key: 0.0 for key in m.as_dict()}, splits=1) for a, m in metrics.items()}
