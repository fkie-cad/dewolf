"""How many of the dependency graph's edges have no ground-truth label.

The model is trained on labeled pairs only (both variables have a DWARF source), but at inference
the conditional renamer also scores pairs with an unlabeled variable (e.g. a compiler temporary),
and their scores are extrapolated. This module rebuilds, from the cached candidate pairs
(features.FunctionData) and a split's params, the edges dependency_graph_from_cfg creates (one edge
per distinct pair whose best occurrence scores > 0) and counts the unlabeled ones - in total and in
the "contested" components, those containing a pair that must stay separate, where the renamer
actually has to cut or refuse merges. Relation edges the renamer adds on top are not included, and
neither are edges with a global variable: the cached pairs are those between local variables.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List

from cvpipeline.corpus import FunctionKey
from cvpipeline.features import FunctionData, PairKey, iter_function_data, pair_key
from cvpipeline.model import Params

COUNTS = (
    "functions",
    "functions_interference_unknown",  # interfering pairs were not computed (function too large)
    "edges",
    "edges_one_unlabeled",
    "edges_both_unlabeled",
    "contested_edges",
    "contested_edges_one_unlabeled",
    "contested_edges_both_unlabeled",
)


def graph_edges(data: FunctionData, coefficients: List[float], intercept: float) -> List[PairKey]:
    """The distinct pairs with at least one occurrence scoring > 0 (as in dependency_graph_from_cfg)."""
    edges = set()
    for x, y, vector in data.pairs:
        if sum(c * v for c, v in zip(coefficients, vector)) + intercept > 0:
            edges.add(pair_key(x, y))
    return sorted(edges)


def function_edge_counts(data: FunctionData, coefficients: List[float], intercept: float) -> Counter:
    edges = graph_edges(data, coefficients, intercept)
    parent = list(range(len(data.sources)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for x, y in edges:
        root_x, root_y = find(x), find(y)
        if root_x != root_y:
            parent[root_y] = root_x
    contested = set() if data.interfering is None else {find(x) for x, y in data.interfering if find(x) == find(y)}

    counts = Counter(functions=1, functions_interference_unknown=int(data.interfering is None))
    for x, y in edges:
        unlabeled = (data.sources[x] is None) + (data.sources[y] is None)
        prefixes = ["edges"] + (["contested_edges"] if find(x) in contested else [])
        for prefix in prefixes:
            counts[prefix] += 1
            if unlabeled == 1:
                counts[f"{prefix}_one_unlabeled"] += 1
            elif unlabeled == 2:
                counts[f"{prefix}_both_unlabeled"] += 1
    return counts


def edge_label_counts(work_dir: Path, keys: Iterable[FunctionKey], params: Params) -> Dict[str, int]:
    """The COUNTS summed over the given functions' cached data, for the edges under ``params``."""
    coefficients, total = params.coefficients(), Counter()
    for _, data in iter_function_data(work_dir, keys):
        total.update(function_edge_counts(data, coefficients, params.intercept))
    return {name: total[name] for name in COUNTS}


def describe_edge_labels(counts: Dict[str, int]) -> str:
    def share(prefix: str) -> str:
        n = counts[prefix]
        unlabeled = counts[f"{prefix}_one_unlabeled"] + counts[f"{prefix}_both_unlabeled"]
        return f"{unlabeled} of {n} unlabeled ({100 * unlabeled / n:.1f}%)" if n else "none"

    text = f"edges: {share('edges')}; in contested components: {share('contested_edges')}"
    if counts["functions_interference_unknown"]:
        text += f" ({counts['functions_interference_unknown']} functions without interference data not counted as contested)"
    return text
