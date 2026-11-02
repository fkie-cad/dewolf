"""Assigning functions to k blocks and enumerating the train/holdout splits.

Combinatorics: with k blocks and t training blocks per split, every t-element subset of the k
blocks is one split, so there are C(k, t) splits. The remaining k - t blocks are the split's
holdout (AUC + evaluation). A given block is a holdout block in C(k-1, t) splits (choose all t
training blocks among the other k-1), so every function is evaluated C(k-1, t) times; for the
default t = k - 1 that is exactly once (classic k-fold).
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from itertools import combinations
from math import comb
from typing import Dict, Iterable, List, Sequence, Tuple

from cvpipeline.corpus import FunctionKey, parse_key


@dataclass(frozen=True)
class Split:
    index: int
    train_blocks: Tuple[int, ...]
    holdout_blocks: Tuple[int, ...]

    @property
    def name(self) -> str:
        return f"split_{self.index:03d}"


def validate_k_t(k: int, t: int) -> None:
    if k < 2:
        raise ValueError(f"k must be at least 2, got {k}")
    if not 1 <= t <= k - 1:
        raise ValueError(f"t must be between 1 and k-1 = {k - 1}, got {t}")


def count_splits(k: int, t: int) -> int:
    return comb(k, t)


def enumerate_splits(k: int, t: int) -> List[Split]:
    """All C(k, t) splits, in lexicographic order of their training-block tuples. The order is
    deterministic, so split indices (and output folders) are stable across resumed runs."""
    validate_k_t(k, t)
    splits = []
    for index, train in enumerate(combinations(range(k), t)):
        holdout = tuple(block for block in range(k) if block not in train)
        splits.append(Split(index=index, train_blocks=train, holdout_blocks=holdout))
    return splits


def assign_blocks(keys: Iterable[FunctionKey], k: int, seed: int) -> Dict[FunctionKey, int]:
    """Assign every function to one of k blocks, as equally sized as possible, stratified per
    project.

    Per project the sorted functions are shuffled with an RNG seeded by (seed, project) - so
    adding or removing a project does not reshuffle the others - and dealt out round-robin.
    The round-robin for each project starts where the previous project stopped, so projects whose
    size is not divisible by k do not all pile their surplus into block 0. Result: within a
    project block sizes differ by at most 1, and across the corpus by at most 1 as well.
    """
    if k < 2:
        raise ValueError(f"k must be at least 2, got {k}")
    by_project: Dict[str, List[FunctionKey]] = {}
    for key in keys:
        by_project.setdefault(parse_key(key)[0], []).append(key)

    assignment: Dict[FunctionKey, int] = {}
    next_block = 0
    for project in sorted(by_project):
        members = sorted(by_project[project])
        random.Random(f"{seed}/{project}").shuffle(members)
        for offset, key in enumerate(members):
            assignment[key] = (next_block + offset) % k
        next_block = (next_block + len(members)) % k
    return assignment


def members_of(assignment: Dict[FunctionKey, int], blocks: Sequence[int]) -> List[FunctionKey]:
    wanted = set(blocks)
    return sorted(key for key, block in assignment.items() if block in wanted)
