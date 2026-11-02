from collections import Counter
from math import comb

import pytest

from cvpipeline import folds
from cvpipeline.corpus import make_key


def corpus(sizes):
    """{project: n_functions} -> list of keys"""
    return [make_key(project, "bin", f"f{i}") for project, n in sizes.items() for i in range(n)]


@pytest.mark.parametrize("k,t", [(2, 1), (5, 4), (5, 3), (6, 2), (4, 1)])
def test_number_of_splits_and_holdout_coverage(k, t):
    splits = folds.enumerate_splits(k, t)
    assert len(splits) == comb(k, t) == folds.count_splits(k, t)
    assert len({s.train_blocks for s in splits}) == len(splits)
    for split in splits:
        assert len(split.train_blocks) == t
        assert sorted(split.train_blocks + split.holdout_blocks) == list(range(k))
    holdout_count = Counter(block for split in splits for block in split.holdout_blocks)
    # every block (hence every function) is holdout in exactly C(k-1, t) splits
    assert all(holdout_count[block] == comb(k - 1, t) for block in range(k))


def test_split_names_are_stable_and_ordered():
    splits = folds.enumerate_splits(4, 2)
    assert [s.name for s in splits] == [f"split_{i:03d}" for i in range(6)]
    assert splits[0].train_blocks == (0, 1) and splits[-1].train_blocks == (2, 3)


@pytest.mark.parametrize("k,t", [(1, 1), (3, 0), (3, 3)])
def test_invalid_k_t_rejected(k, t):
    with pytest.raises(ValueError):
        folds.enumerate_splits(k, t)


def test_blocks_are_balanced_globally_and_per_project():
    keys = corpus({"a": 13, "b": 7, "c": 22})
    assignment = folds.assign_blocks(keys, 5, seed=1)
    assert set(assignment) == set(keys)
    sizes = Counter(assignment.values())
    assert max(sizes.values()) - min(sizes.values()) <= 1
    for project in "abc":
        project_sizes = Counter(block for key, block in assignment.items() if key.startswith(f"{project}/"))
        assert max(project_sizes.values()) - min(project_sizes.values()) <= 1


def test_assignment_is_deterministic_and_seed_dependent():
    keys = corpus({"a": 40, "b": 40})
    assert folds.assign_blocks(keys, 4, seed=7) == folds.assign_blocks(list(reversed(keys)), 4, seed=7)
    assert folds.assign_blocks(keys, 4, seed=7) != folds.assign_blocks(keys, 4, seed=8)


def test_adding_a_project_does_not_reshuffle_others_membership():
    """Per-project RNG: which functions of a project share a block does not depend on the other
    projects (block numbers may rotate because of the round-robin offset)."""
    base = folds.assign_blocks(corpus({"b": 30}), 3, seed=0)
    extended = folds.assign_blocks(corpus({"a": 10, "b": 30}), 3, seed=0)

    def grouping(assignment):
        groups = {}
        for key, block in assignment.items():
            if key.startswith("b/"):
                groups.setdefault(block, set()).add(key)
        return sorted(map(sorted, groups.values()))

    assert grouping(base) == grouping(extended)


def test_members_of():
    assignment = {"p/b::x": 0, "p/b::y": 1, "p/b::z": 2}
    assert folds.members_of(assignment, (0, 2)) == ["p/b::x", "p/b::z"]
