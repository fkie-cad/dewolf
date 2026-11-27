"""Tests for the weights file of the conditional out-of-SSA mode."""

import json

import pytest
from decompiler.pipeline.ssa.conditional_attribute_helper import Feature, cannot_share_name, get_phi_pairs
from decompiler.pipeline.ssa.conditional_weights import DEFAULT_WEIGHTS_FILE, ConditionalWeights
from decompiler.pipeline.ssa.variable_renaming import ConditionalVariableRenamer
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Assignment, Constant, Integer, Return, Variable
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

NAMES = [feature.value for feature in Feature]


def _weights(**changes) -> dict:
    data = {
        "coefficients": {name: float(i) for i, name in enumerate(NAMES)},
        "intercept": -1.5,
        "strategy": 3,
        "min_kept_score": 0.25,
    }
    data.update(changes)
    return data


def _write(tmp_path, data: dict) -> str:
    path = tmp_path / "weights.json"
    path.write_text(json.dumps(data))
    return str(path)


def _task(weights_path: str = "") -> DecompilerTask:
    cfg = ControlFlowGraph()
    x = Variable("x", Integer.int32_t(), 0)
    cfg.add_node(BasicBlock(0, [Assignment(x, Constant(1, Integer.int32_t())), Return([x])]))
    options = Options.load_default_options()
    options.set("out-of-ssa-translation.conditional_weights", weights_path)
    return DecompilerTask(name="weights-test", function_identifier="", cfg=cfg, options=options)


def test_bundled_file_matches_features():
    with open(DEFAULT_WEIGHTS_FILE) as file:
        assert list(json.load(file)["coefficients"]) == NAMES
    assert set(ConditionalWeights.from_file().coefficients) == set(Feature)


def test_load_weights_file(tmp_path):
    weights = ConditionalWeights.from_file(_write(tmp_path, _weights()))
    assert weights.coefficients == {feature: float(i) for i, feature in enumerate(Feature)}
    assert weights.intercept == -1.5
    assert weights.strategy == 3
    assert weights.min_kept_score == 0.25


def test_min_kept_score_null_is_off(tmp_path):
    assert ConditionalWeights.from_file(_write(tmp_path, _weights(min_kept_score=None))).min_kept_score is None


@pytest.mark.parametrize(
    "names",
    [NAMES[:-1], NAMES + ["new_feature"], []],
)
def test_missing_or_unknown_feature_fails(tmp_path, names):
    with pytest.raises(ValueError):
        ConditionalWeights.from_file(_write(tmp_path, _weights(coefficients={name: 1.0 for name in names})))


def test_missing_file_fails(tmp_path):
    with pytest.raises(ValueError, match="missing.json"):
        ConditionalWeights.from_file(tmp_path / "missing.json")


def test_invalid_json_fails(tmp_path):
    path = tmp_path / "weights.json"
    path.write_text("{not json")
    with pytest.raises(ValueError, match="weights.json"):
        ConditionalWeights.from_file(path)


@pytest.mark.parametrize("key", ["coefficients", "intercept", "strategy"])
def test_missing_key_fails(tmp_path, key):
    data = _weights()
    del data[key]
    with pytest.raises(ValueError, match=key):
        ConditionalWeights.from_file(_write(tmp_path, data))


def _weights_of_the_renamer(weights_path: str) -> ConditionalWeights:
    """Return the weights the conditional renamer loads for a task with the given option."""
    task = _task(weights_path)
    return ConditionalVariableRenamer(task, InterferenceGraph(task.graph), get_phi_pairs(task.graph)).weights


def test_empty_option_uses_bundled_file():
    assert _weights_of_the_renamer("") == ConditionalWeights.from_file(DEFAULT_WEIGHTS_FILE)


def test_option_path_overrides_bundled_file(tmp_path):
    path = _write(tmp_path, _weights())
    assert _weights_of_the_renamer(path) == ConditionalWeights.from_file(path)


def test_cannot_share_name_raises_on_missing_type():
    """A variable without type raises, even if the other one has a type (and the types therefore differ)."""
    typed, untyped = Variable("x", Integer.int32_t(), 0), Variable("y", None, 0)
    with pytest.raises(Exception):
        cannot_share_name(InterferenceGraph(ControlFlowGraph()), typed, untyped)
