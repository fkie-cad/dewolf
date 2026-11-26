"""Tests for the weights file of the conditional out-of-SSA mode."""

import json

import pytest
from decompiler.pipeline.ssa.conditional_attribute_helper import FEATURES, cannot_share_name
from decompiler.pipeline.ssa.conditional_out_of_SSA import BUNDLED_WEIGHTS_FILE, ConditionalOutOfSSA, load_conditional_weights
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Assignment, Constant, Integer, Return, Variable
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def _weights(**changes) -> dict:
    data = {
        "features": list(FEATURES),
        "coefficients": [float(i) for i in range(len(FEATURES))],
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
    with open(BUNDLED_WEIGHTS_FILE) as file:
        assert tuple(json.load(file)["features"]) == FEATURES
    weights = load_conditional_weights()
    assert len(weights.coefficients) == len(FEATURES)


def test_load_weights_file(tmp_path):
    weights = load_conditional_weights(_write(tmp_path, _weights()))
    assert weights.coefficients == [float(i) for i in range(len(FEATURES))]
    assert weights.intercept == -1.5
    assert weights.strategy == 3
    assert weights.min_kept_score == 0.25


def test_min_kept_score_null_is_off(tmp_path):
    assert load_conditional_weights(_write(tmp_path, _weights(min_kept_score=None))).min_kept_score is None


@pytest.mark.parametrize(
    "features",
    [list(reversed(FEATURES)), list(FEATURES)[:-1], list(FEATURES) + ["new_feature"], []],
)
def test_feature_mismatch_fails(tmp_path, features):
    with pytest.raises(ValueError):
        load_conditional_weights(_write(tmp_path, _weights(features=features)))


def test_coefficient_count_mismatch_fails(tmp_path):
    with pytest.raises(ValueError):
        load_conditional_weights(_write(tmp_path, _weights(coefficients=[1.0])))


def test_empty_option_uses_bundled_file():
    assert ConditionalOutOfSSA(_task(""), {}).weights == load_conditional_weights(BUNDLED_WEIGHTS_FILE)


def test_option_path_overrides_bundled_file(tmp_path):
    path = _write(tmp_path, _weights())
    assert ConditionalOutOfSSA(_task(path), {}).weights == load_conditional_weights(path)


def test_cannot_share_name_raises_on_missing_type():
    """A variable without type raises, even if the other one has a type (and the types therefore differ)."""
    typed, untyped = Variable("x", Integer.int32_t(), 0), Variable("y", None, 0)
    with pytest.raises(Exception):
        cannot_share_name(InterferenceGraph(ControlFlowGraph()), typed, untyped)
