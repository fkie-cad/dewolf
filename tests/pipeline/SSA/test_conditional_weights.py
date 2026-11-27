"""Tests for the weights file of the conditional out-of-SSA mode."""

import json

import decompiler.pipeline.ssa.outofssatranslation as out_of_ssa_module
import pytest
from decompiler.pipeline.ssa.conditional_attribute_helper import Feature, cannot_share_name
from decompiler.pipeline.ssa.conditional_weights import DEFAULT_WEIGHTS_FILE, ConditionalWeights
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Assignment, Constant, Integer, Return, Variable
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

NAMES = [feature.value for feature in Feature]


def _weights(**changes) -> dict:
    data = {
        "features": NAMES,
        "coefficients": [float(i) for i in range(len(NAMES))],
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
    options.set("out-of-ssa-translation.mode", "conditional")
    options.set("out-of-ssa-translation.conditional_weights", weights_path)
    return DecompilerTask(name="weights-test", function_identifier="", cfg=cfg, options=options)


def test_bundled_file_matches_features():
    with open(DEFAULT_WEIGHTS_FILE) as file:
        assert json.load(file)["features"] == NAMES
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
    "features",
    [NAMES[:-1], NAMES + ["new_feature"], NAMES[:-1] + [NAMES[0]], []],
)
def test_feature_mismatch_fails(tmp_path, features):
    with pytest.raises(ValueError):
        ConditionalWeights.from_file(_write(tmp_path, _weights(features=features)))


def test_feature_order_is_free(tmp_path):
    reversed_names = list(reversed(NAMES))
    weights = ConditionalWeights.from_file(_write(tmp_path, _weights(features=reversed_names)))
    assert weights.coefficients == {Feature(name): float(i) for i, name in enumerate(reversed_names)}


def test_coefficient_count_mismatch_fails(tmp_path):
    with pytest.raises(ValueError):
        ConditionalWeights.from_file(_write(tmp_path, _weights(coefficients=[1.0])))


class _RecordingRenamer(out_of_ssa_module.ConditionalVariableRenamer):
    """The conditional renamer that records the weights it got."""

    received_weights = []

    def __init__(self, task, interference_graph, weights, phi_pairs):
        self.received_weights.append(weights)
        super().__init__(task, interference_graph, weights, phi_pairs)


def _weights_reaching_the_renamer(monkeypatch, weights_path: str):
    """Run the out-of-SSA stage in conditional mode and return the weights the renamer got."""
    monkeypatch.setattr(out_of_ssa_module, "ConditionalVariableRenamer", _RecordingRenamer)
    monkeypatch.setattr(_RecordingRenamer, "received_weights", [])
    OutOfSsaTranslation().run(_task(weights_path))
    return _RecordingRenamer.received_weights


def test_empty_option_uses_bundled_file(monkeypatch):
    assert _weights_reaching_the_renamer(monkeypatch, "") == [ConditionalWeights.from_file(DEFAULT_WEIGHTS_FILE)]


def test_option_path_overrides_bundled_file(monkeypatch, tmp_path):
    path = _write(tmp_path, _weights())
    assert _weights_reaching_the_renamer(monkeypatch, path) == [ConditionalWeights.from_file(path)]


def test_cannot_share_name_raises_on_missing_type():
    """A variable without type raises, even if the other one has a type (and the types therefore differ)."""
    typed, untyped = Variable("x", Integer.int32_t(), 0), Variable("y", None, 0)
    with pytest.raises(Exception):
        cannot_share_name(InterferenceGraph(ControlFlowGraph()), typed, untyped)
