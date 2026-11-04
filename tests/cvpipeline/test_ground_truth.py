"""The cv pipeline's ground truth: no Binary Ninja debug-info import, identity-based source keys."""

import pytest

from cvpipeline import config


def test_pipeline_options_disable_binary_ninja_debug_info():
    pytest.importorskip("binaryninja")
    from cvpipeline.decompilation import make_options

    options = make_options("conditional_training")
    assert options.getboolean("binaryninja.use_debug_info") is False
    assert config.BN_LOAD_OPTIONS == {"analysis.debugInfo.internal": False}


def test_ground_truth_is_recorded_in_the_manifest():
    assert config.RunConfig(projects_dir="/p", k=5, t=4, seed=0, C=1.0).to_json()["ground_truth"] == config.GROUND_TRUTH


def test_manifest_from_before_the_ground_truth_field_is_rejected(tmp_path):
    from cvpipeline.storage import write_json_atomic

    write_json_atomic(tmp_path / config.MANIFEST, {"projects_dir": "/p", "k": 5, "t": 4, "seed": 0, "C": 1.0})
    with pytest.raises(config.ConfigMismatch):
        config.check_or_write(tmp_path, config.RunConfig(projects_dir="/p", k=5, t=4, seed=0, C=1.0))


def test_same_name_different_identity_are_different_sources():
    from cvpipeline.variable_matching import MatchKind, classify_source, undermerged, VariableMatch
    from decompiler.structures.pseudo import Integer, Variable, VariableProvenance

    first = Variable("var_0", Integer.int32_t(), origin=VariableProvenance(source_name="i", source_id=0x40))
    second = Variable("var_1", Integer.int32_t(), origin=VariableProvenance(source_name="i", source_id=0x80))
    (key_first, kind), (key_second, _) = classify_source(first), classify_source(second)
    assert kind is MatchKind.DWARF_LOCAL and key_first != key_second
    matches = [
        VariableMatch("var_0", "a#1", key_first, MatchKind.DWARF_LOCAL, "i"),
        VariableMatch("var_1", "b#1", key_second, MatchKind.DWARF_LOCAL, "i"),
    ]
    assert undermerged(matches) == {}  # two distinct `i` in two output variables is correct, not an under-merge
