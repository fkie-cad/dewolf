"""The cv pipeline's ground truth: no Binary Ninja debug-info import, identity-based source keys."""

import pytest

from cvpipeline import config


def test_pipeline_options_disable_binary_ninja_debug_info():
    pytest.importorskip("binaryninja")
    from cvpipeline.decompilation import make_options

    options = make_options("conditional_training")
    assert options.getboolean("binaryninja.use_debug_info") is False
    assert config.BN_LOAD_OPTIONS["analysis.debugInfo.internal"] is False


def test_every_stage_loads_binaries_with_the_same_binary_ninja_options(monkeypatch, tmp_path):
    """Fingerprinting and decompilation must hand Binary Ninja exactly config.BN_LOAD_OPTIONS, incl. a
    generous analysis time limit (a function cut off mid-analysis changes the IL of its callers)."""
    binaryninja = pytest.importorskip("binaryninja")
    from cvpipeline import corpus, decompilation

    assert config.BN_LOAD_OPTIONS["analysis.limits.maxFunctionAnalysisTime"] >= 300_000
    seen = []

    def fake_load(path, options=None):
        seen.append(dict(options or {}))
        return None

    monkeypatch.setattr(binaryninja, "load", fake_load)
    corpus.fingerprint_binary("unused", str(tmp_path / "fingerprints.json"), str(tmp_path / "errors.log"))
    with pytest.raises(RuntimeError):
        with decompilation.open_frontend("unused", decompilation.make_options("min")):
            pass
    assert seen == [config.BN_LOAD_OPTIONS, config.BN_LOAD_OPTIONS]
    assert decompilation.make_options("min").getint("binaryninja.max_function_size") == config.BN_LOAD_OPTIONS["analysis.limits.maxFunctionSize"]


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
