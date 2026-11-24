"""The Binary Ninja variable handler stamps each lifted variable with its storage location."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from decompiler.frontend.binaryninja.handlers.variables import VariableHandler
from decompiler.structures.pseudo import Integer, VariableProvenance


def _binja_variable(name="var_8", source_type="StackVariableSourceType", storage=-8):
    return SimpleNamespace(name=name, type=None, source_type=SimpleNamespace(name=source_type), storage=storage)


def _handler():
    lifter = MagicMock()
    lifter.lift.return_value = Integer.int32_t()
    return VariableHandler(lifter)


def test_ssa_variable_gets_provenance():
    ssa_variable = SimpleNamespace(var=_binja_variable(), version=2)
    variable = _handler().lift_variable_ssa(ssa_variable)
    assert variable.ssa_label == 2
    assert variable.provenance == VariableProvenance(source_type="StackVariableSourceType", storage=-8)


def test_non_ssa_variable_gets_provenance():
    variable = _handler().lift_variable(_binja_variable(name="eax", source_type="RegisterVariableSourceType", storage=24))
    assert variable.provenance == VariableProvenance(source_type="RegisterVariableSourceType", storage=24)


def test_missing_storage_information_does_not_break_lifting():
    broken = SimpleNamespace(name="x", type=None)  # no source_type/storage
    variable = _handler().lift_variable_ssa(SimpleNamespace(var=broken, version=0))
    assert variable.name == "x" and variable.provenance is None
