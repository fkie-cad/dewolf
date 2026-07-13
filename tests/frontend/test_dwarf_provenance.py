"""End-to-end test for DWARF source-name resolution during lifting.

Builds a debug (-g) binary from a tracked system-test source, lifts it with the
real Binary Ninja frontend, and asserts that each lifted variable carries the C
source-variable name (Variable.origin.source_name) matched from DWARF.

Gated on Binary Ninja + pyelftools being importable and gcc being available;
skips cleanly otherwise (like the other frontend tests).
"""

import pathlib
import shutil
import subprocess

import pytest

binaryninja = pytest.importorskip("binaryninja")
pytest.importorskip("elftools")

from decompiler.frontend.binaryninja.frontend import BinaryninjaFrontend
from decompiler.structures.pseudo import Variable
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

SOURCE = pathlib.Path("tests/samples/src/systemtests/test_goto.c")


@pytest.fixture(scope="module")
def debug_binary(tmp_path_factory):
    """Compile test_goto.c with debug info; skip if the toolchain/source is unavailable."""
    if shutil.which("gcc") is None or not SOURCE.exists():
        pytest.skip("gcc or test_goto.c source not available")
    out = tmp_path_factory.mktemp("dwarf") / "test_goto.g"
    result = subprocess.run(
        ["gcc", "-g", "-O0", "-fno-stack-protector", "-o", str(out), str(SOURCE)],
        capture_output=True,
    )
    if result.returncode != 0 or not out.exists():
        pytest.skip(f"could not build debug binary: {result.stderr.decode()[:200]}")
    return str(out)


@pytest.fixture(scope="module")
def frontend(debug_binary):
    return BinaryninjaFrontend.from_path(debug_binary, Options.load_default_options())


def _variables(frontend, function_name):
    """Lift a function and return all its lifted Variables (SSA form)."""
    task = DecompilerTask(function_name, function_name, Options.load_default_options())
    frontend.lift(task)
    return [v for instr in task.graph.instructions for v in list(instr.definitions) + list(instr.requirements) if isinstance(v, Variable)]


def _source_names(variables):
    return {v.origin.source_name: v.origin for v in variables if v.origin is not None and v.origin.source_name is not None}


def test_stack_locals_resolve_to_c_names(frontend):
    """test2 has stack locals `needle` and `i`; both must resolve to their C names."""
    names = _source_names(_variables(frontend, "test2"))
    assert "needle" in names, f"expected 'needle' among resolved names, got {sorted(names)}"
    assert "i" in names, f"expected 'i' among resolved names, got {sorted(names)}"
    assert names["needle"].source_type == "StackVariableSourceType"
    assert names["needle"].storage is not None


def test_other_functions_resolve(frontend):
    assert "a" in _source_names(_variables(frontend, "test1"))
    assert "i" in _source_names(_variables(frontend, "test3"))


def test_no_source_variable_is_honest_none(frontend):
    """Variables with no backing source variable (scratch registers, memory) keep source_name=None."""
    variables = _variables(frontend, "test2")
    assert any(v.origin is None or v.origin.source_name is None for v in variables)


def test_source_name_survives_copy(frontend):
    """copy() carries source_name over - the propagation point used by out-of-SSA renaming."""
    names = _source_names(_variables(frontend, "test1"))
    origin = names["a"]
    carrier = Variable("x", origin=origin)
    assert carrier.copy().origin.source_name == "a"
