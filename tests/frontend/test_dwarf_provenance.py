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


# --------------------------------------------------------------------------------------------- #
# Lifting without Binary Ninja's debug-info import: the IL must not depend on DWARF, while the
# origins are still matched from it (identity, entry-register parameters).
# --------------------------------------------------------------------------------------------- #

_NO_DEBUG_SOURCE = """\
struct small { int a; int b; };
struct big { long a, b, c; };
int f(int a, double b, int c) { int total = a + c; total += (int)b; return total; }
struct big g(int a, int b) { struct big r = {a, b, a}; return r; }
int h(struct small s, int a) { return s.a + a; }
struct pair { long a, b; };
struct mixed { double d; long l; };
long bf(long a, long b, struct pair p, long (*cmp)(void)) { return a + b + p.a + p.b + cmp(); }
double mx(struct mixed m, int k) { return m.d + m.l + k; }
long call(void) { return 1; }
int loops(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) { total += i; }
    for (int i = 0; i < n; i++) { total -= i * 3; }
    return total;
}
int main(void) {
    struct small t = {1, 2}; struct pair p = {1, 2}; struct mixed m = {1.0, 2};
    return f(1, 2.0, 3) + (int)g(4, 5).a + h(t, 6) + loops(7) + (int)bf(1, 2, p, call) + (int)mx(m, 3);
}
"""


def _no_debug_options():
    options = Options.load_default_options()
    options.update({"binaryninja.use_debug_info": False})
    return options


@pytest.fixture(scope="module")
def no_debug_binary(tmp_path_factory):
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    directory = tmp_path_factory.mktemp("nodebug")
    source = directory / "nodebug.c"
    source.write_text(_NO_DEBUG_SOURCE)
    out = directory / "nodebug.g"
    result = subprocess.run(["gcc", "-g", "-O0", "-fno-stack-protector", "-o", str(out), str(source)], capture_output=True)
    if result.returncode != 0 or not out.exists():
        pytest.skip(f"could not build sample: {result.stderr.decode()[:200]}")
    return str(out)


@pytest.fixture(scope="module")
def no_debug_frontend(no_debug_binary):
    frontend = BinaryninjaFrontend.from_path(no_debug_binary, _no_debug_options())
    yield frontend
    frontend._bv.file.close()


def _lift(frontend, function_name):
    task = DecompilerTask(function_name, function_name, _no_debug_options())
    frontend.lift(task)
    return [v for instr in task.graph.instructions for v in list(instr.definitions) + list(instr.requirements) if isinstance(v, Variable)]


def _entry_labels(variables):
    """{register name: source name} of the labelled register variables without a real definition."""
    return {
        v.name: v.origin.source_name
        for v in variables
        if v.origin is not None and v.origin.source_name is not None and v.origin.source_type == "RegisterVariableSourceType" and not v.origin.has_real_def
    }


def test_debug_info_option_reaches_binary_ninja(no_debug_frontend):
    view = no_debug_frontend._bv
    assert binaryninja.Settings().get_bool("analysis.debugInfo.internal", view) is False
    function = next(function for function in view.functions if function.name == "f")
    assert [variable.name for variable in function.parameter_vars] != ["a", "b", "c"]  # BN's own names, not DWARF's


def test_from_path_passes_the_debug_info_setting(monkeypatch):
    from decompiler.frontend.binaryninja import frontend as frontend_module

    seen = {}

    def fake_load(path, options=None):
        seen.update(options or {})
        return None

    monkeypatch.setattr(frontend_module.binaryninja, "load", fake_load)
    with pytest.raises(RuntimeError):
        BinaryninjaFrontend.from_path("unused", _no_debug_options())
    assert seen["analysis.debugInfo.internal"] is False
    with pytest.raises(RuntimeError):
        BinaryninjaFrontend.from_path("unused", Options.load_default_options())
    assert seen["analysis.debugInfo.internal"] is True  # default: dewolf behaves as before


def test_entry_registers_are_named_without_debug_info(no_debug_frontend):
    labels = set(_entry_labels(_lift(no_debug_frontend, "f")).values())
    assert {"a", "b", "c"} <= labels, labels
    assert "total" in _source_names(_lift(no_debug_frontend, "f"))


def test_two_loop_counters_have_distinct_identities(no_debug_frontend):
    identities = {
        v.origin.source_id for v in _lift(no_debug_frontend, "loops") if v.origin is not None and v.origin.source_name == "i"
    }
    assert len(identities) == 2, identities


def test_main_without_parameters_gets_no_entry_labels(no_debug_frontend):
    """BN may guess argc/argv/envp for main(void); DWARF has no parameters, so nothing is labelled."""
    assert _entry_labels(_lift(no_debug_frontend, "main")) == {}


def test_entry_parameter_source_on_signatures(no_debug_frontend):
    from decompiler.frontend.binaryninja.parameter_sources import make_parameter_source

    view = no_debug_frontend._bv
    abi = make_parameter_source(view)
    starts = {function.name: function.start for function in view.functions}
    named = lambda name, register: getattr(abi.entry_parameter(starts[name], register, name), "name", None)
    assert [named("f", register) for register in ("rdi", "xmm0", "rsi")] == ["a", "b", "c"]
    assert [named("main", register) for register in ("rdi", "rsi", "rdx")] == [None, None, None]
    # g returns a 24-byte struct: rdi carries the hidden result pointer, a/b arrive in esi/edx (checked
    # against gcc's code).
    assert abi.entry_parameter(starts["g"], "rdi", "g") is None
    assert abi.entry_parameter(starts["g"], "rsi", "g").name == "a"
    assert abi.entry_parameter(starts["g"], "rdx", "g").name == "b"
    # h(struct small s, int a): the 8-byte struct takes one INTEGER register
    for register, name in (("rdi", "s"), ("rsi", "a")):
        assert abi.entry_parameter(starts["h"], register, "h").name == name


def _entry_labels_by_register(frontend, function_name):
    view = frontend._bv
    return {
        view.arch.get_reg_name(v.origin.storage): v.origin.source_name
        for v in _lift(frontend, function_name)
        if v.origin is not None and v.origin.source_name is not None and v.origin.source_type == "RegisterVariableSourceType" and not v.origin.has_real_def
    }


def test_struct_arguments_label_their_first_register(no_debug_frontend):
    """Lifted without debug info: the registers the prologue stores are named per the System V classification."""
    bf = _entry_labels_by_register(no_debug_frontend, "bf")
    assert {bf.get(register) for register in ("rdi", "rsi", "rdx", "r8")} == {"a", "b", "p", "cmp"}
    assert bf.get("rdx") == "p" and bf.get("r8") == "cmp" and "rcx" not in bf  # second half of p unnamed
    mx = _entry_labels_by_register(no_debug_frontend, "mx")
    assert mx.get("xmm0", mx.get("zmm0")) == "m" and mx.get("rsi") == "k"


# --------------------------------------------------------------------------------------------- #
# Register lookup PC: variables.py must look a real definition up right after its defining
# instruction (a location-list range for the new value starts there; at the instruction DWARF still
# describes the overwritten previous occupant), and a phi at the start of its block.
# --------------------------------------------------------------------------------------------- #

_ROTATION_SOURCE = """\
#include <stdio.h>
#include <stdlib.h>
int walk(int n) {
    int fwd = 0, bwd = 0, dir = 1, back = -1, tmp, i = 1, dist;
    while (i <= n) {
        if (dir > 0) fwd = fwd + i; else bwd = bwd + i;
        tmp = dir; dir = back; back = tmp; i = i + 1;
    }
    dist = abs(fwd - bwd);
    printf("distance %d\\n", dist);
    return dist;
}
int main(int argc, char **argv) { return walk(argc > 1 ? atoi(argv[1]) : 5); }
"""


@pytest.fixture(scope="module")
def rotation_frontend(tmp_path_factory):
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    directory = tmp_path_factory.mktemp("rotation")
    source = directory / "walk.c"
    source.write_text(_ROTATION_SOURCE)
    out = directory / "walk"
    result = subprocess.run(["gcc", "-g", "-O2", "-fno-inline", "-o", str(out), str(source)], capture_output=True)
    if result.returncode != 0 or not out.exists():
        pytest.skip(f"could not build sample: {result.stderr.decode()[:200]}")
    frontend = BinaryninjaFrontend.from_path(str(out), _no_debug_options())
    yield frontend
    frontend._bv.file.close()


def test_registers_are_labelled_after_their_defining_instruction(rotation_frontend):
    from decompiler.frontend.binaryninja.dwarf import DwarfVariableResolver
    from decompiler.structures.pseudo import Phi

    view = rotation_frontend._bv
    resolver = DwarfVariableResolver.for_path(view.file.filename)
    task = DecompilerTask("walk", "walk", _no_debug_options())
    rotation_frontend.lift(task)
    phi_defined = {phi.destination for phi in task.graph.instructions if isinstance(phi, Phi)}
    seen = {}
    for instruction in task.graph.instructions:
        for variable in instruction.definitions:
            origin = variable.origin
            if isinstance(variable, Variable) and origin is not None and origin.source_type == "RegisterVariableSourceType" and origin.has_real_def:
                seen[(variable.name, variable.ssa_label)] = variable
    identity = lambda match: match.die_offset if match is not None else None
    decisive = 0
    for variable in seen.values():
        origin = variable.origin
        at_definition = resolver.source_match(origin, view.start, origin.def_address, view.arch.get_reg_name)
        if variable in phi_defined:
            assert origin.source_id == identity(at_definition), f"phi {variable} must be looked up at its block start"
            continue
        after = origin.def_address + view.get_instruction_length(origin.def_address)
        after_definition = resolver.source_match(origin, view.start, after, view.arch.get_reg_name)
        if identity(at_definition) != identity(after_definition):
            decisive += 1
            assert origin.source_id == identity(after_definition), (
                f"{variable} defined at {origin.def_address:#x} carries {origin.source_name}, but DWARF names "
                f"{getattr(after_definition, 'name', None)} after the instruction ({getattr(at_definition, 'name', None)} at it)"
            )
    assert decisive > 0, "the sample produced no definition where the two lookups differ"
