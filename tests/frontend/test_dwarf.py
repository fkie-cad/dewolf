"""Unit and end-to-end tests for the DWARF parsing in the binaryninja frontend.

The unit tests exercise _die_name and _decode_storage directly (with stub DIEs / opcodes, no binary);
the gcc-gated end-to-end tests parse a compiled sample to cover inlined-function recovery and the
location-list base address.
"""

import pathlib
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Optional

import pytest

from decompiler.frontend.binaryninja.dwarf import _die_name


@dataclass
class _Attr:
    """Stub of a pyelftools attribute; only `value` is read by _die_name for DW_AT_name."""

    value: bytes


@dataclass
class _Die:
    """Minimal pyelftools DIE stub: attributes map names to an _Attr (DW_AT_name) or a target _Die (references)."""

    offset: int
    attributes: Dict[str, object] = field(default_factory=dict)

    def get_DIE_from_attribute(self, name: str) -> "_Die":
        target = self.attributes[name]
        assert isinstance(target, _Die), "reference attribute must point at a DIE"
        return target


def _named(offset: int, name: str) -> _Die:
    return _Die(offset, {"DW_AT_name": _Attr(name.encode())})


def test_direct_name_is_returned():
    assert _die_name(_named(1, "counter")) == "counter"


def test_unnamed_die_without_links_is_none():
    assert _die_name(_Die(1)) is None


def test_name_followed_through_abstract_origin():
    """A concrete instance with no name of its own resolves to the abstract DIE's name."""
    abstract = _named(10, "helper")
    concrete = _Die(20, {"DW_AT_abstract_origin": abstract})
    assert _die_name(concrete) == "helper"


def test_name_followed_through_specification():
    spec = _named(10, "method")
    definition = _Die(20, {"DW_AT_specification": spec})
    assert _die_name(definition) == "method"


def test_direct_name_wins_over_link():
    """A DIE that has both its own name and a link uses its own name (no dereference)."""
    other = _named(10, "wrong")
    die = _Die(20, {"DW_AT_name": _Attr(b"right"), "DW_AT_abstract_origin": other})
    assert _die_name(die) == "right"


def test_name_followed_through_chain_of_links():
    """abstract_origin can point at another unnamed DIE that itself links to the name."""
    root = _named(10, "deep")
    middle = _Die(20, {"DW_AT_abstract_origin": root})
    leaf = _Die(30, {"DW_AT_abstract_origin": middle})
    assert _die_name(leaf) == "deep"


def test_cyclic_links_do_not_recurse_forever():
    """Malformed DWARF with a reference cycle terminates and yields None instead of recursing."""
    first = _Die(10)
    second = _Die(20, {"DW_AT_abstract_origin": first})
    first.attributes["DW_AT_abstract_origin"] = second
    assert _die_name(first) is None


class _RaisingDie(_Die):
    def get_DIE_from_attribute(self, name: str):
        raise ValueError("unresolvable reference")


def test_unresolvable_reference_is_swallowed():
    """A reference that cannot be resolved does not raise; the DIE is treated as unnamed."""
    die = _RaisingDie(20, {"DW_AT_abstract_origin": _named(10, "unused")})
    assert _die_name(die) is None


# --------------------------------------------------------------------------------------------- #
# End-to-end against a real DWARF binary (no Binary Ninja needed - parses the model directly).
# Gated on gcc + pyelftools; skips cleanly where the toolchain is unavailable or does not emit the
# concrete out-of-line instance of an inlined function (the shape this fix targets).
# --------------------------------------------------------------------------------------------- #

# A static function whose address is taken: gcc -O2 inlines the direct call yet must still emit an
# out-of-line copy, which DWARF records as a concrete instance naming itself only via
# DW_AT_abstract_origin - the case that dropped whole functions from the model before the fix.
_INLINE_SOURCE = """\
#include <stdio.h>
static int helper(int factor, int base) {
    int scaled = factor * 7;
    int shifted = scaled + base;
    return shifted;
}
int (*volatile keep)(int, int) = helper;
int main(int argc, char** argv) {
    int r = helper(argc, 3);
    printf("%d %d\\n", r, keep(argc, 5));
    return r;
}
"""


def _has_anonymous_concrete_instance(path: str, function_name: str) -> bool:
    """True if the DWARF has a subprogram with low_pc, no direct name, whose abstract origin is `function_name`.

    The concrete-out-of-line-instance shape the fix handles. Resolves the origin name here (not via the
    code under test) so reverting the fix makes the guarded test fail rather than silently skip.
    """
    elffile = pytest.importorskip("elftools.elf.elffile")

    def origin_name(die):
        for attr in ("DW_AT_abstract_origin", "DW_AT_specification"):
            if attr in die.attributes:
                referenced = die.get_DIE_from_attribute(attr)
                direct = referenced.attributes.get("DW_AT_name")
                return direct.value.decode() if direct else origin_name(referenced)
        return None

    with open(path, "rb") as handle:
        dwarf = elffile.ELFFile(handle).get_dwarf_info()
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                attributes = die.attributes
                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in attributes or "DW_AT_name" in attributes:
                    continue
                if origin_name(die) == function_name:
                    return True
    return False


@pytest.fixture(scope="module", params=["-g", "-gdwarf-4"], ids=["default", "dwarf4"])
def inline_binary(request, tmp_path_factory):
    """Compile the inline sample with gcc -O2 at the requested debug flag; skip if the toolchain fails.

    Parametrized over the toolchain default and explicit DWARF 4 - the latter is what exposed the
    location-list base-address bug (its .debug_loc uses base-relative entries with no base selection).
    """
    pytest.importorskip("elftools")
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    directory = tmp_path_factory.mktemp("dwarf_inline")
    source = directory / "inl.c"
    source.write_text(_INLINE_SOURCE)
    out = directory / "inl.g"
    result = subprocess.run(["gcc", request.param, "-O2", "-o", str(out), str(source)], capture_output=True)
    if result.returncode != 0 or not out.exists():
        pytest.skip(f"could not build inline binary with {request.param}: {result.stderr.decode()[:200]}")
    if out.read_bytes()[:4] != b"\x7fELF":  # macOS 'gcc' is clang -> Mach-O, which this ELF/DWARF path cannot read
        pytest.skip("compiler did not produce an ELF binary")
    return str(out)


def test_inlined_function_concrete_instance_is_recovered(inline_binary):
    """The out-of-line copy of an inlined function, named only via abstract_origin, is parsed.

    Regression guard for the drop: before following DW_AT_abstract_origin, the anonymous concrete
    instance was skipped and `helper` was absent from the model entirely.
    """
    from decompiler.frontend.binaryninja.dwarf import _parse_dwarf

    if not _has_anonymous_concrete_instance(inline_binary, "helper"):
        pytest.skip("compiler did not emit an anonymous concrete instance of the inlined function")
    functions = {function.name: function for function in _parse_dwarf(inline_binary).values()}
    assert "helper" in functions, "inlined function's out-of-line instance was dropped from the DWARF model"
    variable_names = {variable.name for variable in functions["helper"].variables}
    # Names come from the abstract DIE via abstract_origin; the parameters are the reliable subset.
    assert {"factor", "base"} <= variable_names, f"expected params factor/base among {sorted(variable_names)}"


def _function_bodies(path: str):
    """Return (cu_base, {name: (low_pc, high_pc)}) for every named subprogram, high_pc normalized absolute."""
    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as handle:
        dwarf = ELFFile(handle).get_dwarf_info()
        unit = next(dwarf.iter_CUs())
        base_attr = unit.get_top_DIE().attributes.get("DW_AT_low_pc")
        cu_base = base_attr.value if base_attr is not None else 0
        bodies = {}
        for die in unit.iter_DIEs():
            if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes or "DW_AT_high_pc" not in die.attributes:
                continue
            low = die.attributes["DW_AT_low_pc"].value
            high_attr = die.attributes["DW_AT_high_pc"]
            high = high_attr.value if high_attr.form == "DW_FORM_addr" else low + high_attr.value
            name = _die_name(die)
            if name is not None:
                bodies[name] = (low, high)
        return cu_base, bodies


def test_location_list_ranges_are_relative_to_cu_base(inline_binary):
    """A function's location-list PC ranges must fall inside its own body (checked on non-CU-base functions).

    Regression guard for the base-address bug: offsets are relative to the CU base, not the function's,
    so using the function's low_pc shifted ranges outside the body and broke matching off the CU base.
    """
    from decompiler.frontend.binaryninja.dwarf import RangedLocation, _parse_dwarf

    cu_base, bodies = _function_bodies(inline_binary)
    functions = {function.name: function for function in _parse_dwarf(inline_binary).values()}
    checked = 0
    for name, function in functions.items():
        if name not in bodies or bodies[name][0] == cu_base:
            continue  # a function at the CU base cannot distinguish the bug
        low, high = bodies[name]
        for variable in function.variables:
            if not isinstance(variable.location, RangedLocation):
                continue
            for pc_range in variable.location.ranges:
                checked += 1
                assert low <= pc_range.low < high, (
                    f"{name}.{variable.name} range [{pc_range.low:#x},{pc_range.high:#x}) lies outside the "
                    f"function body [{low:#x},{high:#x}) - location-list base address is wrong"
                )
    if checked == 0:
        pytest.skip("no location-list ranges in a non-CU-base function to check")


# --------------------------------------------------------------------------------------------- #
# Storage decoding: frame-pointer-relative stack slots (DW_OP_breg <fp>). Exercises _decode_storage
# directly on an x64 parser with stub opcodes - needs pyelftools (for describe_reg_name) but no binary.
# --------------------------------------------------------------------------------------------- #


@dataclass
class _Op:
    """Stub of a parsed DWARF expression opcode: an opcode number and its arguments."""

    op: int
    args: tuple = ()


def _x64_parser():
    """An _DwarfParser wired for x64 without opening a binary (only the decode fields are set)."""
    pytest.importorskip("elftools")
    from decompiler.frontend.binaryninja.dwarf import _DwarfParser

    parser = object.__new__(_DwarfParser)
    parser._arch = "x64"
    parser._cfa_delta = 8
    parser._frame_pointer = "rbp"
    return parser


def test_decode_frame_pointer_relative_stack_slot():
    """DW_OP_breg6 (rbp) off resolves to a stack slot at off - cfa_delta (verified against BN storages)."""
    from decompiler.frontend.binaryninja.dwarf import StackSlot

    parser = _x64_parser()
    assert parser._decode_storage([_Op(0x76, (-44,))]) == StackSlot(-52)  # DW_OP_breg6 -44 -> -52 (== BN 'sw')
    assert parser._decode_storage([_Op(0x76, (-128,))]) == StackSlot(-136)


def test_decode_stack_pointer_relative_is_unmatched():
    """DW_OP_breg7 (rsp) needs per-PC frame-unwind state we do not track, so it decodes to None."""
    parser = _x64_parser()
    assert parser._decode_storage([_Op(0x77, (24,))]) is None  # DW_OP_breg7 +24


def test_decode_frame_base_and_register_still_work():
    """The pre-existing DW_OP_fbreg and DW_OP_reg forms are unaffected by the breg addition."""
    from decompiler.frontend.binaryninja.dwarf import RegisterSlot, StackSlot

    parser = _x64_parser()
    assert parser._decode_storage([_Op(0x91, (-32,))]) == StackSlot(-24)  # DW_OP_fbreg -32 -> -32 + 8
    assert parser._decode_storage([_Op(0x56)]) == RegisterSlot("rbp")  # DW_OP_reg6 -> rbp


def test_decode_fbreg_off_frame_pointer_register():
    """With a register frame base (clang's rbp) DW_OP_fbreg is relative to it, not the CFA (verified against BN)."""
    from decompiler.frontend.binaryninja.dwarf import StackSlot

    parser = _x64_parser()
    # clang emits DW_AT_frame_base = DW_OP_reg6 (rbp); DW_OP_fbreg then means rbp + off -> off - cfa_delta.
    assert parser._decode_storage([_Op(0x91, (-8,))], "rbp") == StackSlot(-16)  # main's argc slot
    assert parser._decode_storage([_Op(0x91, (-28,))], "rbp") == StackSlot(-36)  # main's local_iter slot


def test_decode_computed_value_is_unmatched():
    """A location ending in DW_OP_stack_value is a computed value living nowhere, so it decodes to None."""
    parser = _x64_parser()
    # DW_OP_breg6 -96; DW_OP_deref; DW_OP_stack_value  -> a pointer computation, not a stored slot
    assert parser._decode_storage([_Op(0x76, (-96,)), _Op(0x06), _Op(0x9F)]) is None




# --------------------------------------------------------------------------------------------- #
# Resolver selection (no binary): identity, scopes for shared locations, the register lookup PC,
# and address-keyed functions with a load bias.
# --------------------------------------------------------------------------------------------- #


def _origin(source_type="StackVariableSourceType", storage=-20, def_address=0x1010, function=0x1000, has_real_def=True):
    from decompiler.structures.pseudo import VariableProvenance

    return VariableProvenance(
        source_type=source_type, storage=storage, def_address=def_address, function=function, has_real_def=has_real_def
    )


def _resolver_with_function(variables, low_pc=0x1000, image_base=0, parameters=()):
    from decompiler.frontend.binaryninja.dwarf import DwarfFunction, DwarfVariableResolver

    resolver = DwarfVariableResolver(None)  # inert: no binary is opened
    resolver._functions = {low_pc: DwarfFunction(low_pc, tuple(variables), tuple(parameters), "f")}
    resolver._image_base = image_base
    return resolver


def _stack_variable(name, die_offset, storage=-20, scope=None, depth=0):
    from decompiler.frontend.binaryninja.dwarf import DwarfVariable, FixedLocation, StackSlot

    return DwarfVariable(name, FixedLocation(StackSlot(storage)), die_offset, scope, depth)


def test_single_location_match_carries_name_and_identity():
    from decompiler.frontend.binaryninja.dwarf import SourceMatch

    resolver = _resolver_with_function([_stack_variable("i", 0x40)])
    assert resolver.source_match(_origin()) == SourceMatch("i", 0x40)
    assert resolver.source_name(_origin()) == "i"


def test_same_name_in_two_scopes_gives_two_identities():
    """Two loops' `i` sharing one slot: the defining instruction's scope decides, and the identities differ."""
    first = _stack_variable("i", 0x40, scope=((0x1000, 0x1020),), depth=1)
    second = _stack_variable("i", 0x80, scope=((0x1020, 0x1040),), depth=1)
    resolver = _resolver_with_function([first, second])
    assert resolver.source_match(_origin(def_address=0x1010)).die_offset == 0x40
    assert resolver.source_match(_origin(def_address=0x1030)).die_offset == 0x80


def test_shared_slot_prefers_innermost_scope_over_first_match():
    """A function-level variable and a block variable sharing a slot: inside the block the block's wins."""
    outer = _stack_variable("outer", 0x40)
    inner = _stack_variable("inner", 0x80, scope=((0x1008, 0x1018),), depth=1)
    resolver = _resolver_with_function([outer, inner])
    assert resolver.source_name(_origin(def_address=0x1010)) == "inner"
    assert resolver.source_name(_origin(def_address=0x1030)) == "outer"


def test_ambiguous_shared_slot_stays_unmatched():
    """Two variables of the same depth whose scopes both contain the definition: no guess."""
    first = _stack_variable("a", 0x40, scope=((0x1000, 0x1040),), depth=1)
    second = _stack_variable("b", 0x80, scope=((0x1000, 0x1040),), depth=1)
    resolver = _resolver_with_function([first, second])
    assert resolver.source_match(_origin(def_address=0x1010)) is None


def test_register_location_list_is_read_after_the_defining_instruction():
    """At the defining instruction DWARF still describes the register's previous occupant; the range
    of the newly written variable starts at the next instruction, which lookup_pc points at."""
    from decompiler.frontend.binaryninja.dwarf import DwarfVariable, PcRange, RangedLocation, RegisterSlot

    old = DwarfVariable("old", RangedLocation((PcRange(0x1000, 0x1014, RegisterSlot("rax")),)), 0x40)
    new = DwarfVariable("new", RangedLocation((PcRange(0x1014, 0x1030, RegisterSlot("rax")),)), 0x80)
    resolver = _resolver_with_function([old, new])
    origin = _origin(source_type="RegisterVariableSourceType", storage=0, def_address=0x1010)
    rax = lambda index: "rax"
    assert resolver.source_name(origin, lookup_pc=0x1014, register_name=rax) == "new"
    assert resolver.source_name(origin, register_name=rax) == "old"  # looked up at the definition itself


def test_functions_are_found_by_address_with_load_bias():
    """A PIE (DWARF image base 0) mapped at 0x400000: function entry and def address are both shifted."""
    resolver = _resolver_with_function([_stack_variable("i", 0x40, scope=((0x1000, 0x1020),), depth=1)])
    origin = _origin(def_address=0x401010, function=0x401000)
    assert resolver.source_name(origin, load_base=0x400000) == "i"
    assert resolver.source_name(origin) is None  # without the bias the function is not found
    assert resolver.function_at(0x401000, 0x400000).name == "f"


# --------------------------------------------------------------------------------------------- #
# Global address matching: a global's DWARF location is an absolute address, so the disassembler's
# load address must be subtracted (a PIE is mapped at a different base than the DWARF addresses).
# --------------------------------------------------------------------------------------------- #


def _resolver_with_globals(globals_by_name_and_address: dict, image_base: int):
    from decompiler.frontend.binaryninja.dwarf import DwarfVariableResolver, SourceMatch

    resolver = DwarfVariableResolver(None)  # inert: no binary is opened
    resolver._globals = {address: SourceMatch(name, address) for address, name in globals_by_name_and_address.items()}
    resolver._image_base = image_base
    return resolver


def test_global_source_name_without_load_base_looks_up_as_is():
    resolver = _resolver_with_globals({0x50BE: "nl"}, image_base=0)
    assert resolver.global_source_name(0x50BE) == "nl"
    assert resolver.global_source_name(0x9999) is None
    assert resolver.global_source_name(None) is None


def test_global_source_name_subtracts_pie_load_bias():
    """A PIE (DWARF image base 0) mapped at 0x400000: the disassembler address is dwarf_addr + bias."""
    resolver = _resolver_with_globals({0x50BE: "nl"}, image_base=0)
    assert resolver.global_source_name(0x4050BE, load_base=0x400000) == "nl"  # 0x4050be - (0x400000 - 0) == 0x50be
    assert resolver.global_match(0x4050BE, load_base=0x400000).die_offset == 0x50BE


def test_global_source_name_zero_bias_when_load_base_matches_image_base():
    """A non-PIE (load address == DWARF image base) has zero bias, so the address is unchanged."""
    resolver = _resolver_with_globals({0x400500: "g"}, image_base=0x400000)
    assert resolver.global_source_name(0x400500, load_base=0x400000) == "g"


# --------------------------------------------------------------------------------------------- #
# Entry registers from the System V calling convention (parameter_sources.sysv_entry_registers).
# --------------------------------------------------------------------------------------------- #


_EIGHTBYTES = {"integer": ("integer",), "sse": ("sse",), "memory": (), "other": None}


def _sysv(parameters, returns_in_memory=False):
    """Registers -> names for parameters given as (name, class name or tuple of eightbyte classes)."""
    from decompiler.frontend.binaryninja.dwarf import DwarfFunction, DwarfParameter
    from decompiler.frontend.binaryninja.parameter_sources import sysv_entry_registers

    function = DwarfFunction(
        0x1000,
        (),
        tuple(
            DwarfParameter(name, offset, eightbytes=_EIGHTBYTES[kind] if isinstance(kind, str) else kind)
            for offset, (name, kind) in enumerate(parameters, start=1)
        ),
        "f",
        returns_in_memory,
    )
    return {register: match.name for register, match in sysv_entry_registers(function).items()}


def test_sysv_integer_and_sse_classes_are_counted_separately():
    assert _sysv([("a", "integer"), ("b", "sse"), ("c", "integer"), ("d", "sse")]) == {"rdi": "a", "xmm0": "b", "rsi": "c", "xmm1": "d"}


def test_sysv_hidden_result_pointer_shifts_integer_registers():
    assert _sysv([("a", "integer"), ("b", "integer")], returns_in_memory=True) == {"rsi": "a", "rdx": "b"}


def test_sysv_memory_parameters_consume_no_register():
    assert _sysv([("big", "memory"), ("a", "integer")]) == {"rdi": "a"}


def test_sysv_unknown_layout_stops_assignment():
    """A parameter whose layout could not be classified may take any registers: everything after it stays unnamed."""
    assert _sysv([("a", "integer"), ("s", "other"), ("b", "integer"), ("x", "sse")]) == {"rdi": "a"}


def test_sysv_unclassifiable_return_names_nothing():
    """Unknown whether rdi carries a hidden result pointer: no register is named."""
    assert _sysv([("a", "integer")], returns_in_memory=None) == {}


def test_sysv_small_aggregates_take_one_register_per_eightbyte():
    """Only the first eightbyte's register is named; the second one is consumed."""
    pair, mixed = ("integer", "integer"), ("sse", "integer")
    assert _sysv([("a", "integer"), ("p", pair), ("cmp", "integer")]) == {"rdi": "a", "rsi": "p", "rcx": "cmp"}
    assert _sysv([("m", mixed), ("k", "integer"), ("x", "sse")]) == {"xmm0": "m", "rsi": "k", "xmm1": "x"}


def test_sysv_aggregate_without_enough_registers_goes_to_the_stack():
    """A two-register struct with one register left is passed in memory; later parameters still get it."""
    five = [(f"p{index}", "integer") for index in range(5)]
    assert _sysv(five + [("s", ("integer", "integer")), ("g", "integer")])["r9"] == "g"


def test_sysv_unnamed_parameter_consumes_its_register():
    assert _sysv([(None, "integer"), ("b", "integer")]) == {"rsi": "b"}


def test_sysv_parameters_beyond_the_registers_are_on_the_stack():
    names = [(f"p{index}", "integer") for index in range(7)]
    table = _sysv(names)
    assert table["r9"] == "p5" and "p6" not in table.values()


def test_canonical_register_names():
    from decompiler.frontend.binaryninja.parameter_sources import canonical_register

    assert canonical_register(None, "zmm3") == "xmm3"
    assert canonical_register(None, "ymm0") == "xmm0"
    assert canonical_register(None, "rdi") == "rdi"


# --------------------------------------------------------------------------------------------- #
# End-to-end against compiled samples (gcc + pyelftools, no Binary Ninja).
# --------------------------------------------------------------------------------------------- #


def _compile(tmp_path_factory, name: str, sources: Dict[str, str], flags) -> str:
    pytest.importorskip("elftools")
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    directory = tmp_path_factory.mktemp(name)
    paths = []
    for file_name, text in sources.items():
        path = directory / file_name
        path.write_text(text)
        paths.append(str(path))
    out = directory / name
    result = subprocess.run(["gcc", *flags, "-o", str(out), *paths], capture_output=True)
    if result.returncode != 0 or not out.exists() or out.read_bytes()[:4] != b"\x7fELF":
        pytest.skip(f"could not build {name}: {result.stderr.decode()[:200]}")
    return str(out)


def _functions_by_name(path: str):
    from decompiler.frontend.binaryninja.dwarf import _parse_dwarf

    by_name: Dict[str, list] = {}
    for function in _parse_dwarf(path).values():
        by_name.setdefault(function.name, []).append(function)
    return by_name


_SCOPES_SOURCE = """\
int work(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) { total += i; }
    for (int i = 0; i < n; i++) { total -= i * 3; }
    return total;
}
int main(int argc, char **argv) { return work(argc); }
"""


def test_same_named_locals_get_distinct_identities_and_scopes(tmp_path_factory):
    binary = _compile(tmp_path_factory, "scopes", {"scopes.c": _SCOPES_SOURCE}, ["-g", "-O0"])
    (work,) = _functions_by_name(binary)["work"]
    loop_counters = [variable for variable in work.variables if variable.name == "i"]
    assert len(loop_counters) == 2
    assert loop_counters[0].die_offset != loop_counters[1].die_offset
    assert all(variable.scope is not None and variable.depth >= 1 for variable in loop_counters)
    (total,) = [variable for variable in work.variables if variable.name == "total"]
    assert total.scope is None and total.depth == 0


_STATIC_A = "static int helper(int x) { int la = x + 1; return la; }\nint fa(int x) { return helper(x); }\n"
_STATIC_B = "static int helper(int y) { int lb = y * 2; return lb; }\nint fb(int y) { return helper(y); }\n"
_STATIC_MAIN = "int fa(int); int fb(int);\nint main(int argc, char **argv) { return fa(argc) + fb(argc); }\n"


def test_static_functions_with_the_same_name_are_kept_apart(tmp_path_factory):
    """Keyed by address, two `static helper` of different units no longer overwrite each other."""
    binary = _compile(tmp_path_factory, "statics", {"a.c": _STATIC_A, "b.c": _STATIC_B, "main.c": _STATIC_MAIN}, ["-g", "-O0"])
    helpers = _functions_by_name(binary)["helper"]
    assert len(helpers) == 2 and helpers[0].low_pc != helpers[1].low_pc
    assert sorted(sorted(variable.name for variable in helper.variables) for helper in helpers) == [["la", "x"], ["lb", "y"]]


_TYPES_SOURCE = """\
struct small { int a; int b; };
struct big { long a, b, c; };
int f(int a, double b, char *c, struct big s, long double ld, int d) { return a + (int)b + c[0] + (int)s.a + (int)ld + d; }
struct big g(int a) { struct big r = {a, a, a}; return r; }
int h(struct small s, int a) { return s.a + a; }
int main(void) { struct big s = {1, 2, 3}; struct small t = {1, 2}; char c = 0; return f(1, 2.0, &c, s, 3.0L, 4) + (int)g(5).a + h(t, 6); }
"""


def test_parameter_type_classes_and_sysv_registers(tmp_path_factory):
    from decompiler.frontend.binaryninja.parameter_sources import sysv_entry_registers

    binary = _compile(tmp_path_factory, "types", {"types.c": _TYPES_SOURCE}, ["-g", "-O0"])
    functions = {name: found[0] for name, found in _functions_by_name(binary).items()}
    f = functions["f"]
    assert [(p.name, p.type_class) for p in f.parameters] == [
        ("a", "integer"),
        ("b", "sse"),
        ("c", "integer"),
        ("s", "memory"),
        ("ld", "memory"),
        ("d", "integer"),
    ]
    names = lambda function: {register: match.name for register, match in sysv_entry_registers(function).items()}
    assert names(f) == {"rdi": "a", "xmm0": "b", "rsi": "c", "rdx": "d"}
    assert functions["g"].returns_in_memory and names(functions["g"]) == {"rsi": "a"}
    assert names(functions["h"]) == {"rdi": "s", "rsi": "a"}  # struct small {int, int}: one INTEGER eightbyte
    assert functions["main"].parameters == () and names(functions["main"]) == {}


_INLINED_LOCALS_SOURCE = """\
static inline int mix(int v) { int t = v * v + 7; return t ^ (v >> 3); }
int main(int argc, char **argv) { return mix(argc) + mix(argc + (int)argv[0][0]); }
"""


def _inlined_has_located_children(path: str, caller: str) -> bool:
    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as handle:
        dwarf = ELFFile(handle).get_dwarf_info()
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or _die_name(die) != caller:
                    continue
                stack = list(die.iter_children())
                while stack:
                    child = stack.pop()
                    if child.tag == "DW_TAG_inlined_subroutine":
                        if any("DW_AT_location" in grandchild.attributes for grandchild in child.iter_children()):
                            return True
                    stack.extend(child.iter_children())
    return False


def test_locals_of_inlined_functions_are_parsed(tmp_path_factory):
    binary = _compile(tmp_path_factory, "inlined", {"inlined.c": _INLINED_LOCALS_SOURCE}, ["-g", "-O2"])
    if not _inlined_has_located_children(binary, "main"):
        pytest.skip("compiler emitted no located variables for the inlined instances")
    (main,) = _functions_by_name(binary)["main"]
    inlined = [variable for variable in main.variables if variable.name in ("v", "t")]
    assert inlined, f"no inlined locals among {sorted(variable.name for variable in main.variables)}"
    assert all(variable.depth >= 1 and variable.scope is not None for variable in inlined)
    assert len({variable.die_offset for variable in inlined if variable.name == "v"}) == len([v for v in inlined if v.name == "v"])


_AGGREGATES_SOURCE = """\
struct pair { long a, b; };
struct dpair { double x, y; };
struct mixed { double d; long l; };
struct small { int a; float f; };
struct card { int rank; int suit; };
struct withld { long double x; };
struct tiny { char c[3]; };
union number { int i; float f; };
struct packed { char c; int i; } __attribute__((packed));
struct empty { };
long bf(long a, long b, struct pair p, long (*cmp)(void)) { return a + b + p.a + p.b + cmp(); }
long ex(long a, long b, long c, long d, long e, struct pair p, long g) { return a + b + c + d + e + p.a + g; }
double mx(struct mixed m, int k, struct dpair q, struct small s) { return m.d + m.l + k + q.x + q.y + s.a + s.f; }
int cd(struct card a, const struct card *b, int n, struct tiny t) { return a.rank + b->suit + n + t.c[0]; }
long double ld(struct withld w, int k) { return w.x + k; }
int un(union number u, struct packed p, int k) { return u.i + p.i + k; }
struct dpair rd(int a) { struct dpair r = {a, a}; return r; }
int em(struct empty e, int a) { (void)e; return a; }
long call(void) { return 1; }
int main(void) {
    struct pair p = {1, 2}; struct mixed m = {1.0, 2}; struct dpair q = {1.0, 2.0}; struct small s = {1, 2.0f};
    struct card c = {1, 2}; struct withld w = {1.0L}; struct tiny t = {{1, 2, 3}}; union number u = {1}; struct packed k = {1, 2};
    struct empty e = {};
    return (int)(bf(1, 2, p, call) + ex(1, 2, 3, 4, 5, p, 7) + mx(m, 1, q, s) + cd(c, &c, 1, t) + ld(w, 1) + un(u, k, 1) + rd(1).x + em(e, 1));
}
"""


def test_aggregates_are_classified_like_gcc_passes_them(tmp_path_factory):
    """Register tables for structs passed by value, checked once against gcc -O0 prologues:
    bf: rdi, rsi, rdx+rcx (pair), r8; ex: pair on the stack, g in r9; mx: xmm0+rdi (mixed), esi,
    xmm1+xmm2 (dpair), rdx (small); cd: rdi (card), rsi, edx, rcx (tiny); ld: withld in memory, edi."""
    from decompiler.frontend.binaryninja.parameter_sources import sysv_entry_registers

    binary = _compile(tmp_path_factory, "aggregates", {"aggregates.c": _AGGREGATES_SOURCE}, ["-g", "-O0"])
    functions = {name: found[0] for name, found in _functions_by_name(binary).items()}
    names = lambda name: {register: match.name for register, match in sysv_entry_registers(functions[name]).items()}
    assert names("bf") == {"rdi": "a", "rsi": "b", "rdx": "p", "r8": "cmp"}
    assert names("ex") == {"rdi": "a", "rsi": "b", "rdx": "c", "rcx": "d", "r8": "e", "r9": "g"}
    assert names("mx") == {"xmm0": "m", "rsi": "k", "xmm1": "q", "rdx": "s"}
    assert names("cd") == {"rdi": "a", "rsi": "b", "rdx": "n", "rcx": "t"}
    assert names("ld") == {"rdi": "k"}
    assert names("un") == {"rdi": "u", "rsi": "k"}  # union {int, float}: INTEGER; packed struct: memory
    assert functions["rd"].returns_in_memory is False and names("rd") == {"rdi": "a"}  # dpair returned in xmm0/xmm1
    assert names("em") == {"rdi": "a"}  # an empty struct (GNU C, size 0) takes no register
    classes = {p.name: p.eightbytes for p in functions["mx"].parameters}
    assert classes == {"m": ("sse", "integer"), "k": ("integer",), "q": ("sse", "sse"), "s": ("integer",)}
