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
    functions = _parse_dwarf(inline_binary)
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
    """A function's location-list address ranges must fall inside its own body (checked on non-CU-base functions).

    Regression guard for the base-address bug: offsets are relative to the CU base, not the function's,
    so using the function's low_pc shifted ranges outside the body and broke matching off the CU base.
    """
    from decompiler.frontend.binaryninja.dwarf import RangedLocation, _parse_dwarf

    cu_base, bodies = _function_bodies(inline_binary)
    functions = _parse_dwarf(inline_binary)
    checked = 0
    for name, function in functions.items():
        if name not in bodies or bodies[name][0] == cu_base:
            continue  # a function at the CU base cannot distinguish the bug
        low, high = bodies[name]
        for variable in function.variables:
            if not isinstance(variable.location, RangedLocation):
                continue
            for address_range in variable.location.ranges:
                checked += 1
                assert low <= address_range.low < high, (
                    f"{name}.{variable.name} range [{address_range.low:#x},{address_range.high:#x}) lies outside the "
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
    """DW_OP_breg7 (rsp) needs per-address frame-unwind state we do not track, so it decodes to None."""
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
# Ordinal parameter fallback (Solution 3): a register parameter has no DWARF location of its own,
# so it is named by its position among the function's parameters. Exercises _parameter_names and
# the guarded DwarfVariableResolver.parameter_name_by_index directly (no binary).
# --------------------------------------------------------------------------------------------- #


@dataclass
class _ParamDie:
    """Minimal subprogram/child DIE stub: a tag, an optional name, and ordered children."""

    tag: str
    name: Optional[str] = None
    children: tuple = ()
    offset: int = 0

    @property
    def attributes(self) -> Dict[str, object]:
        return {"DW_AT_name": _Attr(self.name.encode())} if self.name is not None else {}

    def iter_children(self):
        return iter(self.children)


def _subprogram(*children: _ParamDie) -> _ParamDie:
    return _ParamDie("DW_TAG_subprogram", children=children)


def test_parameter_names_in_declaration_order():
    """Only direct formal-parameter children are collected, in order; locals are ignored."""
    from decompiler.frontend.binaryninja.dwarf import _parameter_names

    die = _subprogram(
        _ParamDie("DW_TAG_formal_parameter", "v1"),
        _ParamDie("DW_TAG_formal_parameter", "v2"),
        _ParamDie("DW_TAG_variable", "local"),
    )
    assert _parameter_names(die) == ("v1", "v2")


def test_parameter_names_keeps_unnamed_position_as_none():
    """An unnamed parameter stays as None so positions remain aligned with the disassembler's list."""
    from decompiler.frontend.binaryninja.dwarf import _parameter_names

    die = _subprogram(_ParamDie("DW_TAG_formal_parameter", "v1"), _ParamDie("DW_TAG_formal_parameter"))
    assert _parameter_names(die) == ("v1", None)


def _resolver_with(function_name: str, parameters: tuple):
    from decompiler.frontend.binaryninja.dwarf import DwarfFunction, DwarfVariableResolver

    resolver = DwarfVariableResolver(None)  # inert: no binary is opened
    resolver._functions = {function_name: DwarfFunction(0, (), parameters)}
    return resolver


def test_parameter_name_by_index_returns_positional_name():
    resolver = _resolver_with("f", ("v1", "v2"))
    assert resolver.parameter_name_by_index("f", 0, 2) == "v1"
    assert resolver.parameter_name_by_index("f", 1, 2) == "v2"


def test_parameter_name_by_index_guarded_on_count_mismatch():
    """Differing DWARF/disassembler parameter counts mean the lists may not align, so it never guesses."""
    resolver = _resolver_with("f", ("v1", "v2"))
    assert resolver.parameter_name_by_index("f", 0, 3) is None


def test_parameter_name_by_index_unknown_function_or_out_of_range():
    resolver = _resolver_with("f", ("v1", "v2"))
    assert resolver.parameter_name_by_index("missing", 0, 2) is None


# --------------------------------------------------------------------------------------------- #
# Global address matching: a global's DWARF location is an absolute address, so the disassembler's
# load address must be subtracted (a PIE is mapped at a different base than the DWARF addresses).
# --------------------------------------------------------------------------------------------- #


def _resolver_with_globals(globals_by_address: dict, image_base: int):
    from decompiler.frontend.binaryninja.dwarf import DwarfVariableResolver

    resolver = DwarfVariableResolver(None)  # inert: no binary is opened
    resolver._globals = globals_by_address
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


def test_global_source_name_zero_bias_when_load_base_matches_image_base():
    """A non-PIE (load address == DWARF image base) has zero bias, so the address is unchanged."""
    resolver = _resolver_with_globals({0x400500: "g"}, image_base=0x400000)
    assert resolver.global_source_name(0x400500, load_base=0x400000) == "g"
    assert resolver.parameter_name_by_index("f", 5, 2) is None


# --------------------------------------------------------------------------------------------- #
# Lexical scopes and ambiguity: two source variables sharing one stack slot in disjoint blocks.
# --------------------------------------------------------------------------------------------- #


def _shared_slot_resolver(scope_a, scope_b):
    from decompiler.frontend.binaryninja.dwarf import DwarfFunction, DwarfVariable, DwarfVariableResolver, FixedLocation, AddressRange, StackSlot

    resolver = DwarfVariableResolver(None)  # inert: no binary is opened
    slot = FixedLocation(StackSlot(-0x24))
    a = DwarfVariable("a", slot, tuple(AddressRange(low, high, None) for low, high in scope_a) if scope_a else None)
    b = DwarfVariable("b", slot, tuple(AddressRange(low, high, None) for low, high in scope_b) if scope_b else None)
    resolver._functions = {"f": DwarfFunction(0x1000, (a, b))}
    return resolver


def _stack_origin(value_address):
    from decompiler.structures.pseudo.expressions import VariableProvenance

    return VariableProvenance(source_type="StackVariableSourceType", storage=-0x24, value_address=value_address, function=0x1000)


def test_shared_slot_is_resolved_by_lexical_scope():
    resolver = _shared_slot_resolver([(0x1010, 0x1020)], [(0x1020, 0x1030)])
    assert resolver.source_name(_stack_origin(0x1018), "f") == "a"
    assert resolver.source_name(_stack_origin(0x1028), "f") == "b"


def test_shared_slot_outside_both_scopes_is_unnamed():
    resolver = _shared_slot_resolver([(0x1010, 0x1020)], [(0x1020, 0x1030)])
    assert resolver.source_name(_stack_origin(0x1040), "f") is None
    assert resolver.source_names(_stack_origin(0x1040), "f") == set()


def test_shared_slot_without_scopes_is_ambiguous():
    """Both variables match: never pick the first one, give no name."""
    resolver = _shared_slot_resolver(None, None)
    assert resolver.source_name(_stack_origin(0x1018), "f") is None
    assert resolver.source_names(_stack_origin(0x1018), "f") == {"a", "b"}


def test_shared_slot_without_address_is_ambiguous():
    """Without a value_address the scopes cannot rule a variable out."""
    resolver = _shared_slot_resolver([(0x1010, 0x1020)], [(0x1020, 0x1030)])
    assert resolver.source_name(_stack_origin(None), "f") is None


_SHARED_SLOT_SOURCE = """
void fill(int *p, int n) { *p += n; }
int use(int *p) { return *p; }
__attribute__((noinline)) int shared(int n) {
    int total = 0;
    if (n > 3) { int a = n * 2; fill(&a, n); total += use(&a); }
    else { int b = n + 7; fill(&b, n); total -= use(&b); }
    return total;
}
int main(int argc, char **argv) { return shared(argc); }
"""


def test_lexical_block_scopes_are_parsed(tmp_path):
    """gcc -O1 puts a and b into the same slot; each gets the address range of its own block."""
    pytest.importorskip("elftools")
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    source = tmp_path / "shared.c"
    source.write_text(_SHARED_SLOT_SOURCE)
    out = tmp_path / "shared"
    result = subprocess.run(["gcc", "-g", "-O1", "-fno-inline", "-o", str(out), str(source)], capture_output=True)
    if result.returncode != 0 or out.read_bytes()[:4] != b"\x7fELF":
        pytest.skip("could not build an ELF sample")
    from decompiler.frontend.binaryninja.dwarf import _parse_dwarf

    variables = {variable.name: variable for variable in _parse_dwarf(str(out))["shared"].variables}
    a, b = variables["a"], variables["b"]
    if a.location != b.location:
        pytest.skip("compiler did not share the slot")
    assert a.scope and b.scope
    assert not any(ra.low < rb.high and rb.low < ra.high for ra in a.scope for rb in b.scope)
    assert variables["total"].scope is None


class _AddressResolver:
    """Fake DWARF resolver: the names matching at each address."""

    def __init__(self, names_at):
        self._names_at = names_at

    def source_names(self, origin, function_name, register_name=None):
        return set(self._names_at.get(origin.value_address, ()))


def _dwarf_names(names_at, value_address, uses):
    from types import SimpleNamespace

    from decompiler.frontend.binaryninja.handlers.variables import VariableHandler
    from decompiler.structures.pseudo import VariableProvenance

    lifter = SimpleNamespace(dwarf=_AddressResolver(names_at), bv=SimpleNamespace(arch=SimpleNamespace(get_reg_name=str)))
    return VariableHandler(lifter)._dwarf_names(VariableProvenance(storage=1, value_address=value_address), "f", uses)


def test_use_addresses_resolve_ambiguity():
    """{i, max} at the definition, {max} at a use: the value can only be max."""
    assert _dwarf_names({0x10: {"i", "max"}, 0x20: {"max"}}, 0x10, [0x20]) == {"max"}


def test_use_address_without_match_is_a_gap():
    assert _dwarf_names({0x10: {"a"}}, 0x10, [0x20]) == {"a"}
    assert _dwarf_names({0x20: {"a"}}, 0x10, [0x20]) == {"a"}


def test_disagreeing_addresses_are_ambiguous():
    assert _dwarf_names({0x10: {"a"}, 0x20: {"b"}}, 0x10, [0x20]) == {"a", "b"}


def test_storage_names_collects_every_variable_in_the_storage_ignoring_address_and_scope():
    from decompiler.frontend.binaryninja.dwarf import DwarfFunction, DwarfVariable, FixedLocation, AddressRange, RangedLocation, RegisterSlot, StackSlot
    from decompiler.structures.pseudo.expressions import VariableProvenance

    moving = RangedLocation((AddressRange(0, 4, RegisterSlot("rdi")), AddressRange(4, 8, StackSlot(-8)), AddressRange(8, 9, None)))
    variables = (
        DwarfVariable("i", FixedLocation(RegisterSlot("rdi")), scope=(AddressRange(100, 200, None),)),
        DwarfVariable("max", moving),
        DwarfVariable("local", FixedLocation(StackSlot(-16))),
    )
    resolver = _resolver_with("f", ())
    resolver._functions = {"f": DwarfFunction(0, variables)}
    reg = lambda index: "rdi"
    register = VariableProvenance(source_type="RegisterVariableSourceType", storage=1, value_address=0x1000, function=0)
    stack = VariableProvenance(source_type="StackVariableSourceType", storage=-8, function=0)
    assert resolver.storage_names(register, "f", reg) == {"i", "max"}
    assert resolver.storage_names(stack, "f", reg) == {"max"}
    assert resolver.storage_names(replace_storage(stack, -99), "f", reg) == frozenset()
    assert resolver.storage_names(stack, "unknown", reg) == frozenset()


def replace_storage(origin, storage):
    from dataclasses import replace

    return replace(origin, storage=storage)
