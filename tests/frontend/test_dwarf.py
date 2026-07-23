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
    """True if the DWARF has a subprogram with low_pc but no direct name resolving to `function_name`.

    The concrete-out-of-line-instance shape the fix handles; a precondition so the test skips rather
    than passes vacuously where the compiler did not produce it.
    """
    elffile = pytest.importorskip("elftools.elf.elffile")
    with open(path, "rb") as handle:
        dwarf = elffile.ELFFile(handle).get_dwarf_info()
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                attributes = die.attributes
                if "DW_AT_low_pc" in attributes and "DW_AT_name" not in attributes and _die_name(die) == function_name:
                    return True
    return False


@pytest.fixture(scope="module")
def inline_binary(tmp_path_factory):
    """Compile the inline sample with gcc -O2 -g; skip if the toolchain is unavailable or fails."""
    pytest.importorskip("elftools")
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    directory = tmp_path_factory.mktemp("dwarf_inline")
    source = directory / "inl.c"
    source.write_text(_INLINE_SOURCE)
    out = directory / "inl.g"
    result = subprocess.run(["gcc", "-g", "-O2", "-o", str(out), str(source)], capture_output=True)
    if result.returncode != 0 or not out.exists():
        pytest.skip(f"could not build inline debug binary: {result.stderr.decode()[:200]}")
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
    """A function's location-list PC ranges must fall inside its own body (checked on non-CU-base functions).

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


def test_decode_computed_value_is_unmatched():
    """A location ending in DW_OP_stack_value is a computed value living nowhere, so it decodes to None."""
    parser = _x64_parser()
    # DW_OP_breg6 -96; DW_OP_deref; DW_OP_stack_value  -> a pointer computation, not a stored slot
    assert parser._decode_storage([_Op(0x76, (-96,)), _Op(0x06), _Op(0x9F)]) is None
