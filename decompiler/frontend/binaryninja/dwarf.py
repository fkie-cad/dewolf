"""Resolve DWARF source variables for lifted variables.

For a binary compiled with -g, DWARF records which machine location holds which
*source* variable. This module parses that information and, given a lifted
variable's provenance (source_type + storage + def_address), returns the C source
variable occupying the same location at the definition site - as a SourceMatch
carrying the variable's name and its identity (the offset of its DWARF DIE, unique
per binary, so two distinct source variables that share a name stay distinct).

The matching is location based, not name based: DWARF identifies a variable by
where it lives (a stack slot, or a register over a range of PC values), so a
Binary Ninja / dewolf SSA variable is matched to its source variable by having
the same location - never by name (Binary Ninja's heuristic names are unrelated).
Functions are looked up by their entry address, so the matching is also
independent of Binary Ninja's symbol names and of whether Binary Ninja imported
the debug information itself (analysis.debugInfo.internal).

pyelftools is an optional dependency: if it is not installed, or the binary has
no DWARF, this resolver is inert and every lookup returns None.

Design: parsing (all elftools/ELF coupling) lives in `_DwarfParser`, which turns a
binary into a plain in-memory model (`DwarfFunction` -> `DwarfVariable` /
`DwarfParameter` -> location value objects). `DwarfVariableResolver` only queries
that model, so the matching logic is free of any DWARF-format knowledge. Naming
register parameters at function entry (which DWARF usually does not describe by
location) is done by SysVAbiParameterSource (see parameter_sources.py).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    from elftools.dwarf.descriptions import describe_reg_name
    from elftools.dwarf.dwarf_expr import DWARFExprParser
    from elftools.dwarf.locationlists import BaseAddressEntry, LocationExpr, LocationParser
    from elftools.elf.elffile import ELFFile

    _DWARF_AVAILABLE = True
except ImportError:  # pragma: no cover - pyelftools is optional
    _DWARF_AVAILABLE = False

# CFA = SP-at-entry + return-address-slot-size, per architecture (translates the
# DWARF frame base DW_OP_call_frame_cfa to Binary Ninja's SP-at-entry convention).
_CFA_DELTA_BY_ARCH = {"x64": 8, "x86": 4}

# Frame-pointer register per architecture, used to match DW_OP_breg <fp> stack slots (see _decode_storage).
_FRAME_POINTER_BY_ARCH = {"x64": "rbp", "x86": "ebp"}

# Binary Ninja variable source-type names we can match against a DWARF location.
_STACK_SOURCE_TYPE = "StackVariableSourceType"
_REGISTER_SOURCE_TYPE = "RegisterVariableSourceType"

# DWARF expression opcodes (numeric, robust against op-name formatting).
_OP_ADDR = 0x03
_OP_ADDRX = 0xA1  # DWARF5 indexed address: operand is an index into .debug_addr
_OP_FBREG = 0x91
_OP_REG0, _OP_REG31 = 0x50, 0x6F
_OP_BREG0, _OP_BREG31 = 0x70, 0x8F
_OP_REGX = 0x90
_OP_BREGX = 0x92
_OP_IMPLICIT_VALUE = 0x9E
_OP_STACK_VALUE = 0x9F

# DW_AT_encoding values of DW_TAG_base_type used to classify parameter types.
_ATE_COMPLEX_FLOAT = 0x03
_ATE_FLOAT = 0x04


@dataclass(frozen=True)
class SourceMatch:
    """A matched C source variable: its name and its identity (the offset of its DWARF DIE)."""

    name: str
    die_offset: int


@dataclass(frozen=True)
class LiftedLocation:
    """Where Binary Ninja says a lifted variable lives - the query a StorageLocation matches against."""

    is_stack: bool
    is_register: bool
    storage: int
    register_name: Optional[str]  # architecture register name, for register variables

    @classmethod
    def from_provenance(cls, origin, resolve_register) -> LiftedLocation:
        """Build a LiftedLocation from a variable's provenance.

        :param origin: the variable's VariableProvenance (must have a non-None storage)
        :param resolve_register: callable BN-register-index -> name, used only for register variables
        """
        is_register = origin.source_type == _REGISTER_SOURCE_TYPE
        register_name = resolve_register(origin.storage) if (is_register and resolve_register) else None
        return cls(origin.source_type == _STACK_SOURCE_TYPE, is_register, origin.storage, register_name)


class StorageLocation(ABC):
    """A single machine location a DWARF variable can occupy."""

    @abstractmethod
    def matches(self, lifted: LiftedLocation) -> bool:
        """Return True if a lifted variable at `lifted` occupies this location."""


@dataclass(frozen=True)
class StackSlot(StorageLocation):
    """A stack slot, as a signed offset in Binary Ninja's SP-at-entry convention."""

    bn_storage: int

    def matches(self, lifted: LiftedLocation) -> bool:
        return lifted.is_stack and lifted.storage == self.bn_storage


@dataclass(frozen=True)
class RegisterSlot(StorageLocation):
    """A register, identified by its architecture register name (e.g. 'rax')."""

    name: str

    def matches(self, lifted: LiftedLocation) -> bool:
        return lifted.is_register and lifted.register_name == self.name


class VariableLocation(ABC):
    """Where a source variable lives across its lifetime: fixed, or varying by PC range."""

    @abstractmethod
    def storage_at(self, pc: Optional[int]) -> Optional[StorageLocation]:
        """Return the storage location in effect at `pc` (or the fixed one), else None."""


@dataclass(frozen=True)
class FixedLocation(VariableLocation):
    """A variable that occupies one storage location for the whole function."""

    storage: StorageLocation

    def storage_at(self, pc: Optional[int]) -> Optional[StorageLocation]:
        return self.storage


@dataclass(frozen=True)
class PcRange:
    """A storage location valid over the half-open PC range [low, high)."""

    low: int
    high: int
    storage: Optional[StorageLocation]


@dataclass(frozen=True)
class RangedLocation(VariableLocation):
    """A variable that moves between locations, each valid over a PC range (a DWARF location list)."""

    ranges: Tuple[PcRange, ...]

    def storage_at(self, pc: Optional[int]) -> Optional[StorageLocation]:
        if pc is None:
            return None
        for pc_range in self.ranges:
            if pc_range.storage is not None and pc_range.low <= pc < pc_range.high:
                return pc_range.storage
        return None


# A lexical scope as half-open PC ranges [low, high); None stands for the whole function.
Scope = Optional[Tuple[Tuple[int, int], ...]]


def _scope_contains(scope: Scope, pc: Optional[int]) -> bool:
    """True if `pc` lies in `scope` (the function scope contains every pc)."""
    if scope is None:
        return True
    if pc is None:
        return False
    return any(low <= pc < high for low, high in scope)


@dataclass(frozen=True)
class DwarfVariable:
    """A named source variable, the location(s) it occupies, and the lexical scope it is declared in.

    `scope` holds the PC ranges of the innermost enclosing lexical block or inlined-subroutine instance
    (None: declared at function level), `depth` how many such scopes enclose it. Both only serve to
    disambiguate several source variables that occupy the same location (see DwarfVariableResolver).
    """

    name: str
    location: VariableLocation
    die_offset: int = 0
    scope: Scope = None
    depth: int = 0


# Parameter type classes (for reporting), as far as the x86-64 System V calling convention distinguishes them.
TYPE_INTEGER = "integer"  # integers, enums, bools, pointers: one general-purpose register
TYPE_SSE = "sse"  # float / double: one SSE register
TYPE_AGGREGATE = "aggregate"  # struct/union/array of at most 16 bytes passed in registers
TYPE_MEMORY = "memory"  # passed on the stack, consumes no register (aggregates > 16 bytes, long double, ...)
TYPE_MULTI = "multi"  # scalar in two registers (__int128, complex double)
TYPE_OTHER = "other"  # unknown layout: register use not derived

# System V classes of one eightbyte of an argument.
CLASS_INTEGER = "integer"
CLASS_SSE = "sse"


@dataclass(frozen=True)
class DwarfParameter:
    """A formal parameter of a function: its name (None if unnamed), identity and System V classification.

    `eightbytes` holds the class of each eightbyte of the value as the x86-64 System V convention
    passes it (CLASS_INTEGER / CLASS_SSE, one register each), () if it is passed in memory, or None
    if its layout could not be classified. `type_class` is a coarse summary for reporting.
    """

    name: Optional[str]
    die_offset: int
    type_class: str = TYPE_OTHER
    eightbytes: Optional[Tuple[str, ...]] = None


@dataclass(frozen=True)
class DwarfFunction:
    """A source function's entry address, its named local variables and parameters, and its parameter list."""

    low_pc: int
    variables: Tuple[DwarfVariable, ...]
    parameters: Tuple[DwarfParameter, ...] = ()  # direct formal parameters in declaration order
    name: Optional[str] = None
    # the caller passes a hidden result pointer (aggregate returned in memory); None if the return type is not classifiable
    returns_in_memory: Optional[bool] = False


# Reference attributes carrying the name of a DIE with none of its own: a concrete instance of an
# inlined function (or its locals) links to the abstract DIE holding the name via DW_AT_abstract_origin;
# DW_AT_specification is the analogous split for declarations.
_NAME_ORIGIN_ATTRS = ("DW_AT_abstract_origin", "DW_AT_specification")


def _die_attribute(die, attribute: str, _seen: Optional[frozenset] = None):
    """Return a DIE's attribute, following abstract-origin/specification links, or None."""
    value = die.attributes.get(attribute)
    if value is not None:
        return value
    seen = (_seen or frozenset()) | {die.offset}  # guard against reference cycles in malformed DWARF
    for link in _NAME_ORIGIN_ATTRS:
        if link not in die.attributes:
            continue
        try:
            referenced = die.get_DIE_from_attribute(link)
        except Exception:  # unresolvable reference: try the next link
            continue
        if referenced.offset not in seen:
            value = _die_attribute(referenced, attribute, seen)
            if value is not None:
                return value
    return None


def _die_name(die) -> Optional[str]:
    """Return the decoded DW_AT_name of a DIE, following abstract-origin/specification links, or None."""
    name_attr = _die_attribute(die, "DW_AT_name")
    return name_attr.value.decode() if name_attr is not None else None


def _referenced_type(die):
    """The DIE that `die`'s DW_AT_type (followed through abstract origins) points at, or None."""
    owner = die
    seen = set()
    while owner is not None and owner.offset not in seen:
        seen.add(owner.offset)
        if "DW_AT_type" in owner.attributes:
            try:
                return owner.get_DIE_from_attribute("DW_AT_type")
            except Exception:
                return None
        owner = next((_resolve_link(owner, link) for link in _NAME_ORIGIN_ATTRS if link in owner.attributes), None)
    return None


def _resolve_link(die, link: str):
    try:
        return die.get_DIE_from_attribute(link)
    except Exception:
        return None


# Type DIEs that do not change how a value is passed.
_TRANSPARENT_TYPE_TAGS = (
    "DW_TAG_typedef",
    "DW_TAG_const_type",
    "DW_TAG_volatile_type",
    "DW_TAG_restrict_type",
    "DW_TAG_atomic_type",
)
_POINTER_TYPE_TAGS = ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type", "DW_TAG_ptr_to_member_type")
_AGGREGATE_TYPE_TAGS = ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type", "DW_TAG_array_type")


def _strip_type(type_die):
    """Follow typedefs and qualifiers to the type that determines how a value is passed."""
    for _ in range(64):  # bounded: malformed DWARF may contain cycles
        if type_die is None or type_die.tag not in _TRANSPARENT_TYPE_TAGS:
            return type_die
        type_die = _resolve_link(type_die, "DW_AT_type") if "DW_AT_type" in type_die.attributes else None
    return None


def _byte_size(type_die) -> Optional[int]:
    size = type_die.attributes.get("DW_AT_byte_size")
    return size.value if size is not None and isinstance(size.value, int) else None


class _Unclassified(Exception):
    """The value's layout cannot be classified (unknown type, VLA, C++ base classes, ...)."""


class _InMemory(Exception):
    """The value is passed in memory (contains long double, unaligned fields, ...)."""


def _array_count(array_die) -> Optional[int]:
    """Number of elements of an array type (product over its dimensions); 0 for a flexible array, None if not constant."""
    count = 1
    for subrange in array_die.iter_children():
        if subrange.tag != "DW_TAG_subrange_type":
            continue
        attributes = subrange.attributes
        if "DW_AT_count" in attributes:
            value = attributes["DW_AT_count"].value
        elif "DW_AT_upper_bound" in attributes:
            upper = attributes["DW_AT_upper_bound"].value
            lower = attributes["DW_AT_lower_bound"].value if "DW_AT_lower_bound" in attributes else 0
            value = upper - lower + 1 if isinstance(upper, int) and isinstance(lower, int) else None
        else:
            return 0  # flexible array member: occupies no bytes
        if not isinstance(value, int):
            return None
        count *= value
    return count


def _type_size(type_die) -> Optional[int]:
    """The size in bytes of a (stripped) type, computing it for arrays; None if unknown."""
    if type_die is None:
        return None
    size = _byte_size(type_die)
    if size is not None:
        return size
    if type_die.tag in _POINTER_TYPE_TAGS:
        return 8
    if type_die.tag == "DW_TAG_array_type":
        element = _strip_type(_referenced_type(type_die))
        count, element_size = _array_count(type_die), _type_size(element)
        return count * element_size if count is not None and element_size is not None else None
    return None


def _scalar_eightbytes(type_die) -> Tuple[str, ...]:
    """System V classes of a scalar type; raises _InMemory / _Unclassified."""
    tag = type_die.tag
    if tag in _POINTER_TYPE_TAGS or tag == "DW_TAG_enumeration_type":
        return (CLASS_INTEGER,)
    if tag != "DW_TAG_base_type":
        raise _Unclassified()
    size = _byte_size(type_die)
    encoding = type_die.attributes.get("DW_AT_encoding")
    encoding = encoding.value if encoding is not None else None
    if encoding == _ATE_FLOAT:
        if size in (4, 8):
            return (CLASS_SSE,)
        name = _die_name(type_die) or ""
        if size == 16 and "long double" in name:
            raise _InMemory()  # x87 class
        raise _Unclassified()  # e.g. __float128 (SSE + SSEUP)
    if encoding == _ATE_COMPLEX_FLOAT:
        if size == 8:
            return (CLASS_SSE,)
        if size == 16:
            return (CLASS_SSE, CLASS_SSE)
        raise _InMemory()  # complex long double
    if size is not None and size <= 8:
        return (CLASS_INTEGER,)
    if size == 16:
        return (CLASS_INTEGER, CLASS_INTEGER)  # __int128
    raise _Unclassified()


def _scalar_alignment(type_die, size: int) -> int:
    if type_die.tag == "DW_TAG_base_type":
        encoding = type_die.attributes.get("DW_AT_encoding")
        if encoding is not None and encoding.value == _ATE_COMPLEX_FLOAT:
            return max(size // 2, 1)
    return max(size, 1)


def _leaves(type_die, base: int, depth: int) -> Iterator[Tuple[int, Tuple[str, ...]]]:
    """Yield (byte offset, classes) of every scalar inside a type, flattening structs, unions and arrays."""
    if depth > 16:
        raise _Unclassified()
    type_die = _strip_type(type_die)
    if type_die is None:
        raise _Unclassified()
    tag = type_die.tag
    if tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
        is_union = tag == "DW_TAG_union_type"
        for member in type_die.iter_children():
            if member.tag == "DW_TAG_inheritance":
                raise _Unclassified()  # C++ base classes: not handled
            if member.tag != "DW_TAG_member":
                continue
            attributes = member.attributes
            if "DW_AT_declaration" in attributes or "DW_AT_external" in attributes:
                continue  # static member: not part of the object
            location = attributes.get("DW_AT_data_member_location")
            if location is not None and not isinstance(location.value, int):
                raise _Unclassified()  # location expression (old DWARF)
            offset = location.value if location is not None else None
            if "DW_AT_bit_size" in attributes:  # bit field: an integer in the eightbyte holding its first bit
                if "DW_AT_data_bit_offset" in attributes:
                    offset = attributes["DW_AT_data_bit_offset"].value // 8
                yield base + (offset or 0), (CLASS_INTEGER,)
                continue
            if offset is None:
                if not is_union:
                    raise _Unclassified()
                offset = 0
            yield from _leaves(_referenced_type(member), base + offset, depth + 1)
        return
    if tag == "DW_TAG_array_type":
        element = _strip_type(_referenced_type(type_die))
        count, element_size = _array_count(type_die), _type_size(element)
        if count is None or element_size is None or count > 16:
            raise _Unclassified()
        for index in range(count):
            yield from _leaves(element, base + index * element_size, depth + 1)
        return
    classes = _scalar_eightbytes(type_die)
    size = _type_size(type_die)
    if size is not None and base % _scalar_alignment(type_die, size):
        raise _InMemory()  # unaligned field (packed struct)
    yield base, classes


def _merge_class(first: Optional[str], second: str) -> str:
    """Merge two classes of one eightbyte: INTEGER wins over SSE."""
    if first is None or first == second:
        return second
    return CLASS_INTEGER


def _eightbytes(type_die) -> Optional[Tuple[str, ...]]:
    """The System V classes of the eightbytes a value of this type is passed in.

    () if it is passed in memory, None if the layout cannot be classified. Aggregates (struct, union,
    array) of at most 16 bytes are classified per eightbyte: INTEGER if any integer-class scalar lies
    in it, SSE if only float/double do; an aggregate larger than 16 bytes, or containing long double
    or unaligned fields, goes to memory.
    """
    type_die = _strip_type(type_die)
    if type_die is None:
        return None
    try:
        if type_die.tag not in _AGGREGATE_TYPE_TAGS:
            return _scalar_eightbytes(type_die)
        size = _type_size(type_die)
        if size is None:
            return None
        if size == 0:
            return ()  # empty struct (GNU C): occupies no register and no stack slot
        if size > 16:
            return ()
        classes: List[Optional[str]] = [None] * ((size + 7) // 8)
        for offset, leaf_classes in _leaves(type_die, 0, 0):
            for index, leaf_class in enumerate(leaf_classes):
                slot = offset // 8 + index
                if slot >= len(classes):
                    raise _Unclassified()
                classes[slot] = _merge_class(classes[slot], leaf_class)
        if any(leaf_class is None for leaf_class in classes):
            return None  # an eightbyte of pure padding: not handled
        return tuple(classes)
    except _InMemory:
        return ()
    except _Unclassified:
        return None


def _summary_class(type_die, eightbytes: Optional[Tuple[str, ...]]) -> str:
    """A coarse type class for reporting (see TYPE_*)."""
    if eightbytes is None:
        return TYPE_OTHER
    if eightbytes == ():
        return TYPE_MEMORY
    if _strip_type(type_die) is not None and _strip_type(type_die).tag in _AGGREGATE_TYPE_TAGS:
        return TYPE_AGGREGATE
    if len(eightbytes) > 1:
        return TYPE_MULTI
    return TYPE_INTEGER if eightbytes[0] == CLASS_INTEGER else TYPE_SSE


def _returns_in_memory(subprogram_die) -> Optional[bool]:
    """True if the function returns an aggregate in memory (the caller passes a hidden result pointer).

    Scalars (including long double, returned in x87 registers) never do. None if the returned aggregate
    cannot be classified, so it is unknown whether the first integer register carries the pointer.
    """
    return_type = _strip_type(_referenced_type(subprogram_die))
    if return_type is None or return_type.tag not in _AGGREGATE_TYPE_TAGS:
        return False
    eightbytes = _eightbytes(return_type)
    if eightbytes is None:
        return None
    return eightbytes == ()


def _parameters(die) -> Tuple[DwarfParameter, ...]:
    """Return a subprogram's formal parameters in declaration order.

    Direct DW_TAG_formal_parameter children only (never descending into lexical blocks), so the order
    is the declaration order the calling convention assigns registers in. Unnamed parameters are kept
    (name None), as they still occupy their register.
    """
    parameters = []
    for child in die.iter_children():
        if child.tag != "DW_TAG_formal_parameter":
            continue
        type_die = _referenced_type(child)
        eightbytes = _eightbytes(type_die)
        parameters.append(DwarfParameter(_die_name(child), child.offset, _summary_class(type_die, eightbytes), eightbytes))
    return tuple(parameters)


class _DwarfParser:
    """Turns a binary's DWARF into the in-memory model, isolating all elftools coupling."""

    def __init__(self, elf: ELFFile):
        self._dwarf = elf.get_dwarf_info()
        self._arch: str = elf.get_machine_arch()
        self._cfa_delta: int = _CFA_DELTA_BY_ARCH.get(self._arch, 8)
        self._frame_pointer: Optional[str] = _FRAME_POINTER_BY_ARCH.get(self._arch)
        self._image_base: int = self._elf_image_base(elf)
        self._location_parser = LocationParser(self._dwarf.location_lists())
        self._range_lists = None  # created lazily: only needed for scopes described by DW_AT_ranges

    @staticmethod
    def _elf_image_base(elf: ELFFile) -> int:
        """The base address DWARF addresses are relative to: the lowest PT_LOAD segment vaddr (0 if none).

        For a PIE this is 0, while the disassembler maps the image at its own load address; the
        difference is the load bias applied when matching (see DwarfVariableResolver._bias). For a
        non-PIE the segment vaddrs are the final addresses, so this equals the load address and the
        bias is zero.
        """
        load_vaddrs = [segment["p_vaddr"] for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
        return min(load_vaddrs) if load_vaddrs else 0

    def parse(self) -> Dict[int, DwarfFunction]:
        """Parse every subprogram with code into a {low_pc: DwarfFunction} model."""
        functions: Dict[int, DwarfFunction] = {}
        for compilation_unit in self._dwarf.iter_CUs():
            expr_parser = DWARFExprParser(compilation_unit.structs)
            dwarf_version = compilation_unit["version"]
            loclist_base = self._compilation_unit_base(compilation_unit)
            for die in compilation_unit.iter_DIEs():
                function = self._parse_subprogram(die, compilation_unit, expr_parser, dwarf_version, loclist_base)
                if function is not None:
                    functions[function.low_pc] = function
        return functions

    @staticmethod
    def _compilation_unit_base(compilation_unit) -> int:
        """The base address location-list and range-list offsets are relative to: the CU's DW_AT_low_pc (0 if absent).

        Offsets are relative to the compilation unit's base, not the enclosing function's; using the
        function's low_pc shifts every range and matches only the function that sits at the CU base.
        """
        low_pc = compilation_unit.get_top_DIE().attributes.get("DW_AT_low_pc")
        return low_pc.value if low_pc is not None else 0

    def _parse_subprogram(self, die, compilation_unit, expr_parser, dwarf_version, loclist_base) -> Optional[DwarfFunction]:
        """Parse one DW_TAG_subprogram DIE with a code address into a DwarfFunction, else None."""
        if die.tag != "DW_TAG_subprogram":
            return None
        low_pc = die.attributes.get("DW_AT_low_pc")
        if low_pc is None:
            return None
        variables = tuple(self._parse_locals(die, compilation_unit, expr_parser, dwarf_version, loclist_base))
        return DwarfFunction(low_pc.value, variables, _parameters(die), _die_name(die), _returns_in_memory(die))

    def _parse_locals(self, die, compilation_unit, expr_parser, dwarf_version, loclist_base) -> Iterator[DwarfVariable]:
        """Yield the named local variables and parameters of a subprogram that have a resolvable location."""
        frame_base_register = self._frame_base_register(die, expr_parser)
        for local_die, scope, depth in self._walk_locals(die, compilation_unit, loclist_base, None, 0):
            location = self._location_of(local_die, expr_parser, dwarf_version, loclist_base, frame_base_register)
            name = _die_name(local_die)
            if name is not None and location is not None:
                yield DwarfVariable(name, location, local_die.offset, scope, depth)

    def _walk_locals(self, die, compilation_unit, base: int, scope: Scope, depth: int) -> Iterator[Tuple[Any, Scope, int]]:
        """Yield (DIE, scope, depth) for the variables and parameters under a subprogram.

        Descends into lexical blocks and inlined-subroutine instances (whose locals and parameters live
        in the caller's frame and registers), each opening a nested scope. A block without code ranges
        is transparent: its variables keep the enclosing scope. Nested subprograms are not entered.
        """
        for child in die.iter_children():
            if child.tag in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                yield child, scope, depth
            elif child.tag in ("DW_TAG_lexical_block", "DW_TAG_inlined_subroutine"):
                ranges = self._pc_ranges(child, compilation_unit, base)
                if ranges:
                    yield from self._walk_locals(child, compilation_unit, base, ranges, depth + 1)
                else:
                    yield from self._walk_locals(child, compilation_unit, base, scope, depth)

    def _pc_ranges(self, die, compilation_unit, base: int) -> Tuple[Tuple[int, int], ...]:
        """The code ranges of a DIE (DW_AT_low_pc/DW_AT_high_pc or DW_AT_ranges), or () if it has none."""
        attributes = die.attributes
        low = attributes.get("DW_AT_low_pc")
        high = attributes.get("DW_AT_high_pc")
        if low is not None and high is not None:
            end = high.value if high.form in ("DW_FORM_addr", "DW_FORM_addrx") else low.value + high.value
            return ((low.value, end),)
        ranges_attr = attributes.get("DW_AT_ranges")
        if ranges_attr is None:
            return ()
        try:
            if self._range_lists is None:
                self._range_lists = self._dwarf.range_lists()
            if self._range_lists is None:
                return ()
            entries = self._range_lists.get_range_list_at_offset(ranges_attr.value, cu=compilation_unit)
        except Exception:
            return ()
        ranges: List[Tuple[int, int]] = []
        base_address = base
        for entry in entries:
            if hasattr(entry, "base_address"):  # BaseAddressEntry
                base_address = entry.base_address
                continue
            if getattr(entry, "is_absolute", False):
                ranges.append((entry.begin_offset, entry.end_offset))
            else:
                ranges.append((base_address + entry.begin_offset, base_address + entry.end_offset))
        return tuple(ranges)

    def _frame_base_register(self, die, expr_parser) -> Optional[str]:
        """Return the register a subprogram's DW_AT_frame_base is expressed off, or None for a CFA frame base.

        DW_AT_frame_base takes one of two forms. DW_OP_call_frame_cfa (emitted by GCC) has no register:
        this returns None and DW_OP_fbreg offsets are taken relative to the CFA. DW_OP_reg<n> (emitted by
        clang, typically rbp) names a register: this returns its name and DW_OP_fbreg offsets are taken
        relative to it, exactly like a DW_OP_breg off the same register (see _frame_pointer_slot). An absent
        or non-register frame base uses the CFA convention.
        """
        frame_base_attr = die.attributes.get("DW_AT_frame_base")
        if frame_base_attr is None:
            return None
        try:
            opcodes = expr_parser.parse_expr(frame_base_attr.value)
        except Exception:
            return None
        if len(opcodes) != 1:
            return None
        operation = opcodes[0]
        if _OP_REG0 <= operation.op <= _OP_REG31:
            return describe_reg_name(operation.op - _OP_REG0, self._arch)
        if operation.op == _OP_REGX:
            return describe_reg_name(operation.args[0], self._arch)
        return None  # DW_OP_call_frame_cfa or anything else: use the CFA convention

    def _location_of(self, die, expr_parser, dwarf_version, loclist_base, frame_base_register) -> Optional[VariableLocation]:
        """Parse a variable's DW_AT_location into a VariableLocation, or None if it has no matchable storage.

        A DW_AT_location is either a single expression (one location for the whole function) or a
        location list (the variable moves between locations over PC ranges, made absolute against the
        compilation-unit base address - see _compilation_unit_base).
        """
        location_attr = die.attributes.get("DW_AT_location")
        if location_attr is None or not self._location_parser.attribute_has_location(location_attr, dwarf_version):
            return None
        parsed_location = self._location_parser.parse_from_attribute(location_attr, dwarf_version, die=die)
        if isinstance(parsed_location, LocationExpr):
            storage = self._decode_storage(expr_parser.parse_expr(parsed_location.loc_expr), frame_base_register)
            return FixedLocation(storage) if storage is not None else None
        return RangedLocation(tuple(self._parse_ranges(parsed_location, expr_parser, loclist_base, frame_base_register)))

    def _parse_ranges(self, parsed_location, expr_parser, loclist_base, frame_base_register) -> Iterator[PcRange]:
        """Yield the PC ranges of a location list, resolving each range's storage descriptor."""
        base_address = loclist_base
        for entry in parsed_location:
            if isinstance(entry, BaseAddressEntry):
                base_address = entry.base_address
                continue
            if getattr(entry, "is_absolute", False):
                low, high = entry.begin_offset, entry.end_offset
            else:
                low, high = base_address + entry.begin_offset, base_address + entry.end_offset
            yield PcRange(low, high, self._decode_storage(expr_parser.parse_expr(entry.loc_expr), frame_base_register))

    def _decode_storage(self, parsed_opcodes, frame_base_register: Optional[str] = None) -> Optional[StorageLocation]:
        """Decode a parsed DWARF location expression into a StorageLocation, or None if it has no matchable storage.

        Returns None for an empty expression, a computed/implicit value with no storage, or any form
        we do not match here (sp-relative breg, global, composite).
        """
        if not parsed_opcodes or any(op.op in (_OP_STACK_VALUE, _OP_IMPLICIT_VALUE) for op in parsed_opcodes):
            return None
        if len(parsed_opcodes) == 1:
            operation = parsed_opcodes[0]
            if operation.op == _OP_FBREG:
                # DW_OP_fbreg is relative to the subprogram's frame base. Off a register (clang's rbp) it is
                # identical to a DW_OP_breg off that register; off the CFA (GCC) it uses the CFA convention.
                if frame_base_register is not None:
                    return self._frame_pointer_slot(frame_base_register, operation.args[0])
                return StackSlot(operation.args[0] + self._cfa_delta)
            if _OP_REG0 <= operation.op <= _OP_REG31:
                return RegisterSlot(describe_reg_name(operation.op - _OP_REG0, self._arch))
            if operation.op == _OP_REGX:
                return RegisterSlot(describe_reg_name(operation.args[0], self._arch))
            if _OP_BREG0 <= operation.op <= _OP_BREG31:
                return self._frame_pointer_slot(describe_reg_name(operation.op - _OP_BREG0, self._arch), operation.args[0])
            if operation.op == _OP_BREGX:
                return self._frame_pointer_slot(describe_reg_name(operation.args[0], self._arch), operation.args[1])
        return None

    def _frame_pointer_slot(self, register_name: str, offset: int) -> Optional[StackSlot]:
        """A DW_OP_breg off the frame pointer as a StackSlot in BN's SP-at-entry convention, else None.

        With the standard prologue the frame pointer sits one pointer-slot (== _cfa_delta) below
        SP-at-entry, so frame_pointer + off is at SP-at-entry + (off - _cfa_delta). Off any other
        register (e.g. sp-relative) we do not track the per-PC frame state, so it stays unmatched.
        """
        if self._frame_pointer is None or register_name != self._frame_pointer:
            return None
        return StackSlot(offset - self._cfa_delta)

    def parse_globals(self) -> Dict[int, SourceMatch]:
        """Parse every named variable at a fixed address into an {address: SourceMatch} model.

        Covers file-scope globals and static locals alike - both are DW_TAG_variable DIEs whose
        DW_AT_location is a single DW_OP_addr; ordinary stack/register locals have other location
        forms and are skipped. Later definitions win on address collision (last write).
        """
        globals_by_address: Dict[int, SourceMatch] = {}
        for compilation_unit in self._dwarf.iter_CUs():
            expr_parser = DWARFExprParser(compilation_unit.structs)
            for die in compilation_unit.iter_DIEs():
                if die.tag != "DW_TAG_variable":
                    continue
                address = self._global_address(die, expr_parser, compilation_unit)
                name = _die_name(die)
                if address is not None and name is not None:
                    globals_by_address[address] = SourceMatch(name, self._global_identity(die))
        return globals_by_address

    @staticmethod
    def _global_identity(die) -> int:
        """The identity of a global: the DIE of its declaration if this DIE completes one (DW_AT_specification).

        A global declared in a header and defined in a .c file has a declaration DIE in every unit that
        includes the header, but only the defining DIE has the address; using the declaration's offset
        when present keeps the identity of one global stable.
        """
        specification = _resolve_link(die, "DW_AT_specification") if "DW_AT_specification" in die.attributes else None
        return specification.offset if specification is not None else die.offset

    def _global_address(self, die, expr_parser, compilation_unit) -> Optional[int]:
        """The absolute address of a variable at a fixed location, else None.

        Handles the direct form (DW_OP_addr, operand is the address) and the DWARF5 indexed form
        (DW_OP_addrx, operand indexes .debug_addr and is resolved against the compilation unit).
        """
        location_attr = die.attributes.get("DW_AT_location")
        if location_attr is None or location_attr.form not in ("DW_FORM_exprloc", "DW_FORM_block1"):
            return None
        opcodes = expr_parser.parse_expr(location_attr.value)
        if len(opcodes) != 1:
            return None
        operation = opcodes[0]
        if operation.op == _OP_ADDR:
            return operation.args[0]
        if operation.op == _OP_ADDRX:
            try:
                return self._dwarf.get_addr(compilation_unit, operation.args[0])
            except Exception:  # missing/unreadable .debug_addr: treat as no fixed address
                return None
        return None


class DwarfVariableResolver:
    """Matches lifted variables to their DWARF source variables by storage location."""

    def __init__(self, path: Optional[str]):
        """Parse the DWARF at path (if any); leave the resolver inert on any failure.

        :param path: filesystem path to the ELF binary, or None to build an inert resolver
        """
        self._functions: Dict[int, DwarfFunction] = {}  # {DWARF low_pc: function}
        self._globals: Dict[int, SourceMatch] = {}  # {DWARF address: global}
        self._image_base: int = 0  # base the DWARF addresses are relative to (see _DwarfParser._elf_image_base)
        self.arch: Optional[str] = None  # pyelftools machine arch, e.g. 'x64'
        if _DWARF_AVAILABLE and path:
            try:
                self.arch, self._image_base, self._functions, self._globals = _parse_binary(path)
            except Exception as exc:  # never let ground-truth parsing break lifting
                logging.warning(f"DWARF parsing failed for {path}: {exc}")

    @classmethod
    @lru_cache(maxsize=None)
    def for_path(cls, path: Optional[str]) -> DwarfVariableResolver:
        """Return a resolver for the given binary path, parsed at most once per path."""
        return cls(path)

    @property
    def available(self) -> bool:
        """True if DWARF was parsed and at least one function or global is known."""
        return bool(self._functions or self._globals)

    def _bias(self, load_base: Optional[int]) -> int:
        """The load bias: disassembler address - DWARF address (0 if the load base is unknown)."""
        return 0 if load_base is None else load_base - self._image_base

    def function_at(self, function_start: Optional[int], load_base: Optional[int] = None) -> Optional[DwarfFunction]:
        """Return the DWARF function whose entry is the disassembler address `function_start`, else None."""
        if function_start is None:
            return None
        return self._functions.get(function_start - self._bias(load_base))

    def global_match(self, address: Optional[int], load_base: Optional[int] = None) -> Optional[SourceMatch]:
        """Return the DWARF global variable at the disassembler address `address`, or None if unknown.

        :param load_base: the disassembler's image load address; when given, the load bias
            (load_base - the DWARF image base) is subtracted so a PIE mapped at a different address
            still lines up with the DWARF addresses. When None the address is looked up as-is.
        """
        if address is None:
            return None
        return self._globals.get(address - self._bias(load_base))

    def global_source_name(self, address: Optional[int], load_base: Optional[int] = None) -> Optional[str]:
        """Return the DWARF source name of the global variable at `address`, or None if unknown."""
        match = self.global_match(address, load_base)
        return match.name if match is not None else None

    def source_match(
        self,
        origin,
        load_base: Optional[int] = None,
        lookup_pc: Optional[int] = None,
        register_name=None,
    ) -> Optional[SourceMatch]:
        """Return the C source variable occupying a lifted variable's location at its definition.

        :param origin: the variable's VariableProvenance (source_type, storage, def_address, function)
        :param load_base: the disassembler's image load address (see global_match)
        :param lookup_pc: disassembler address at which the location is looked up; defaults to
            origin.def_address. For a real definition this should be the address right after the
            defining instruction: a location-list range for the new value starts there, while at the
            instruction itself DWARF still describes the register's previous occupant.
        :param register_name: callable BN-register-index -> name, for register variables

        Selection: the source variables whose location at `lookup_pc` matches. A single one is taken.
        Several (a slot or register shared by variables of different scopes, or reused) are narrowed to
        those whose lexical scope contains the defining instruction, and the innermost of them wins;
        if that is still not unique, the variable stays unmatched rather than guessing.
        """
        if origin is None or origin.storage is None:
            return None
        function = self.function_at(origin.function, load_base)
        if function is None:
            return None
        bias = self._bias(load_base)
        lifted = LiftedLocation.from_provenance(origin, register_name)
        if lookup_pc is None:
            lookup_pc = origin.def_address
        dwarf_lookup_pc = lookup_pc - bias if lookup_pc is not None else None
        dwarf_def_pc = origin.def_address - bias if origin.def_address is not None else None
        candidates = [
            variable
            for variable in function.variables
            if (storage := variable.location.storage_at(dwarf_lookup_pc)) is not None and storage.matches(lifted)
        ]
        chosen = self._select(candidates, dwarf_def_pc)
        return SourceMatch(chosen.name, chosen.die_offset) if chosen is not None else None

    @staticmethod
    def _select(candidates: List[DwarfVariable], def_pc: Optional[int]) -> Optional[DwarfVariable]:
        """Pick the one source variable among location matches (see source_match), or None."""
        if not candidates:
            return None
        if len({candidate.die_offset for candidate in candidates}) == 1:
            return candidates[0]
        in_scope = [candidate for candidate in candidates if _scope_contains(candidate.scope, def_pc)]
        if not in_scope:
            return None
        deepest = max(candidate.depth for candidate in in_scope)
        innermost = {candidate.die_offset: candidate for candidate in in_scope if candidate.depth == deepest}
        return next(iter(innermost.values())) if len(innermost) == 1 else None

    def source_name(self, origin, load_base: Optional[int] = None, lookup_pc: Optional[int] = None, register_name=None) -> Optional[str]:
        """Return only the name of source_match (convenience for callers that need no identity)."""
        match = self.source_match(origin, load_base, lookup_pc, register_name)
        return match.name if match is not None else None


def _parse_binary(path: str) -> Tuple[Optional[str], int, Dict[int, DwarfFunction], Dict[int, SourceMatch]]:
    """Open an ELF binary and parse its DWARF into (arch, image base, functions, globals) (empty if none)."""
    with open(path, "rb") as file_handle:
        elf_file = ELFFile(file_handle)
        arch = elf_file.get_machine_arch()
        if not elf_file.has_dwarf_info():
            return arch, 0, {}, {}
        parser = _DwarfParser(elf_file)
        return arch, parser._image_base, parser.parse(), parser.parse_globals()


def _parse_dwarf(path: str) -> Dict[int, DwarfFunction]:
    """Open an ELF binary and parse its DWARF into the {low_pc: DwarfFunction} model (empty if none)."""
    with open(path, "rb") as file_handle:
        elf_file = ELFFile(file_handle)
        if not elf_file.has_dwarf_info():
            return {}
        return _DwarfParser(elf_file).parse()
