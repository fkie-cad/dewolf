"""Resolve DWARF source-variable names for lifted variables.

For a binary compiled with -g, DWARF records which machine location holds which
*source* variable. This module parses that information and, given a lifted
variable's provenance (source_type + storage + def_address), returns the name of
the C source variable occupying the same location at the definition site.

The matching is location based, not name based: DWARF identifies a variable by
where it lives (a stack slot, or a register over a range of PC values), so a
Binary Ninja / dewolf SSA variable is matched to its source variable by having
the same location - never by name (Binary Ninja's heuristic names are unrelated).

pyelftools is an optional dependency: if it is not installed, or the binary has
no DWARF, this resolver is inert and every lookup returns None.

Design: parsing (all elftools/ELF coupling) lives in `_DwarfParser`, which turns a
binary into a plain in-memory model (`DwarfFunction` -> `DwarfVariable` -> location
value objects). `DwarfVariableResolver` only queries that model, so the matching
logic is free of any DWARF-format or architecture knowledge.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Iterator, Optional, Tuple

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

# Binary Ninja variable source-type names we can match against a DWARF location.
_STACK_SOURCE_TYPE = "StackVariableSourceType"
_REGISTER_SOURCE_TYPE = "RegisterVariableSourceType"

# DWARF expression opcodes (numeric, robust against op-name formatting).
_OP_ADDR = 0x03
_OP_FBREG = 0x91
_OP_REG0, _OP_REG31 = 0x50, 0x6F
_OP_BREG0, _OP_BREG31 = 0x70, 0x8F
_OP_REGX = 0x90
_OP_BREGX = 0x92
_OP_IMPLICIT_VALUE = 0x9E
_OP_STACK_VALUE = 0x9F


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


@dataclass(frozen=True)
class DwarfVariable:
    """A named source variable and the location(s) it occupies."""

    name: str
    location: VariableLocation


@dataclass(frozen=True)
class DwarfFunction:
    """A source function's entry address and its named local variables and parameters."""

    low_pc: int
    variables: Tuple[DwarfVariable, ...]


def _die_name(die) -> Optional[str]:
    """Return the decoded DW_AT_name of a Debugging Information Entry (DIE), or None if it is unnamed."""
    name_attr = die.attributes.get("DW_AT_name")
    return name_attr.value.decode() if name_attr else None


def _walk_locals(die) -> Iterator:
    """Yield the variable and parameter DIEs under a subprogram, descending into lexical blocks."""
    for child in die.iter_children():
        if child.tag in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
            yield child
        elif child.tag == "DW_TAG_lexical_block":
            yield from _walk_locals(child)


class _DwarfParser:
    """Turns a binary's DWARF into the in-memory model, isolating all elftools coupling."""

    def __init__(self, elf: ELFFile):
        self._dwarf = elf.get_dwarf_info()
        self._arch: str = elf.get_machine_arch()
        self._cfa_delta: int = _CFA_DELTA_BY_ARCH.get(self._arch, 8)
        self._location_parser = LocationParser(self._dwarf.location_lists())

    def parse(self) -> Dict[str, DwarfFunction]:
        """Parse every named subprogram into a {function_name: DwarfFunction} model."""
        functions: Dict[str, DwarfFunction] = {}
        for compilation_unit in self._dwarf.iter_CUs():
            expr_parser = DWARFExprParser(compilation_unit.structs)
            dwarf_version = compilation_unit["version"]
            for die in compilation_unit.iter_DIEs():
                parsed = self._parse_subprogram(die, expr_parser, dwarf_version)
                if parsed is not None:
                    name, function = parsed
                    functions[name] = function
        return functions

    def _parse_subprogram(self, die, expr_parser, dwarf_version) -> Optional[Tuple[str, DwarfFunction]]:
        """Parse one DW_TAG_subprogram DIE into (name, DwarfFunction), or None if it is not a named function."""
        if die.tag != "DW_TAG_subprogram":
            return None
        low_pc = die.attributes.get("DW_AT_low_pc")
        name = _die_name(die)
        if low_pc is None or name is None:
            return None
        variables = tuple(self._parse_locals(die, expr_parser, dwarf_version, low_pc.value))
        return name, DwarfFunction(low_pc.value, variables)

    def _parse_locals(self, die, expr_parser, dwarf_version, low_pc) -> Iterator[DwarfVariable]:
        """Yield the named local variables and parameters of a subprogram that have a resolvable location."""
        for local_die in _walk_locals(die):
            location = self._location_of(local_die, expr_parser, dwarf_version, low_pc)
            name = _die_name(local_die)
            if name is not None and location is not None:
                yield DwarfVariable(name, location)

    def _location_of(self, die, expr_parser, dwarf_version, low_pc) -> Optional[VariableLocation]:
        """Parse a variable's DW_AT_location into a VariableLocation, or None if it has no matchable storage.

        A DW_AT_location is either a single expression (one location for the whole function) or a
        location list (the variable moves between locations over PC ranges, made absolute against low_pc).
        """
        location_attr = die.attributes.get("DW_AT_location")
        if location_attr is None or not self._location_parser.attribute_has_location(location_attr, dwarf_version):
            return None
        parsed_location = self._location_parser.parse_from_attribute(location_attr, dwarf_version, die=die)
        if isinstance(parsed_location, LocationExpr):
            storage = self._decode_storage(expr_parser.parse_expr(parsed_location.loc_expr))
            return FixedLocation(storage) if storage is not None else None
        return RangedLocation(tuple(self._parse_ranges(parsed_location, expr_parser, low_pc)))

    def _parse_ranges(self, parsed_location, expr_parser, low_pc) -> Iterator[PcRange]:
        """Yield the PC ranges of a location list, resolving each range's storage descriptor."""
        base_address = low_pc
        for entry in parsed_location:
            if isinstance(entry, BaseAddressEntry):
                base_address = entry.base_address
                continue
            if getattr(entry, "is_absolute", False):
                low, high = entry.begin_offset, entry.end_offset
            else:
                low, high = base_address + entry.begin_offset, base_address + entry.end_offset
            yield PcRange(low, high, self._decode_storage(expr_parser.parse_expr(entry.loc_expr)))

    def _decode_storage(self, parsed_opcodes) -> Optional[StorageLocation]:
        """Decode a parsed DWARF location expression into a StorageLocation, or None if it has no matchable storage.

        Returns None for an empty expression, a computed/implicit value with no storage, or any form
        we do not match here (breg / global / composite).
        """
        if not parsed_opcodes or any(op.op in (_OP_STACK_VALUE, _OP_IMPLICIT_VALUE) for op in parsed_opcodes):
            return None
        if len(parsed_opcodes) == 1:
            operation = parsed_opcodes[0]
            if operation.op == _OP_FBREG:
                return StackSlot(operation.args[0] + self._cfa_delta)
            if _OP_REG0 <= operation.op <= _OP_REG31:
                return RegisterSlot(describe_reg_name(operation.op - _OP_REG0, self._arch))
            if operation.op == _OP_REGX:
                return RegisterSlot(describe_reg_name(operation.args[0], self._arch))
        return None


class DwarfVariableResolver:
    """Matches lifted variables to their DWARF source-variable names by storage location."""

    def __init__(self, path: Optional[str]):
        """Parse the DWARF at path (if any); leave the resolver inert on any failure.

        :param path: filesystem path to the ELF binary, or None to build an inert resolver
        """
        self._functions: Dict[str, DwarfFunction] = {}
        if _DWARF_AVAILABLE and path:
            try:
                self._functions = _parse_dwarf(path)
            except Exception as exc:  # never let ground-truth parsing break lifting
                logging.warning(f"DWARF parsing failed for {path}: {exc}")

    @classmethod
    @lru_cache(maxsize=None)
    def for_path(cls, path: Optional[str]) -> DwarfVariableResolver:
        """Return a resolver for the given binary path, parsed at most once per path."""
        return cls(path)

    @property
    def available(self) -> bool:
        """True if DWARF was parsed and at least one function's variables are known."""
        return bool(self._functions)

    def source_name(self, origin, function_name: str, register_name=None) -> Optional[str]:
        """Return the C source-variable name matching a lifted variable's provenance.

        :param origin: the variable's VariableProvenance (source_type, storage, def_address, function)
        :param function_name: the (BN) function name the variable belongs to
        :param register_name: callable BN-register-index -> name, for register variables
        """
        if origin is None or origin.storage is None:
            return None
        function = self._functions.get(function_name)
        if function is None:
            return None
        lifted = LiftedLocation.from_provenance(origin, register_name)
        dwarf_pc = self._dwarf_pc(origin, function.low_pc)
        for variable in function.variables:
            storage = variable.location.storage_at(dwarf_pc)
            if storage is not None and storage.matches(lifted):
                return variable.name
        return None

    @staticmethod
    def _dwarf_pc(origin, low_pc: int) -> Optional[int]:
        """Translate a variable's BN definition address into the corresponding DWARF PC, or None.

        The DWARF PC is where this SSA version is defined; it is used to index location lists.
        """
        if origin.def_address is None or origin.function is None:
            return None
        return origin.def_address - (origin.function - low_pc)  # BN address -> DWARF pc


def _parse_dwarf(path: str) -> Dict[str, DwarfFunction]:
    """Open an ELF binary and parse its DWARF into the {function_name: DwarfFunction} model (empty if none)."""
    with open(path, "rb") as file_handle:
        elf_file = ELFFile(file_handle)
        if not elf_file.has_dwarf_info():
            return {}
        return _DwarfParser(elf_file).parse()