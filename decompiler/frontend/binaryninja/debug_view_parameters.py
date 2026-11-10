"""Entry-parameter source "debug_view": the registers Binary Ninja assigns to a function's parameters.

The alternative to SysVAbiParameterSource (parameter_sources.py). It opens the binary a second time,
with Binary Ninja's own debug-info import enabled, and aligns each function's parameter variables
with the DWARF formal parameters by position - like the original matching did on the lifted view
itself (VariableHandler._parameter_source_name_by_index), which no longer works there because the
lifted view is analysed without debug information. The second view is only read and closed again;
the view that is lifted keeps the analysis settings it was opened with.

Binary Ninja (5.3) resolves the calling convention correctly for values in one register, but not
for everything else: values in two registers (structs of 9-16 bytes, __int128, complex) and
float-only structs are put on the stack or in the wrong register class, long double / packed / empty
structs are given a register, and the hidden result pointer of a function returning an aggregate in
memory is not accounted for. All of those shift the registers of the parameters that follow. So
Binary Ninja's placement of a parameter is checked against the parameter's DWARF type, and a
function's parameters are named only up to the first one that fails the check (see _entry_registers).
Never a wrong name, at the price of the names SysVAbiParameterSource derives beyond that point.

Costs a second full analysis per binary. Selected by parameter_sources.PARAMETER_SOURCE.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from .dwarf import CLASS_INTEGER, CLASS_SSE, DwarfFunction, DwarfVariableResolver, SourceMatch
from .parameter_sources import canonical_register, is_clone

_REGISTER_SOURCE_TYPE = "RegisterVariableSourceType"

# Why the naming of a function's parameters ended before its last parameter (DebugViewParameterSource.stopped).
STOP_RESULT_POINTER = "hidden result pointer"  # returns an aggregate in memory (or an unclassifiable type)
STOP_COUNT = "parameter count"  # Binary Ninja and DWARF list different numbers of parameters
STOP_TWO_REGISTERS = "value in two registers"  # or a type whose layout could not be classified
STOP_PLACEMENT = "placement"  # Binary Ninja does not place the parameter where its type belongs


def _argument_registers(arch, calling_convention) -> Dict[str, List[Optional[str]]]:
    """Binary Ninja's argument registers of a calling convention per eightbyte class, in assignment order."""
    if calling_convention is None:
        return {CLASS_INTEGER: [], CLASS_SSE: []}
    return {
        CLASS_INTEGER: [canonical_register(arch, name) for name in calling_convention.int_arg_regs],
        CLASS_SSE: [canonical_register(arch, name) for name in calling_convention.float_arg_regs],
    }


def _entry_registers(arch, function, dwarf_function: DwarfFunction) -> Tuple[Dict[str, SourceMatch], Optional[str]]:
    """The {register: formal parameter} table of one function of the debug-info view, and why the
    naming stopped early (a STOP_* reason, None if every parameter was accepted).

    Binary Ninja's parameter variables and the DWARF formal parameters are aligned by position, which
    requires equally many of both. If Binary Ninja applied the DWARF signature they are the same list;
    if it did not (it skips functions sharing their name with another one, e.g. a static function from
    a header), its own parameter analysis found the registers and the count check decides whether it
    saw the same parameters as the source.

    A parameter is accepted if Binary Ninja places it where the calling convention puts a value of its
    DWARF type: a value of one eightbyte in the next unused integer or float argument register of
    Binary Ninja's calling convention (on the stack once those are used up), a value passed in memory
    on the stack. Binary Ninja cannot place a value of two eightbytes, so naming stops there, as it
    does at the first parameter placed differently - from then on the registers are shifted. Nothing
    is named if the function returns an aggregate in memory, whose hidden result pointer takes the
    first integer register without Binary Ninja knowing.
    """
    if dwarf_function.returns_in_memory is not False:
        return {}, STOP_RESULT_POINTER
    variables = list(function.parameter_vars)
    parameters = dwarf_function.parameters
    if len(variables) != len(parameters):
        return {}, STOP_COUNT
    registers = _argument_registers(arch, function.calling_convention)
    used = {CLASS_INTEGER: 0, CLASS_SSE: 0}
    table: Dict[str, SourceMatch] = {}
    for variable, parameter in zip(variables, parameters):
        eightbytes = parameter.eightbytes
        if eightbytes is None or len(eightbytes) > 1:
            return table, STOP_TWO_REGISTERS
        expected = None
        for eightbyte in eightbytes:
            if used[eightbyte] < len(registers[eightbyte]):
                expected = registers[eightbyte][used[eightbyte]]
            used[eightbyte] += 1
        actual = None
        if variable.source_type.name == _REGISTER_SOURCE_TYPE:
            actual = canonical_register(arch, arch.get_reg_name(variable.storage))
        if actual != expected:
            return table, STOP_PLACEMENT
        if actual is not None and parameter.name is not None:
            table[actual] = SourceMatch(parameter.name, parameter.die_offset)
    return table, None


class DebugViewParameterSource:
    """Entry registers read from a second Binary Ninja view that imported the debug information.

    The view is opened lazily on the first query, every function's table is read (see
    _entry_registers) and the view is closed again.
    """

    def __init__(self, dwarf: DwarfVariableResolver, path: Optional[str], load_base: Optional[int], max_function_size: Optional[int] = None):
        self._dwarf = dwarf
        self._path = path
        self._load_base = load_base
        self._max_function_size = max_function_size
        self._tables: Optional[Dict[int, Dict[str, SourceMatch]]] = None
        self.stopped: Dict[int, str] = {}  # {function start: STOP_* reason}, for diagnostics

    def entry_parameter(self, bn_function_start: int, register_name: str, symbol_name: Optional[str] = None) -> Optional[SourceMatch]:
        """Return the formal parameter arriving in `register_name` at entry of the function at
        `bn_function_start` (an address of the lifted view), or None if unknown."""
        if is_clone(symbol_name):
            return None
        if self._tables is None:
            self._tables = self._build_tables()
        return self._tables.get(bn_function_start, {}).get(register_name)

    def _build_tables(self) -> Dict[int, Dict[str, SourceMatch]]:
        """Open the debug-info view, read {function start: {register: formal parameter}}, close it."""
        # The placement check uses the DWARF eightbyte classes, which are those of x86-64 System V.
        if not self._path or not self._dwarf.available or self._dwarf.arch != "x64":
            return {}
        try:
            import binaryninja

            options: Dict[str, object] = {"analysis.debugInfo.internal": True}
            if self._max_function_size is not None:
                options["analysis.limits.maxFunctionSize"] = self._max_function_size
            view = binaryninja.load(self._path, options=options)
        except Exception as exc:
            logging.warning(f"could not open the debug-info view of {self._path}: {exc}")
            return {}
        if view is None:
            return {}
        try:
            # Translate the debug view's addresses to the lifted view's, should the two load the image differently.
            shift = (self._load_base - view.start) if self._load_base is not None else 0
            tables: Dict[int, Dict[str, SourceMatch]] = {}
            for function in view.functions:
                if is_clone(function.name):
                    continue
                dwarf_function = self._dwarf.function_at(function.start, view.start)
                if dwarf_function is None:
                    continue
                table, reason = _entry_registers(view.arch, function, dwarf_function)
                if table:
                    tables[function.start + shift] = table
                if reason is not None:
                    self.stopped[function.start + shift] = reason
            return tables
        except Exception as exc:
            logging.warning(f"could not read the parameters from the debug-info view of {self._path}: {exc}")
            return {}
        finally:
            view.file.close()
