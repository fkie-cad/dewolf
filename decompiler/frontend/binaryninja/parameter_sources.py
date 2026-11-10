"""Name register parameters at function entry with their DWARF formal parameter.

At -O0, DWARF describes a parameter by the stack slot the prologue spills it to, not by the
register it arrives in, so the entry version of that register (e.g. rdi#0) cannot be matched by
location like everything else in dwarf.py. An entry-parameter source provides the missing table
"register at entry -> formal parameter" per function. There are two, interchangeable behind
entry_parameter(); PARAMETER_SOURCE picks the one the lifter uses:

- "abi": SysVAbiParameterSource derives the registers from the DWARF parameter types with the
  x86-64 System V calling convention, including the classification of structs of at most 16 bytes.
  It needs no Binary Ninja analysis of its own, so it works the same whether or not Binary Ninja
  imported the debug information.
- "debug_view": DebugViewParameterSource (debug_view_parameters.py) reads the registers Binary Ninja
  assigns in a second view of the binary that imported the debug information.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Dict, Optional

from .dwarf import CLASS_INTEGER, DwarfFunction, DwarfVariableResolver, SourceMatch

# The entry-parameter source the lifter uses: "abi" or "debug_view" (see the module docstring).
# The two label differently: after changing it, do not resume a cv pipeline run labelled with the other one.
PARAMETER_SOURCE = "abi"

# x86-64 System V argument registers, in assignment order.
SYSV_INTEGER_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
SYSV_SSE_REGISTERS = tuple(f"xmm{index}" for index in range(8))


def canonical_register(arch, register_name: Optional[str]) -> Optional[str]:
    """Normalize a Binary Ninja register name to the name used in the parameter tables.

    General-purpose sub-registers map to their full-width register (edi -> rdi); vector registers
    map to their xmm name (zmm0/ymm0 -> xmm0), since only the low lane carries a float argument.
    """
    if register_name is None:
        return None
    for prefix in ("zmm", "ymm"):
        if register_name.startswith(prefix):
            return "xmm" + register_name[len(prefix) :]
    if register_name.startswith("xmm") or arch is None:
        return register_name
    try:
        return arch.regs[register_name].full_width_reg
    except Exception:
        return register_name


def is_clone(symbol_name: Optional[str]) -> bool:
    """True for a GCC clone (foo.isra.0, foo.constprop.0, foo.part.0, foo.cold): its parameters may have
    been removed or reordered by the compiler, so the declared signature does not describe its registers."""
    return symbol_name is not None and "." in symbol_name


def sysv_entry_registers(function: DwarfFunction) -> Dict[str, SourceMatch]:
    """The {register: formal parameter} table the x86-64 System V convention gives a DWARF function.

    Each parameter is passed as its eightbytes (see dwarf._eightbytes): an INTEGER eightbyte takes the
    next of rdi, rsi, rdx, rcx, r8, r9, an SSE eightbyte the next of xmm0-xmm7, so a struct of at
    most 16 bytes may take one or two registers of either class. If the registers left do not suffice
    for all eightbytes of a parameter, the whole parameter goes to the stack and later parameters may
    still use the registers. A parameter passed in memory consumes no register; a function returning
    an aggregate in memory receives the hidden result pointer in rdi first. Only the register of a
    parameter's first eightbyte is named (like a split stack object, only its start is labelled).
    Assignment stops at a parameter whose layout could not be classified, and the table is empty if
    the return type could not be, so no register is ever named by a guess. Unnamed parameters still
    consume their registers but get no entry.
    """
    table: Dict[str, SourceMatch] = {}
    if function.returns_in_memory is None:
        return table
    integer_index = 1 if function.returns_in_memory else 0
    sse_index = 0
    for parameter in function.parameters:
        eightbytes = parameter.eightbytes
        if eightbytes is None:
            break
        needed_integer = sum(1 for eightbyte in eightbytes if eightbyte == CLASS_INTEGER)
        needed_sse = len(eightbytes) - needed_integer
        if integer_index + needed_integer > len(SYSV_INTEGER_REGISTERS) or sse_index + needed_sse > len(SYSV_SSE_REGISTERS):
            continue  # passed on the stack as a whole
        registers = []
        for eightbyte in eightbytes:
            if eightbyte == CLASS_INTEGER:
                registers.append(SYSV_INTEGER_REGISTERS[integer_index])
                integer_index += 1
            else:
                registers.append(SYSV_SSE_REGISTERS[sse_index])
                sse_index += 1
        if registers and parameter.name is not None:
            table[registers[0]] = SourceMatch(parameter.name, parameter.die_offset)
    return table


class SysVAbiParameterSource:
    """Entry registers computed from the DWARF parameter types (x86-64 System V only; inert otherwise)."""

    def __init__(self, dwarf: DwarfVariableResolver, load_base: Optional[int]):
        self._dwarf = dwarf
        self._load_base = load_base
        self._tables: Dict[int, Dict[str, SourceMatch]] = {}

    def entry_parameter(self, bn_function_start: int, register_name: str, symbol_name: Optional[str] = None) -> Optional[SourceMatch]:
        """Return the formal parameter arriving in `register_name` at entry of the function at
        `bn_function_start` (a disassembler address), or None if unknown."""
        if self._dwarf.arch != "x64" or is_clone(symbol_name):
            return None
        if bn_function_start not in self._tables:
            function = self._dwarf.function_at(bn_function_start, self._load_base)
            self._tables[bn_function_start] = sysv_entry_registers(function) if function is not None else {}
        return self._tables[bn_function_start].get(register_name)


@lru_cache(maxsize=None)
def _cached_source(kind: str, path: Optional[str], load_base: Optional[int], max_function_size: Optional[int]):
    dwarf = DwarfVariableResolver.for_path(path)
    if kind == "abi":
        return SysVAbiParameterSource(dwarf, load_base)
    if kind == "debug_view":
        from .debug_view_parameters import DebugViewParameterSource  # imports this module

        return DebugViewParameterSource(dwarf, path, load_base, max_function_size)
    raise ValueError(f"unknown entry-parameter source '{kind}'")


def make_parameter_source(bv, kind: Optional[str] = None):
    """Return the entry-parameter source of the given kind (default: PARAMETER_SOURCE) for the binary
    of view `bv`, built at most once per binary (inert without a view or DWARF)."""
    kind = kind or PARAMETER_SOURCE
    if bv is None:
        return _cached_source(kind, None, None, None)
    max_function_size = None
    if kind == "debug_view":
        try:  # analyse the second view with the same function size limit as the lifted one
            from binaryninja import Settings

            max_function_size = Settings().get_integer("analysis.limits.maxFunctionSize", bv)
        except Exception:
            max_function_size = None
    return _cached_source(kind, bv.file.filename, bv.start, max_function_size)
