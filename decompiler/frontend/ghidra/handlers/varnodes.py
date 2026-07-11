"""Handler lifting Ghidra Varnode objects to dewolf pseudo expressions."""

import logging
from typing import Optional, Union

from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, GlobalVariable, Integer, OperationType, Pointer, UnaryOperation
from decompiler.structures.pseudo.expressions import Variable

BYTE_SIZE = 8
GLOBAL_VARIABLE_PREFIX = "data_"


class VarnodeHandler(Handler):
    """Lift ghidra varnodes (SSA values) onto pseudo expressions."""

    def register(self) -> None:
        self._lifter.lift_varnode = self.lift_varnode

    def lift_varnode(self, vn, destination: bool = False, **kwargs) -> Optional[Union[Variable, Constant, GlobalVariable]]:
        """Lift a single varnode.

        :param destination: True if this varnode is the output (being written to) of an op.
        """
        if vn is None:
            return None
        try:
            if vn.isConstant():
                return self._lift_constant(vn)
            if vn.isAddress():
                return self._lift_address(vn, destination=destination)
            return self._lift_variable(vn, destination=destination)
        except Exception as exc:  # noqa: BLE001
            logging.warning("[GhidraVarnodeHandler] failed to lift %r: %s", vn, exc)
            return Variable(f"vn_{vn.getUniqueId()}", self._lifter.lift_type(None))

    def _lift_constant(self, vn) -> Constant:
        value = int(vn.getOffset())
        size = int(vn.getSize()) or 4
        # A pointer-sized constant that addresses a defined string -> lift as a string literal
        # (e.g. ``apr_optional_hook_get("create_req")`` instead of ``apr_optional_hook_get(0x52c038)``),
        # matching Binary Ninja's string recovery.
        if size * BYTE_SIZE == self._lifter._address_size_bits():
            if (s := self._lifter._string_at(value)) is not None:
                return Constant(s, vartype=Pointer(Integer.char()))
        # Default integer constants to *signed* (matching the Binary Ninja frontend), so ordinary
        # literals render as ``0`` / ``1`` / ``8`` instead of the noisy ``0U`` / ``1U`` the codegen
        # emits to preserve an unsigned type. We only sign when the value's top bit (at its own
        # width) is clear -- i.e. signed and unsigned render identically -- so a genuine high-bit
        # value (a flag like ``0x80000000`` or a mask like ``0xffffffff``) keeps its unsigned type
        # and current rendering rather than flipping to a confusing negative decimal.
        signed = 0 <= value < (1 << (size * BYTE_SIZE - 1))
        vartype = Integer(size * BYTE_SIZE, signed=signed)
        return Constant(value, vartype=vartype)

    def _lift_address(self, vn, destination: bool):
        """A varnode in the ram address space: an aliased global variable, versioned by memory version.

        Address varnodes that reach the lifter (i.e. not call/branch targets, which are handled
        inline) denote fixed globals tracked by Ghidra's memory SSA. We lift them as aliased
        ``GlobalVariable``\ s whose ``ssa_label`` is the memory version in scope (assigned by
        ``precompute_memory_versions`` via INDIRECT / address-MULTIEQUAL), so the pipeline's
        mem-phi and missing-definitions stages see consistent labels. A varnode that actually
        addresses a function is lifted as a ``FunctionSymbol`` (function pointer value).
        """
        addr = int(vn.getOffset())
        size = int(vn.getSize()) or 8
        program = self._lifter.program
        # Function pointer used as a value (e.g. passed as an argument).
        try:
            if program.getFunctionManager().getFunctionAt(self._lifter._address(addr)) is not None:
                return self._lifter._function_symbol_at(program, addr)
        except Exception:  # noqa: BLE001
            pass
        name = self._global_name(program, addr)
        vartype = self._lifter._global_type(program, addr, size)
        # A global that the function never genuinely writes holds a constant value throughout, so it
        # is lifted as a plain, non-aliased single-version global. This bypasses the aliased memory-
        # version machinery (memory phis + per-memory-op carry-forward Relations) that Ghidra's
        # conservative, per-call INDIRECTs would otherwise blow up -- matching Binary Ninja, which
        # does not re-version a global merely because a call might touch it. Only genuinely-written
        # globals (see precompute_written_globals) keep the aliased, versioned treatment.
        is_aliased = addr in self._lifter._written_globals
        ssa_label = self._lifter._addr_version.get(int(vn.getUniqueId()), 0) if is_aliased else 0
        return GlobalVariable(
            name,
            vartype=vartype,
            initial_value=Constant(addr, vartype=Pointer(vartype, size * BYTE_SIZE)),
            ssa_label=ssa_label,
            is_aliased=is_aliased,
        )

    def _lift_variable(self, vn, destination: bool) -> Variable:
        name = self._lifter._name_for(vn)
        vartype = self._lifter._type_for_varnode(vn)
        is_aliased = self._lifter._is_aliased(vn)
        return Variable(name, vartype, ssa_label=self._lifter._version(vn), is_aliased=is_aliased)

    def _global_name(self, program, addr: int) -> str:
        """Deterministic name for a global by its address.

        We prefer a real (symbol-table) name from Ghidra when one exists (e.g. ``lut``), looked up
        by address so it is stable and does not split one global into two. We deliberately ignore
        Ghidra's auto-generated ``DAT_`` labels (flaky per-varnode); without a real symbol we fall
        back to ``data_<hex>`` (Binary Ninja's convention).
        """
        if (sym := self._lifter._global_symbol_name(addr)) is not None:
            return sym
        return f"{GLOBAL_VARIABLE_PREFIX}{hex(addr)}"

    @staticmethod
    def _purge(name: str) -> str:
        return name.translate({ord(" "): "_", ord("'"): "", ord("."): "_", ord("`"): ""})
