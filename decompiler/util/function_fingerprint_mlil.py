"""Structural fingerprint built directly on BinaryNinja's MLIL SSA form, for the NARROWER
goal of recognizing functions that are literally the same compiled object code (e.g. the same
statically-linked library routine) differing only in relocation-sensitive addresses and the
string/assert content those addresses point to.

The fingerprint is name agnostic: neither the function's own name nor the names of what it refers
to (called functions, imports, globals) enter it, whether or not BinaryNinja knows symbols for them.
A referenced address is replaced by the order of its first mention in the function ("<address1>",
"<address2>", ...), so two functions that differ only in which functions or globals they use get the
same fingerprint, while "the same target twice" and "two different targets" stay distinguishable, and
a recursive function does not contain its own name. What a call passes and returns is part of the
instruction and stays in.
"""

import hashlib
from typing import Dict, Optional

from binaryninja.binaryview import BinaryView
from binaryninja.enums import RegisterValueType
from binaryninja.function import Function
from binaryninja.mediumlevelil import MediumLevelILBasicBlock, MediumLevelILFunction, MediumLevelILInstruction, SSAVariable

# Instruction operations that are pure relocation-sensitive addresses, never real numeric
# values
_ADDRESS_LIKE_OPS = frozenset({"MLIL_CONST_PTR", "MLIL_IMPORT", "MLIL_EXTERN_PTR"})

# MLIL_CONST_DATA .constant is a ConstantData wrapper, not a plain
# int. Only its ConstantDataAggregateValue variant is an address (an inline struct/string
# literal's location, e.g. a __builtin_strncpy source). Its ZeroExtend/SignExtend variants
# carry a genuine numeric value in .value, not an address.
# Those must NOT be blinded, or we'd be blinding real constants by accident.
_CONST_DATA_ADDRESS_TYPES = frozenset({RegisterValueType.ConstantDataAggregateValue})

# MLIL_MEM_PHI tracks memory-SSA versions (compiler-internal bookkeeping about which prior
# memory-writing instructions a load might observe), not a real program variable or value
# therefor dropped entirely
_DROPPED_OPS = frozenset({"MLIL_MEM_PHI"})


# {address: number} of the addresses one function refers to, in order of first mention.
AddressNumbers = Dict[int, int]


def _resolve_address(address: int, addresses: AddressNumbers) -> str:
    # Addresses are relocation-sensitive and the names behind them must not matter, so an address
    # is blinded to a placeholder carrying only the order of its first mention in the function.
    # Symbols are deliberately not looked up: with BinaryNinja's debug-info import their names would
    # enter the fingerprint, and without it every symbol is "auto" and indistinguishable anyway.
    return f"<address{addresses.setdefault(address, len(addresses) + 1)}>"


def _serialize_var(var: SSAVariable) -> str:
    # For truly identical compiled code, BinaryNinja's own
    # SSA variable naming/versioning is a function of the instruction sequence itself, not of
    # load address, so it should already match between two relocated copies.
    return f"{var.var.name}#{var.version}"


def _serialize_expr(expr, bv: BinaryView, addresses: AddressNumbers) -> str:
    if isinstance(expr, SSAVariable):
        return _serialize_var(expr)
    if isinstance(expr, list):
        return "[" + ",".join(_serialize_expr(v, bv, addresses) for v in expr) + "]"
    if isinstance(expr, dict):
        # MLIL_JUMP_TO.targets: {raw jump-table-entry address: target MLIL instruction index}.
        # The address is relocation-sensitive and redundant. Keep only the blind, sorted values.
        return "{" + ",".join(str(v) for v in sorted(expr.values())) + "}"
    if not isinstance(expr, MediumLevelILInstruction):
        return str(expr)  # Raw int/str leaf (e.g. a memory-version number) -> kept exact

    op = expr.operation.name
    if op in _ADDRESS_LIKE_OPS:
        # MLIL_EXTERN_PTR additionally carries a byte offset into the external symbol
        # (e.g. a field access on an unresolved extern struct).
        # CONST_PTR/IMPORT only ever carry the one "constant" operand,
        # so this is a no-op for them. Dropping it for EXTERN_PTR would silently treat two
        # different field accesses on the same external symbol as identical.
        offset = getattr(expr, "offset", 0)
        resolved = _resolve_address(expr.constant, addresses)
        return f"{resolved}+{offset}" if offset else resolved
    if op == "MLIL_CONST" and bv.is_valid_offset(expr.constant):
        # A bare MLIL_CONST can still be a real address disguised as a plain integer.
        # bv.is_valid_offset is cheap and the false-positive risk is low in practice,
        # since a small numeric constant landing exactly inside the binary's narrow mapped
        # range by coincidence is unlikely.
        return _resolve_address(expr.constant, addresses)
    if op == "MLIL_CONST_DATA":
        constant_data = expr.constant
        if constant_data.type in _CONST_DATA_ADDRESS_TYPES:
            return _resolve_address(constant_data.value, addresses)
        return f"const_data:{constant_data.type.name}:{constant_data.value}"

    # Fallback for every other opcode: none of these carry a relocation-sensitive address,
    # so just recurse into every operand and keep it exact.
    operand_strs = [_serialize_expr(value, bv, addresses) for _, value, _ in expr.detailed_operands]
    return f"({op} {' '.join(operand_strs)})"


def _serialize_instruction(instr: MediumLevelILInstruction, bv: BinaryView, addresses: AddressNumbers) -> Optional[str]:
    op = instr.operation.name
    if op in _DROPPED_OPS:
        return None
    return _serialize_expr(instr, bv, addresses)


def function_fingerprint(function: Function) -> str:
    """A hash that collides for functions whose MLIL SSA instruction sequence is identical
    modulo the relocation-sensitive addresses it refers to and the names behind them (see the
    module docstring). Only guaranteed self-consistent within one corpus preparation run."""

    bv = function.view
    mlil: MediumLevelILFunction = function.mlil.ssa_form

    block_offset = {}
    addresses: AddressNumbers = {}  # numbered in the order the instructions mention them

    def block_id(block: MediumLevelILBasicBlock) -> int:
        return block_offset.setdefault(block.start, block.start)

    lines = []
    for block in mlil.basic_blocks:
        lines.append(f"B{block_id(block)}")
        phi_lines = []
        other_lines = []
        for instr in block:
            serialized = _serialize_instruction(instr, bv, addresses)
            if serialized is None:
                continue
            if instr.operation.name == "MLIL_VAR_PHI":
                phi_lines.append(serialized)
            else:
                other_lines.append(serialized)
        lines.extend(sorted(phi_lines))
        lines.extend(other_lines)
        edge_strs = [f"{edge.type.name}->{block_id(edge.target)}" for edge in block.outgoing_edges]
        lines.append(f"edges:{sorted(edge_strs)}")

    canonical_text = "\n".join(lines)
    return hashlib.sha256(canonical_text.encode()).hexdigest()
