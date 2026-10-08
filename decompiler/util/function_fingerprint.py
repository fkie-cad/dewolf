import hashlib
import re
from typing import Dict, Tuple

from decompiler.structures.graphs.branches import SwitchCase
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo.expressions import (
    Constant,
    Expression,
    GlobalVariable,
    Symbol,
    Variable,
)
from decompiler.structures.pseudo.instructions import (
    Assignment,
    Comment,
    GenericBranch,
    Instruction,
    Phi,
    Relation,
    Return,
)
from decompiler.structures.pseudo.operations import COMMUTATIVE_OPERATIONS, Call, MemberAccess, Operation, UnaryOperation

_VarKey = Tuple[str, object, str, bool]

_BN_AUTO_NAME = re.compile(r"(sub|data)_[0-9a-fA-F]+")


class _Canonicalizer:
    def __init__(self) -> None:
        self._block_id: Dict[BasicBlock, int] = {}
        self._var_id: Dict[_VarKey, int] = {}

    def block(self, block: BasicBlock) -> int:
        return self._block_id.setdefault(block, len(self._block_id))

    def positional_variable_id(self, var: Variable) -> int:
        key: _VarKey = (var.name, var.ssa_label, str(var.type), var.is_aliased)
        return self._var_id.setdefault(key, len(self._var_id))


def _variable_identity(var: Variable, c: "_Canonicalizer") -> str:
    if var.origin is not None and var.origin.source_name is not None:
        return f"src:{var.origin.source_name}"
    return f"pos:{c.positional_variable_id(var)}"


def _serialize_constant(const: Constant) -> str:
    return "const"


def _serialize_global(expr: GlobalVariable) -> str:
    return "gvar"


def _serialize_array_info(array_info, c: "_Canonicalizer") -> str:
    index = array_info.index
    index_str = _serialize_expr(index, c) if isinstance(index, Expression) else "idx:literal"
    base_str = _serialize_expr(array_info.base, c) if array_info.base is not None else "none"
    return f"[base={base_str},index={index_str},confidence={array_info.confidence}]"


def _serialize_expr(expr: Expression, c: "_Canonicalizer") -> str:
    if isinstance(expr, GlobalVariable):
        return _serialize_global(expr)
    if isinstance(expr, Symbol):
        if _BN_AUTO_NAME.fullmatch(expr.name):
            return f"sym:{type(expr).__name__}:unresolved"
        return f"sym:{type(expr).__name__}:{expr.name}"
    if isinstance(expr, Constant):
        return _serialize_constant(expr)
    if isinstance(expr, Variable):
        return f"v:{_variable_identity(expr, c)}"
    if isinstance(expr, Call):
        operand_strs = [_serialize_expr(op, c) for op in expr.operands]
        return f"(call {_serialize_expr(expr.function, c)} {' '.join(operand_strs)})"
    if isinstance(expr, MemberAccess):
        return f"(member_access {_serialize_expr(expr.operand, c)}.{expr.member_name}@{expr.member_offset})"
    if isinstance(expr, UnaryOperation):
        parts = [f"contraction={expr.contraction}"]
        if expr.array_info is not None:
            parts.append(_serialize_array_info(expr.array_info, c))
        return f"({expr.operation.name} {_serialize_expr(expr.operand, c)} {' '.join(parts)})"
    if isinstance(expr, Operation):
        operand_strs = [_serialize_expr(op, c) for op in expr.operands]
        if expr.operation in COMMUTATIVE_OPERATIONS:
            operand_strs.sort()
        return f"({expr.operation.name} {' '.join(operand_strs)})"
    return f"expr:{type(expr).__name__}:{expr!r}"


def _serialize_instruction(instr: Instruction, c: "_Canonicalizer") -> str:
    if isinstance(instr, Comment):
        return ""
    if isinstance(instr, Phi):
        origins = sorted(
            (c.block(pred), _serialize_expr(val, c) if val is not None else "undef")
            for pred, val in instr.origin_block.items()
        )
        return f"{type(instr).__name__} {_serialize_expr(instr.destination, c)} = {origins}"
    if isinstance(instr, Relation):
        return f"rel {_serialize_expr(instr.destination, c)} = {_serialize_expr(instr.value, c)}"
    if isinstance(instr, Return):
        return f"return {_serialize_expr(instr.values, c)}"
    if isinstance(instr, GenericBranch):
        return f"{type(instr).__name__} {_serialize_expr(instr.condition, c)}"
    if isinstance(instr, Assignment):
        return f"assign {_serialize_expr(instr.destination, c)} = {_serialize_expr(instr.value, c)}"
    defs = [_serialize_expr(v, c) for v in instr.definitions]
    reqs = [_serialize_expr(v, c) for v in instr.requirements]
    return f"{type(instr).__name__}:{defs}<-{reqs}"


def function_fingerprint(cfg: ControlFlowGraph) -> str:
    if cfg.root is None:
        raise ValueError("Cannot fingerprint a CFG without a root/entry block.")

    c = _Canonicalizer()
    lines = []
    for block in cfg.iter_depth_first(cfg.root):
        lines.append(f"B{c.block(block)}")
        pending_unordered: list[str] = []
        for instr in block.instructions:
            serialized = _serialize_instruction(instr, c)
            if not serialized:
                continue
            if isinstance(instr, (Phi, Relation)):
                pending_unordered.append(serialized)
                continue
            if pending_unordered:
                lines.extend(sorted(pending_unordered))
                pending_unordered = []
            lines.append(serialized)
        if pending_unordered:
            lines.extend(sorted(pending_unordered))
        edge_strs = [
            f"{edge.condition_type.value}->{c.block(edge.sink)}" + (f"[{len(edge.cases)}]" if isinstance(edge, SwitchCase) else "")
            for edge in cfg.get_out_edges(block)
        ]
        lines.append(f"edges:{sorted(edge_strs)}")

    canonical_text = "\n".join(lines)
    return hashlib.sha256(canonical_text.encode()).hexdigest()
