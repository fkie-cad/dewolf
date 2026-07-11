"""Handler lifting Ghidra PcodeOp objects to dewolf pseudo instructions."""

import logging
from typing import Optional

from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Branch,
    Call,
    Condition,
    Constant,
    IndirectBranch,
    Integer,
    ListOperation,
    OperationType,
    Phi,
    Pointer,
    Return,
    UnaryOperation,
    UnknownExpression,
)
from decompiler.structures.pseudo.expressions import Variable

BYTE_SIZE = 8


class OpcodeHandler(Handler):
    """Lift p-code operations (flat SSA) onto pseudo instructions."""

    def register(self) -> None:
        from ghidra.program.model.pcode import PcodeOp

        P = PcodeOp
        # (p-code constant name, handler). Built via getattr so missing constants
        # (which differ across Ghidra versions) are skipped gracefully.
        handlers = [
            ("COPY", self.lift_copy),
            ("LOAD", self.lift_load),
            ("STORE", self.lift_store),
            ("BRANCH", self.lift_branch),
            ("CBRANCH", self.lift_cbranch),
            ("BRANCHIND", self.lift_branchind),
            ("CALL", self.lift_call),
            ("CALLIND", self.lift_callind),
            ("RETURN", self.lift_return),
            ("MULTIEQUAL", self.lift_phi),
            ("INDIRECT", self.lift_indirect),
            ("CAST", self.lift_cast),
            ("PTRADD", self.lift_ptradd),
            ("PTRSUB", self.lift_ptrsub),
            ("SUBPIECE", self.lift_subpiece),
            ("PIECE", self.lift_piece),
            ("INT_NEGATE", self.lift_unary_int(OperationType.bitwise_not)),
            ("INT_2COMP", self.lift_unary_int(OperationType.negate)),
            ("INT_SEXT", self.lift_extend),
            ("INT_ZEXT", self.lift_extend),
            ("BOOL_NEGATE", self.lift_unary_int(OperationType.logical_not)),
            ("INT_EQUAL", self.lift_compare(OperationType.equal)),
            ("INT_NOTEQUAL", self.lift_compare(OperationType.not_equal)),
            ("INT_LESS", self.lift_compare(OperationType.less_us)),
            ("INT_SLESS", self.lift_compare(OperationType.less)),
            ("INT_LESSEQUAL", self.lift_compare(OperationType.less_or_equal_us)),
            ("INT_SLESSEQUAL", self.lift_compare(OperationType.less_or_equal)),
            ("INT_ADD", self.lift_binary_int(OperationType.plus)),
            ("INT_SUB", self.lift_binary_int(OperationType.minus)),
            ("INT_MULT", self.lift_binary_int(OperationType.multiply)),
            ("INT_DIV", self.lift_binary_int(OperationType.divide_us)),
            ("INT_SDIV", self.lift_binary_int(OperationType.divide)),
            ("INT_REM", self.lift_binary_int(OperationType.modulo_us)),
            ("INT_SREM", self.lift_binary_int(OperationType.modulo)),
            ("INT_AND", self.lift_binary_int(OperationType.bitwise_and)),
            ("INT_OR", self.lift_binary_int(OperationType.bitwise_or)),
            ("INT_XOR", self.lift_binary_int(OperationType.bitwise_xor)),
            ("INT_LEFT", self.lift_binary_int(OperationType.left_shift)),
            ("INT_RIGHT", self.lift_binary_int(OperationType.right_shift_us)),
            ("INT_SRIGHT", self.lift_binary_int(OperationType.right_shift)),
            ("BOOL_AND", self.lift_binary_int(OperationType.logical_and)),
            ("BOOL_OR", self.lift_binary_int(OperationType.logical_or)),
            ("BOOL_XOR", self.lift_binary_int(OperationType.bitwise_xor)),
            ("FLOAT_ADD", self.lift_binary_int(OperationType.plus_float)),
            ("FLOAT_SUB", self.lift_binary_int(OperationType.minus_float)),
            ("FLOAT_MULT", self.lift_binary_int(OperationType.multiply_float)),
            ("FLOAT_DIV", self.lift_binary_int(OperationType.divide_float)),
            ("FLOAT_EQUAL", self.lift_compare(OperationType.equal)),
            ("FLOAT_NOTEQUAL", self.lift_compare(OperationType.not_equal)),
            ("FLOAT_LESS", self.lift_compare(OperationType.less)),
            ("FLOAT_LESSEQUAL", self.lift_compare(OperationType.less_or_equal)),
            ("FLOAT_NEG", self.lift_unary_int(OperationType.negate)),
            ("FLOAT_INT2FLOAT", self.lift_cast),
            ("FLOAT_FLOAT2FLOAT", self.lift_cast),
            ("FLOAT_TRUNC", self.lift_cast),
            ("FLOAT_CEIL", self.lift_unary_int(OperationType.cast)),
            ("FLOAT_FLOOR", self.lift_unary_int(OperationType.cast)),
            ("FLOAT_ROUND", self.lift_unary_int(OperationType.cast)),
            ("FLOAT_SQRT", self.lift_unary_int(OperationType.cast)),
            ("FLOAT_ABS", self.lift_unary_int(OperationType.cast)),
            # Boolean/flag ops Ghidra emits in high-pcode. These produce a 1-bit result that often
            # feeds a branch condition, so they need a precise boolean lowering (a synthetic call
            # would make z3-based stages such as dead-path-elimination choke on the condition).
            ("INT_CARRY", self.lift_int_carry),
            ("INT_SCARRY", self.lift_unknown_flag),
            ("INT_SBORROW", self.lift_unknown_flag),
            ("FLOAT_NAN", self.lift_float_nan),
        ]
        # Generic fallback for any p-code opcode without a dedicated handler (CALLOTHER, INSERT,
        # SEGMENTOP, NEW, POPCOUNT, LZCOUNT, ...). Defining the (possibly used) output as an opaque
        # expression prevents the "non-aliased variable has no definition" crash. We deliberately
        # use UnknownExpression (not a synthetic Call): z3's logic converter raises ValueError on
        # it, which dead-path-elimination catches and skips, whereas a Call would silently yield a
        # non-boolean and crash z3.
        self._lifter._fallback_lift = self.lift_generic
        for name, handler in handlers:
            opcode = getattr(P, name, None)
            if opcode is None:
                continue
            self._lifter.OPCODE_HANDLERS[int(opcode)] = handler
        compare_names = [
            "INT_EQUAL",
            "INT_NOTEQUAL",
            "INT_LESS",
            "INT_SLESS",
            "INT_LESSEQUAL",
            "INT_SLESSEQUAL",
            "FLOAT_EQUAL",
            "FLOAT_NOTEQUAL",
            "FLOAT_LESS",
            "FLOAT_LESSEQUAL",
        ]
        self._compare_opcodes = {int(getattr(P, n)) for n in compare_names if getattr(P, n, None) is not None}
        self._lifter._compare_opcodes = self._compare_opcodes

    # -- helpers -----------------------------------------------------------
    def _out(self, op):
        return op.getOutput()

    def _out_type(self, op):
        return self._lifter._type_for_varnode(self._out(op))

    def _in(self, op, i, address_of=True):
        return self._lifter.lift_varnode(op.getInput(i), address_of=address_of)

    def _inputs(self, op, address_of=True):
        return [self._lifter.lift_varnode(v, address_of=address_of) for v in op.getInputs()]

    # -- control flow ------------------------------------------------------
    def lift_branch(self, op, **kwargs):
        """Unconditional branch is encoded as an edge, no instruction."""
        return None

    def lift_cbranch(self, op, **kwargs) -> Branch:
        cond = self._lift_branch_condition(op)
        if not isinstance(cond, Condition):
            cond = Condition(OperationType.not_equal, [cond, Constant(0, cond.type)])
        return Branch(cond)

    def _lift_branch_condition(self, op) -> Condition:
        cond_vn = op.getInput(1)
        defn = cond_vn.getDef() if cond_vn is not None else None
        if defn is not None and defn.getOpcode() in self._compare_opcodes:
            return self._build_condition(defn)
        return Condition(OperationType.not_equal, [self._lifter.lift_varnode(cond_vn), Constant(0, Integer_int32())])

    def _build_condition(self, op) -> Condition:
        from ghidra.program.model.pcode import PcodeOp

        optype = self._compare_opcode_to_optype(op.getOpcode())
        return Condition(optype, [self._lifter.lift_varnode(op.getInput(0)), self._lifter.lift_varnode(op.getInput(1))])

    def _compare_opcode_to_optype(self, opcode) -> OperationType:
        from ghidra.program.model.pcode import PcodeOp

        mapping = {
            PcodeOp.INT_EQUAL: OperationType.equal,
            PcodeOp.INT_NOTEQUAL: OperationType.not_equal,
            PcodeOp.INT_LESS: OperationType.less_us,
            PcodeOp.INT_SLESS: OperationType.less,
            PcodeOp.INT_LESSEQUAL: OperationType.less_or_equal_us,
            PcodeOp.INT_SLESSEQUAL: OperationType.less_or_equal,
            PcodeOp.FLOAT_EQUAL: OperationType.equal,
            PcodeOp.FLOAT_NOTEQUAL: OperationType.not_equal,
            PcodeOp.FLOAT_LESS: OperationType.less,
            PcodeOp.FLOAT_LESSEQUAL: OperationType.less_or_equal,
        }
        return mapping.get(opcode, OperationType.equal)

    def lift_branchind(self, op, **kwargs) -> IndirectBranch:
        return IndirectBranch(self._in(op, 0))

    def lift_return(self, op, **kwargs) -> Return:
        inputs = list(op.getInputs())
        # Ghidra reserves RETURN input(0) for a const-0 placeholder (the return target);
        # the actual return values are the remaining inputs.
        if len(inputs) >= 1:
            inputs = inputs[1:]
        values = [self._lifter.lift_varnode(v) for v in inputs]
        return Return(values) if values else Return([])

    # -- memory ------------------------------------------------------------
    def lift_copy(self, op, **kwargs):
        out = self._out(op)
        if out is not None and out.isAddress():
            # A COPY of a global (address output) is a no-op rename in memory SSA: the output
            # inherits the input's memory version (see precompute_memory_versions). Lifting it as
            # an assignment would define a second version of the global and make phi sources
            # interfere at merges; skip it -- insert-missing-definitions / phis define the versions.
            return None
        value = self._in(op, 0)
        if self._lifter._is_bool_varnode(out):  # `flag = 0` -> `flag = false`
            value = self._lifter.as_bool_constant(value)
        return Assignment(self._lifter.lift_varnode(out, destination=True), value)

    def lift_load(self, op, **kwargs) -> Assignment:
        ptr = self._in(op, 1)
        return Assignment(
            self._lifter.lift_varnode(self._out(op), destination=True),
            UnaryOperation(OperationType.dereference, [ptr], vartype=self._out_type(op)),
        )

    def lift_store(self, op, **kwargs) -> Assignment:
        addr = self._in(op, 1)
        value = self._in(op, 2)
        mem_version = self._lifter.memory_version_of(op)
        dest = UnaryOperation(OperationType.dereference, [addr], vartype=value.type, writes_memory=mem_version)
        return Assignment(dest, value)

    def lift_indirect(self, op, **kwargs):
        """INDIRECT models a (potential) aliasing version bump caused by a memory-writing op.

        For globals (address outputs) we skip it: the version bump (``global#M = global#prev``)
        is inserted by the ``insert-missing-definitions`` stage right after the causing call, as a
        Relation when the call may change the global. For register locals we emit the copy so the
        bumped version is explicitly defined.
        """
        out = self._out(op)
        if out is not None and out.isAddress():
            return None
        return Assignment(
            self._lifter.lift_varnode(out, destination=True),
            self._lifter.lift_varnode(op.getInput(0), address_of=False),
        )

    # -- calls -------------------------------------------------------------
    def lift_call(self, op, **kwargs) -> Assignment:
        target_addr = int(op.getInput(0).getOffset())
        function_symbol = self._lifter._function_symbol_at(self._lifter.program, target_addr)
        args = [self._lifter.lift_varnode(op.getInput(i)) for i in range(1, op.getNumInputs())]
        return self._build_call_assignment(op, function_symbol, args)

    def lift_callind(self, op, **kwargs) -> Assignment:
        function_symbol = self._lifter._function_symbol_for_pointer(op.getInput(0))
        args = [self._lifter.lift_varnode(op.getInput(i)) for i in range(1, op.getNumInputs())]
        if function_symbol is None:
            function_symbol = self._lifter.lift_varnode(op.getInput(0))
        return self._build_call_assignment(op, function_symbol, args)

    def _build_call_assignment(self, op, function_symbol, args) -> Assignment:
        outputs = []
        out = self._out(op)
        if out is not None:
            outputs = [self._lifter.lift_varnode(out, destination=True)]
        mem_version = self._lifter.memory_version_of(op)
        vartype = outputs[0].type if outputs else self._lifter.lift_type(None)
        meta = {"param_names": self._lifter._param_names_for_call(function_symbol), "is_tailcall": False}
        call = Call(function_symbol, args, vartype=vartype, writes_memory=mem_version, meta_data=meta)
        return Assignment(ListOperation(outputs), call)

    # -- phi ---------------------------------------------------------------
    def lift_phi(self, op, **kwargs):
        out = self._out(op)
        # A MULTIEQUAL whose result is a global (address) is Ghidra's memory phi. A block merge
        # produces one such MULTIEQUAL per global, but they all share a single memory version;
        # we emit one MemPhi (for the representative) and skip the rest. The pipeline's mem-phi
        # converter then expands that MemPhi into one Phi per aliased global.
        if out is not None and out.isAddress():
            info = self._lifter._memphi_by_seq.get(self._lifter._seq(op))
            if info is None:
                return None  # redundant MULTIEQUAL of the same merge
            from decompiler.structures.pseudo import MemPhi
            from decompiler.structures.pseudo.expressions import Variable

            dest_mem = info[0]
            # Derive the source memory versions from the MULTIEQUAL's own input varnodes. Each
            # input is the global's value at the end of one predecessor, and its _addr_version is
            # the memory version in scope there (finalized once precompute_memory_versions has
            # processed the whole function). Computing them this way -- instead of from the
            # block_exit_mem snapshot taken during the single RPO pass -- is what makes loop
            # back-edges correct: the back-edge predecessor is processed *after* the header in
            # RPO, so the snapshot still held the entry version (0) for it, which produced
            # ``phi(mem#forward, mem#0)`` and crashed phi-function-fixer / out-of-ssa.
            src_mems = [self._lifter._addr_version.get(int(vn.getUniqueId()), 0) for vn in op.getInputs()]
            return MemPhi(Variable("mem", ssa_label=dest_mem), [Variable("mem", ssa_label=m) for m in src_mems])
        dest = self._lifter.lift_varnode(out, destination=True)
        sources = [self._lifter.lift_varnode(v) for v in op.getInputs()]
        return Phi(dest, sources)

    # -- arithmetic / casts ------------------------------------------------
    def _inputs_bool_aware(self, op):
        """Lift an op's inputs, retyping a 0/1 constant as bool when a sibling operand is bool.

        Covers ``flag == 0`` (INT_EQUAL/INT_NOTEQUAL) and ``flag && cond`` (BOOL_AND/BOOL_OR), where
        Ghidra leaves the literal typed as an integer -> it would otherwise render 0/1 not false/true.
        No-op for purely arithmetic ops (their operands are never bool-typed).
        """
        inputs = self._inputs(op)
        if any(self._lifter._is_bool_varnode(op.getInput(i)) for i in range(op.getNumInputs())):
            return [self._lifter.as_bool_constant(x) for x in inputs]
        return inputs

    def lift_binary_int(self, op_type: OperationType):
        def _lift(op, **kwargs) -> Assignment:
            return Assignment(
                self._lifter.lift_varnode(self._out(op), destination=True),
                BinaryOperation(op_type, self._inputs_bool_aware(op)),
            )

        return _lift

    def lift_unary_int(self, op_type: OperationType):
        def _lift(op, **kwargs) -> Assignment:
            return Assignment(
                self._lifter.lift_varnode(self._out(op), destination=True),
                UnaryOperation(op_type, [self._in(op, 0)], vartype=self._out_type(op)),
            )

        return _lift

    def lift_compare(self, op_type: OperationType):
        def _lift(op, **kwargs) -> Assignment:
            cond = Condition(op_type, self._inputs_bool_aware(op))
            return Assignment(self._lifter.lift_varnode(self._out(op), destination=True), cond)

        return _lift

    def lift_extend(self, op, **kwargs) -> Assignment:
        return Assignment(
            self._lifter.lift_varnode(self._out(op), destination=True),
            UnaryOperation(OperationType.cast, [self._in(op, 0)], vartype=self._out_type(op)),
        )

    def lift_cast(self, op, **kwargs) -> Assignment:
        return Assignment(
            self._lifter.lift_varnode(self._out(op), destination=True),
            UnaryOperation(OperationType.cast, [self._in(op, 0)], vartype=self._out_type(op)),
        )

    def lift_subpiece(self, op, **kwargs) -> Assignment:
        src = self._in(op, 0)
        offset = int(op.getInput(1).getOffset()) if op.getNumInputs() > 1 else 0
        out_type = self._out_type(op)
        if offset == 0:
            value = UnaryOperation(OperationType.cast, [src], vartype=out_type, contraction=True)
        else:
            value = UnaryOperation(
                OperationType.cast,
                [BinaryOperation(OperationType.right_shift_us, [src, Constant(offset * BYTE_SIZE)])],
                vartype=out_type,
            )
        return Assignment(self._lifter.lift_varnode(self._out(op), destination=True), value)

    def lift_ptradd(self, op, **kwargs) -> Assignment:
        base = self._in(op, 0)
        index_vn = op.getInput(1)
        size = int(op.getInput(2).getOffset()) if op.getNumInputs() > 2 else 1
        dst = self._lifter.lift_varnode(self._out(op), destination=True)
        # A CONSTANT index folds to a single offset: Ghidra emits `PTRADD(base, 1, 4)` for a fixed
        # field/element, which lifted to `base + 1U * 0x4` -- pure noise. Fold it (sign-interpreting
        # the index so negative offsets like `base + 0xffffffff * 0x2` become `base + -2`).
        if index_vn.isConstant():
            bits = (int(index_vn.getSize()) or 4) * BYTE_SIZE
            raw = int(index_vn.getOffset())
            signed = raw - (1 << bits) if raw >= (1 << (bits - 1)) else raw
            offset = signed * size
            base_vn = op.getInput(0)
            if base_vn.isConstant():
                # both base and index constant (e.g. PTRADD(0, 1, 4)) -> one folded address, not `0U + 0x4`
                return Assignment(dst, Constant(int(base_vn.getOffset()) + offset))
            return Assignment(dst, BinaryOperation(OperationType.plus, [base, Constant(offset)]))
        index = self._lifter.lift_varnode(index_vn)
        if size == 1:
            value = BinaryOperation(OperationType.plus, [base, index])
        else:
            value = BinaryOperation(OperationType.plus, [base, BinaryOperation(OperationType.multiply, [index, Constant(size)])])
        return Assignment(dst, value)

    def lift_ptrsub(self, op, **kwargs) -> Assignment:
        dst = self._lifter.lift_varnode(self._out(op), destination=True)
        base_vn = op.getInput(0)
        raw_offset = int(op.getInput(1).getOffset()) if op.getNumInputs() > 1 else 0
        # PTRSUB(stackpointer, offset) is Ghidra's "address of the stack local at <offset>".
        # Recover it as `&local_X` (referencing the named frame variable) instead of the raw
        # `stackpointer + offset` arithmetic that otherwise reads as `var_16 + 0xfffffe74`.
        if self._lifter._is_stack_pointer(base_vn):
            bits = (int(base_vn.getSize()) or 4) * BYTE_SIZE
            signed = raw_offset - (1 << bits) if raw_offset >= (1 << (bits - 1)) else raw_offset
            variable, delta = self._lifter.stack_variable(signed)
            address = UnaryOperation(
                OperationType.address, [variable], vartype=Pointer(variable.type, self._lifter._address_size_bits())
            )
            value = address if delta == 0 else BinaryOperation(OperationType.plus, [address, Constant(delta)])
            return Assignment(dst, value)
        # PTRSUB(const_base, offset) is an absolute address (a global). Fold the constant base into a
        # single address constant instead of the noisy `0U + 0xADDR` that dereferences everywhere.
        if base_vn.isConstant():
            return Assignment(dst, Constant(int(base_vn.getOffset()) + raw_offset))
        value = BinaryOperation(OperationType.plus, [self._in(op, 0), Constant(raw_offset)])
        return Assignment(dst, value)

    def lift_unknown_op(self, op, **kwargs):
        logging.debug("[GhidraOpcodeHandler] skipping unsupported p-code op %s", op.getSeqnum())
        return None

    def lift_int_carry(self, op, **kwargs) -> Assignment:
        """INT_CARRY(a, b) = unsigned carry-out of a+b = ``((a + b) u< a)``.

        Ghidra emits this (and INT_SCARRY/INT_SBORROW) for PIE position calculations and flag
        tracking; without a handler its output is left undefined, which crashes
        ``insert-missing-definitions`` when the value feeds a phi/branch.
        """
        a = self._in(op, 0)
        b = self._in(op, 1)
        value = BinaryOperation(OperationType.less_us, [BinaryOperation(OperationType.plus, [a, b]), a])
        return Assignment(self._lifter.lift_varnode(self._out(op), destination=True), value)

    def lift_float_nan(self, op, **kwargs) -> Assignment:
        """FLOAT_NAN(x) = ``x != x`` (NaN is the only floating-point value not equal to itself).

        Ghidra emits this for ``isnan`` checks; the result feeds a branch condition, so it must
        lower to a real boolean expression (z3-based stages can't reason about a synthetic call).
        """
        x = self._in(op, 0)
        value = BinaryOperation(OperationType.not_equal, [x, x])
        return Assignment(self._lifter.lift_varnode(self._out(op), destination=True), value)

    def lift_unknown_flag(self, op, **kwargs) -> Assignment:
        """Lift rare signed flag ops (INT_SCARRY, INT_SBORROW) as an opaque expression.

        Their precise lowering (signed-overflow predicates) has no clean pseudo IR form and they
        are very rare; defining the output as an unknown expression keeps the function decompilable
        without crashing ``insert-missing-definitions``.
        """
        out = self._out(op)
        if out is None:
            return None
        args = ", ".join(str(self._lifter.lift_varnode(op.getInput(i))) for i in range(op.getNumInputs()))
        return Assignment(
            self._lifter.lift_varnode(out, destination=True),
            UnknownExpression(f"{op.getMnemonic()}({args})"),
        )

    def lift_generic(self, op, **kwargs):
        """Fallback for p-code opcodes without a dedicated handler (CALLOTHER, INSERT, ...).

        Defines the (possibly used) output as an opaque ``UnknownExpression`` so the variable has a
        definition (preventing the ``non-aliased variable has no definition`` crash) while staying
        opaque to the optimizer. We use UnknownExpression rather than a synthetic Call: z3's logic
        converter raises ValueError on it (caught and skipped by dead-path-elimination), whereas a
        Call silently yields a non-boolean and crashes z3. CALLOTHER's input(0) is the user-op index
        constant (folded into the name); ops with no output (side-effect-only) are dropped.
        """
        out = self._out(op)
        if out is None:
            return None
        mnemonic = op.getMnemonic()
        # input(0) is a real operand for ordinary ops (POPCOUNT, LZCOUNT, INSERT, EXTRACT, ...); only
        # CALLOTHER's input(0) is the user-op index constant (folded into the name, not an operand).
        # Defaulting start=1 here previously DROPPED the sole operand of unary ops -> `POPCOUNT()`
        # with no argument, losing the data-flow dependency on its input.
        start = 0
        try:
            from ghidra.program.model.pcode import PcodeOp

            if op.getOpcode() == PcodeOp.CALLOTHER:
                start = 1
                mnemonic = f"callother_{int(op.getInput(0).getOffset())}"
        except Exception:  # noqa: BLE001
            start = 0
        args = ", ".join(str(self._lifter.lift_varnode(op.getInput(i))) for i in range(start, op.getNumInputs()))
        return Assignment(
            self._lifter.lift_varnode(out, destination=True),
            UnknownExpression(f"{mnemonic}({args})"),
        )

    def lift_piece(self, op, **kwargs) -> Assignment:
        """PIECE concatenates two values into a wider one (high:low) -> a RegisterPair value."""
        from decompiler.structures.pseudo import RegisterPair

        high = self._in(op, 0)
        low = self._in(op, 1)
        return Assignment(
            self._lifter.lift_varnode(self._out(op), destination=True),
            RegisterPair(high, low, vartype=self._out_type(op)),
        )


def _is_code_address(expr) -> bool:
    return False


def Integer_int32():
    return Integer.int32_t()
