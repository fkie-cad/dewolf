"""Ghidra lifter converting decompiler High-P-code to dewolf pseudo IR."""

import logging
from typing import Dict, List, Optional, Set, Tuple

from decompiler.frontend.lifter import ObserverLifter
from decompiler.structures.pseudo import FunctionSymbol, ImportedFunctionSymbol, Integer, UnknownExpression, UnknownType
from decompiler.structures.pseudo.complextypes import ComplexTypeMap, UniqueNameProvider

BYTE_SIZE = 8


class GhidraLifter(ObserverLifter):
    """Lift ghidra decompiler p-code (SSA) onto pseudo expressions / instructions."""

    def __init__(self, program, no_bit_masks: bool = True):
        self.no_bit_masks = no_bit_masks
        self.program = program
        self.complex_types: ComplexTypeMap = ComplexTypeMap()
        self.unique_name_provider: UniqueNameProvider = UniqueNameProvider()
        self.OPCODE_HANDLERS: Dict[int, callable] = {}
        self._compare_opcodes = set()
        # SSA versioning state (per function).
        self._hv_next: Dict[Tuple, int] = {}
        self._vn_version: Dict[int, int] = {}
        self._name_cache: Dict[int, Optional[str]] = {}
        self._mem_version = 0
        # Memory-SSA state (per function); aliased globals are versioned by memory version.
        self._addr_version: Dict[int, int] = {}  # address varnode uid -> memory version
        self._op_mem: Dict[int, int] = {}  # op seqnum-time -> memory version (writes_memory)
        # Addresses of globals that are genuinely written in this function (a direct store to a
        # known address, or a non-global value copied into the address). A global NOT in this set is
        # read-only: its value is constant across the function, so it must NOT be routed through the
        # aliased memory-version machinery (which would version it across every call and fabricate a
        # carry-forward Relation per memory op -- an O(globals x memory-ops) blow-up that interferes
        # in out-of-ssa). Populated by precompute_written_globals.
        self._written_globals: Set[int] = set()
        self._memphi_by_seq: Dict[int, Tuple[int, List[int]]] = {}  # rep MULTIEQUAL seq -> (dest, [src]) mem versions
        self._fallback_lift = None  # set by OpcodeHandler.register(); generic p-code fallback
        # Canonical access size per global address: a global Ghidra accesses at multiple sizes
        # (e.g. addr4:0x47125e and addr1:0x47125e) must lift to ONE typed GlobalVariable per
        # (address, memory version); otherwise the 4-byte and 1-byte variants become distinct
        # Variables (Variable equality includes the type) that share (name, ssa_label) and trip
        # "duplicate entries in copy pool". We use the largest access size as the canonical type.
        self._global_size: Dict[int, int] = {}
        # Stack-variable recovery (per function): Ghidra models `&local_X` as
        # PTRSUB(stackpointer, offset); we resolve these to named stack variables instead of
        # emitting raw `stackpointer + offset` arithmetic. Populated by precompute_stack_variables.
        self._stack_pointer_addr = None  # ghidra Address of the stack-pointer register, or None
        self._stack_frame = None  # the function's StackFrame, for offset -> variable lookup
        self._stack_symbols = []  # decompiler-inferred stack layout: (start, length, name, dtype)
        # stack frame offset -> set of HighVariable keys whose value varnodes live there. An offset
        # backed by a single HighVariable is a genuine single local we can name by offset (merging
        # its value accesses with its ``&`` address-of); an offset backed by several is slot reuse we
        # must leave split. Populated by precompute_stack_slot_identity.
        self._stack_offset_reps: Dict[int, set] = {}
        from .handlers import HANDLERS

        for handler in HANDLERS:
            handler(self).register()

    @property
    def is_omitting_masks(self) -> bool:
        return self.no_bit_masks

    # -- dispatch ----------------------------------------------------------
    def lift(self, expression, **kwargs):
        """Dispatch on the ghidra object kind: PcodeOp -> Instruction, Varnode -> Expression, DataType -> Type."""
        if expression is None:
            return None
        kind = expression.getClass().getName()
        if "PcodeOp" in kind:
            handler = self.OPCODE_HANDLERS.get(expression.getOpcode())
            if handler is None:
                if self._fallback_lift is not None:
                    logging.debug("[GhidraLifter] no dedicated handler for p-code opcode %s; using fallback", expression.getOpcode())
                    return self._fallback_lift(expression, **kwargs)
                logging.debug("[GhidraLifter] no handler for p-code opcode %s", expression.getOpcode())
                self._maybe_log_skipped_def(expression)
                return None
            try:
                result = handler(expression, **kwargs)
            except Exception as exc:  # noqa: BLE001
                logging.warning("[GhidraLifter] failed to lift p-code %s: %s", expression.getSeqnum(), exc)
                self._maybe_log_skipped_def(expression)
                return None
            if result is None:
                self._maybe_log_skipped_def(expression)
            return result
        if "Varnode" in kind:
            return self.lift_varnode(expression, **kwargs)
        # Treat anything else as a type (DataType).
        return self.lift_type(expression, **kwargs)

    def _maybe_log_skipped_def(self, op) -> None:
        """Log (debug) when a defining op is skipped, since its result may be used elsewhere.

        The following skips are intentional (memory-SSA no-ops handled by the pipeline), so we only
        surface genuinely unexpected skips at warning level:
          * address-output INDIRECT  -> the version bump is inserted by insert-missing-definitions
          * address-output COPY       -> a no-op rename (output inherits the input's memory version)
          * address-output MULTIEQUAL -> a redundant member of a memory merge; the representative
            MULTIEQUAL emits the MemPhi and MemPhiConverter expands it to per-global Phis
        """
        try:
            out = op.getOutput()
            if out is None:
                return
            from ghidra.program.model.pcode import PcodeOp

            opc = op.getOpcode()
            intentional = (
                (opc == PcodeOp.INDIRECT and out.isAddress())
                or (opc == PcodeOp.COPY and out.isAddress())
                or (opc == PcodeOp.MULTIEQUAL and out.isAddress())
            )
            desc = out.getDescendants() if hasattr(out, "getDescendants") else None
            used = desc is None or desc.hasNext()
            if not used:
                return
            if intentional:
                logging.debug(
                    "[GhidraLifter] skipped defining op %s (opcode=%s) output=%s", op.getSeqnum(), op.getOpcode(), out.getUniqueId()
                )
            else:
                logging.warning(
                    "[GhidraLifter] skipped defining op %s (opcode=%s) output=%s", op.getSeqnum(), op.getOpcode(), out.getUniqueId()
                )
        except Exception:  # noqa: BLE001
            pass

    def lift_unknown(self, expression, **kwargs):
        if expression is None:
            return UnknownType()
        logging.warning("[GhidraLifter] can not lift %r (%s)", expression, type(expression))
        return UnknownExpression(str(expression))

    # -- varnode helpers ---------------------------------------------------
    def precompute_ssa_labels(self, high_function) -> None:
        """Assign SSA labels so that live-in varnodes get label 0 and definitions get 1, 2, ...

        dewolf's ``insert-missing-definitions`` assumes the smallest SSA label of each variable
        is the live-in / entry value (defined from the start) and only inserts definitions for
        strictly larger labels. Lifting lazily in block-iteration order can assign a real
        definition label 0 and a later live-in use label 1, which breaks that invariant
        ("non-aliased variable has no definition"). We therefore pre-scan all p-code:

          * Pass A reserves label 0 for every input varnode with no defining op
            (function parameters / uninitialized live-in values).
          * Pass B assigns incrementing labels to op outputs (definitions) in execution order.

        Uses share their Varnode identity (and thus uid) with the output of their defining
        op, so caching by uid makes uses resolve to their definition's label automatically.
        """
        blocks = list(high_function.getBasicBlocks())
        # Pass A: reserve label 0 for live-in varnodes (no defining op).
        for b in blocks:
            for op in b.getIterator():
                for i in range(op.getNumInputs()):
                    vn = op.getInput(i)
                    if vn is None or not self._is_variable_varnode(vn):
                        continue
                    if vn.getDef() is not None:
                        continue
                    key = self._var_key(vn)
                    if key not in self._hv_next:
                        self._hv_next[key] = 1  # reserve label 0; next def starts at 1
                    self._vn_version[int(vn.getUniqueId())] = 0
        # Pass B: assign labels to definitions (op outputs) in execution order.
        for b in blocks:
            for op in b.getIterator():
                out = op.getOutput()
                if out is None or not self._is_variable_varnode(out):
                    continue
                key = self._var_key(out)
                nxt = self._hv_next.get(key, 0)
                self._hv_next[key] = nxt + 1
                self._vn_version[int(out.getUniqueId())] = nxt

    def precompute_stack_variables(self, high_function) -> None:
        """Record the stack-pointer register and the function's stack frame.

        Ghidra resolves scalar stack accesses to ``stack:`` varnodes (lifted normally), but models
        *address-taken* stack locals (buffers passed to ``memset``/``strcpy``, ``&local``) as
        ``PTRSUB(stackpointer, offset)``. Without recovery those lift to raw
        ``stackpointer + offset`` arithmetic (``var_16 + 0xfffffe74``); with the frame in hand we
        turn them into ``&local_X`` referencing the named stack variable at that offset.
        """
        try:
            sp = self.program.getCompilerSpec().getStackPointer()
            self._stack_pointer_addr = sp.getAddress() if sp is not None else None
        except Exception:  # noqa: BLE001
            self._stack_pointer_addr = None
        try:
            self._stack_frame = high_function.getFunction().getStackFrame()
        except Exception:  # noqa: BLE001
            self._stack_frame = None
        # The decompiler-inferred stack layout (getLocalSymbolMap), which carries the *analysed*
        # types the listing StackFrame lacks -- most importantly array types: a 256-byte buffer is
        # ``undefined`` len 1 in the listing frame but ``undefined1[256]`` here. Recording it lets
        # ``&local`` recover ``unsigned char var[256]`` instead of a lone ``unsigned char var``.
        # Stored as (start_offset, length, name, ghidra_datatype), sorted by start.
        self._stack_symbols = []
        try:
            it = high_function.getLocalSymbolMap().getSymbols()
            while it.hasNext():
                sym = it.next()
                storage = sym.getStorage()
                if storage is None or not storage.isStackStorage():
                    continue
                dtype = sym.getDataType()
                length = dtype.getLength() if dtype is not None else 1
                self._stack_symbols.append((int(storage.getStackOffset()), int(length or 1), sym.getName(), dtype))
        except Exception:  # noqa: BLE001
            self._stack_symbols = []
        self._stack_symbols.sort(key=lambda entry: entry[0])

    def precompute_stack_slot_identity(self, high_function) -> None:
        """Record, per stack frame offset, the set of HighVariables whose value varnodes live there.

        An address-taken local (``&week`` escaping to ``scanf``) has all its value accesses on one
        HighVariable at its slot; naming those accesses by the slot offset then merges them with the
        ``&`` address-of into a single variable. When Ghidra instead keeps several HighVariables at
        one offset (stack-slot reuse or an SSA split), merging by offset would collapse their
        independent SSA versions, so ``_name_for`` leaves those offsets split (see there).
        """
        for b in high_function.getBasicBlocks():
            for op in b.getIterator():
                vns = [op.getOutput()] + [op.getInput(i) for i in range(op.getNumInputs())]
                for vn in vns:
                    if vn is None:
                        continue
                    offset = self._stack_offset_of(vn)
                    if offset is None:
                        continue
                    self._stack_offset_reps.setdefault(offset, set()).add(self._var_key(vn))

    def _stack_offset_has_single_hv(self, offset: int) -> bool:
        """True if exactly one HighVariable's value varnodes occupy the given stack slot."""
        return len(self._stack_offset_reps.get(offset, ())) == 1

    def _high_stack_symbol(self, offset: int):
        """The decompiler-inferred stack symbol containing ``offset``: (name, dtype, start) or None.

        Preferred over the listing StackFrame because it carries analysed array/struct types (a
        stack buffer is ``undefined1[256]`` here but merely ``undefined`` in the listing frame).
        """
        for start, length, name, dtype in self._stack_symbols:
            if start <= offset < start + length:
                return name, dtype, start
        return None

    def _is_stack_pointer(self, vn) -> bool:
        """True if ``vn`` is (a version of) the stack-pointer register."""
        if vn is None or self._stack_pointer_addr is None:
            return False
        try:
            return bool(vn.isRegister()) and vn.getAddress().equals(self._stack_pointer_addr)
        except Exception:  # noqa: BLE001
            return False

    def stack_variable(self, offset: int):
        """The named stack variable at frame ``offset`` (signed), plus any leftover byte delta.

        Returns ``(Variable, delta)`` where ``delta`` is 0 when ``offset`` is the variable's start
        and non-zero when it points inside a larger variable (array/struct indexing) — the caller
        renders ``&var`` or ``&var + delta`` respectively. Falls back to a deterministic
        ``stack_<offset>`` name when Ghidra has no frame variable there.
        """
        from decompiler.structures.pseudo.expressions import Variable

        name = None
        vartype = None
        base_offset = offset
        # Prefer the decompiler-inferred symbol (has array/struct types); fall back to the listing frame.
        if (symbol := self._high_stack_symbol(offset)) is not None:
            try:
                name = self._purge(symbol[0])
                vartype = self.lift_type(symbol[1])
                base_offset = symbol[2]
            except Exception:  # noqa: BLE001
                name = None
        if name is None and self._stack_frame is not None:
            try:
                var = self._stack_frame.getVariableContaining(offset)
            except Exception:  # noqa: BLE001
                var = None
            if var is not None:
                try:
                    name = self._purge(var.getName())
                    vartype = self.lift_type(var.getDataType())
                    base_offset = int(var.getStackOffset())
                except Exception:  # noqa: BLE001
                    name = None
        if name is None:
            # No Ghidra frame variable here; use a stable name in a namespace the out-of-SSA
            # renamer never emits (it produces ``var_N``), so nothing collides pre-rename.
            base_offset = offset
            name = self._stack_slot_name(offset)
        if vartype is None:
            vartype = Integer(BYTE_SIZE, signed=False)
        # A stack slot whose scalar accesses Ghidra kept as ``stack:`` varnodes is lifted there as a
        # non-aliased SSA variable; matching that here (is_aliased=False, live-in label 0) lets
        # out-of-SSA merge this address-of reference with those accesses into one variable. Marking
        # it aliased instead makes insert-missing-definitions insert a conflicting definition
        # ("defined twice") for dual-accessed slots.
        return Variable(name, vartype, ssa_label=0, is_aliased=False), offset - base_offset

    def _stack_offset_of(self, vn) -> Optional[int]:
        """The stack-frame offset a varnode lives at, if it is a stack local; else None.

        Ghidra keeps an address-taken local (e.g. ``week``, whose ``&week`` escapes to ``scanf``) in
        its stack slot and models every access as a varnode in the ``stack`` address space. Reading
        that offset lets us name such value accesses identically to the ``&week`` address-of, so
        out-of-SSA merges them into one variable instead of splitting them.
        """
        try:
            addr = vn.getAddress()
            if addr is not None and addr.getAddressSpace().getName() == "stack":
                return int(addr.getOffset())
        except Exception:  # noqa: BLE001
            return None
        return None

    @staticmethod
    def _stack_slot_name(offset: int) -> str:
        """Deterministic fallback name for a stack slot Ghidra gives no frame variable."""
        return f"stack_{format(offset & 0xFFFFFFFF, 'x')}" if offset < 0 else f"stack_{offset:x}"

    def _stack_variable_name(self, offset: int) -> str:
        """Canonical name of the stack local at ``offset`` (frame-variable name, else ``stack_<off>``).

        Shared by ``_name_for`` (value accesses of an address-taken local) and ``stack_variable``
        (its ``&`` address-of) so both lift to the same name; without this an address-taken local
        splits into ``&var_0`` and a distinct, undefined ``var_1`` (see ``_stack_offset_of``).
        """
        if (symbol := self._high_stack_symbol(offset)) is not None:
            try:
                return self._purge(symbol[0])
            except Exception:  # noqa: BLE001
                pass
        if self._stack_frame is not None:
            try:
                var = self._stack_frame.getVariableContaining(offset)
            except Exception:  # noqa: BLE001
                var = None
            if var is not None:
                try:
                    return self._purge(var.getName())
                except Exception:  # noqa: BLE001
                    pass
        return self._stack_slot_name(offset)

    @staticmethod
    def _is_variable_varnode(vn) -> bool:
        """A varnode that lifts to a (local) Variable, i.e. neither a constant nor an address."""
        try:
            if vn.isConstant() or vn.isAddress():
                return False
        except Exception:  # noqa: BLE001
            return False
        return True

    @staticmethod
    def _seq(op) -> int:
        """Stable, hashable id for a p-code op: its seqnum time (unique within a function)."""
        try:
            return int(op.getSeqnum().getTime())
        except Exception:  # noqa: BLE001
            return int(op.getSeqnum().getTarget().getOffset())

    def precompute_global_sizes(self, high_function) -> None:
        """Record the largest access size per global address.

        Ghidra may access one global at several sizes (e.g. a 4-byte ``int`` load and a 1-byte
        ``SUBPIECE`` of it), emitting separate address varnodes (``addr4:…`` and ``addr1:…``) at
        the same offset. Lifting each at its own size yields distinct typed ``GlobalVariable``\ s
        that share ``(name, ssa_label)`` and collide in the copy pool. Using the maximum access
        size as the canonical type makes all accesses of one global lift to the same typed
        variable, so they de-duplicate (Variable equality includes the type).
        """
        from ghidra.program.model.pcode import PcodeOp

        for b in high_function.getBasicBlocks():
            for op in b.getIterator():
                for i in range(op.getNumInputs()):
                    vn = op.getInput(i)
                    if vn is None or not vn.isAddress():
                        continue
                    addr = int(vn.getOffset())
                    sz = int(vn.getSize())
                    if sz > self._global_size.get(addr, 0):
                        self._global_size[addr] = sz
                out = op.getOutput()
                if out is not None and out.isAddress():
                    addr = int(out.getOffset())
                    sz = int(out.getSize())
                    if sz > self._global_size.get(addr, 0):
                        self._global_size[addr] = sz

    def precompute_written_globals(self, high_function) -> None:
        """Record which global addresses are genuinely written in this function.

        Ghidra models a global (a ram-space varnode) as memory that any call may modify, emitting an
        INDIRECT for it after every call. Treating every such global as aliased makes the memory-SSA
        machinery version it across every call and, via insert-missing-definitions, fabricate a
        carry-forward Relation per memory op -- the O(globals x memory-ops) blow-up that overwhelms
        out-of-ssa. But the overwhelming majority of these globals are never actually written in the
        function (Ghidra fragments a read-only struct/table into many ram varnodes and versions them
        all conservatively). Such read-only globals hold a constant value and need no versioning at
        all; only genuinely-written globals need the aliased machinery.

        A global at address A is written iff some op *defines a non-derived value* at A:
          * a STORE to a statically-known constant address A, or
          * any op whose output is the ram varnode at A and whose first input is NOT itself a global
            (a register/constant/arithmetic value written into A).
        A def whose source is another global (a COPY rename, or a SUBPIECE/PIECE fragmenting a wide
        global into a narrower view) is value-preserving, not a write, so it does not mark A written.
        Conservative may-writes (INDIRECT, and stores through a computed pointer) are deliberately
        ignored -- matching Binary Ninja and Ghidra's own decompiler, which do not re-version a
        global just because a call *might* touch it.
        """
        from ghidra.program.model.pcode import PcodeOp as P

        for b in high_function.getBasicBlocks():
            for op in b.getIterator():
                opc = op.getOpcode()
                out = op.getOutput()
                if out is not None and out.isAddress() and opc not in (P.INDIRECT, P.MULTIEQUAL):
                    in0 = op.getInput(0) if op.getNumInputs() else None
                    if in0 is None or not in0.isAddress():
                        self._written_globals.add(int(out.getOffset()))
                if opc == P.STORE and op.getNumInputs() > 1:
                    target = op.getInput(1)
                    if target is not None and target.isConstant():
                        self._written_globals.add(int(target.getOffset()))

    def _is_written_global(self, vn) -> bool:
        """True if the varnode is a ram global that this function genuinely writes (see above)."""
        return vn is not None and vn.isAddress() and int(vn.getOffset()) in self._written_globals

    def defines_readonly_global(self, op) -> bool:
        """True if the op's output is a read-only global (a constant location we do not version).

        Every op that outputs a read-only global is value-preserving plumbing -- an SSA rename
        (COPY), a conservative may-write (INDIRECT), a merge (MULTIEQUAL), or a fragmenting view
        (SUBPIECE / PIECE); a read-only global has no genuine-write def by definition. We drop such
        ops when parsing: the global is read directly from its (constant) memory location wherever it
        is used, so no definition is needed and none of the aliased carry-forward Relations arise.
        """
        out = op.getOutput()
        return out is not None and out.isAddress() and int(out.getOffset()) not in self._written_globals

    def precompute_memory_versions(self, high_function) -> None:
        """Compute a unified memory-version SSA over the function (Binary Ninja's model).

        Memory versions form a single counter shared by all aliased globals:
          * version 0 is the function entry;
          * every CALL / CALLIND / STORE starts a new version (``writes_memory``);
          * every global assignment (any op with an address output that is not an INDIRECT) starts
            a new version;
          * at a block with address-MULTIEQUALs (a memory merge) one new version M_merge is
            allocated and shared by all those MULTIEQUALs -> a single ``MemPhi`` per merge, which
            the pipeline expands into one Phi per aliased global.

        Each global varnode is labelled with the memory version in scope at its defining op
        (INDIRECT outputs inherit the causing call's version). Reads share their Varnode identity
        with the defining op, so caching by uid makes uses resolve automatically.
        """
        from ghidra.program.model.pcode import PcodeOp as P

        blocks = list(high_function.getBasicBlocks())
        if not blocks:
            return
        by_index = {int(b.getIndex()): b for b in blocks}
        entry_block = blocks[0]
        try:
            entry_addr = int(high_function.getFunction().getEntryPoint().getOffset())
            for b in blocks:
                if int(b.getStart().getOffset()) == entry_addr:
                    entry_block = b
                    break
        except Exception:  # noqa: BLE001
            pass

        order: list = []
        visited: set = set()

        def _rpo(b):
            bid = int(b.getIndex())
            if bid in visited:
                return
            visited.add(bid)
            for i in range(b.getOutSize()):
                _rpo(b.getOut(i))
            order.append(b)

        _rpo(entry_block)
        order.reverse()
        for b in blocks:
            if int(b.getIndex()) not in visited:
                order.append(b)

        block_exit_mem: Dict[int, int] = {}
        # block id -> (M_merge, [predecessor exit memory versions])
        self._memphi_info: Dict[int, Tuple[int, List[int]]] = {}
        memphi_rep_seq: Dict[int, int] = {}  # block id -> rep MULTIEQUAL seq

        for b in order:
            bid = int(b.getIndex())
            ops = list(b.getIterator())
            # Only genuinely-written globals participate in the memory-version SSA; read-only globals
            # are lifted as plain single-version globals and must not create memory phis (see
            # precompute_written_globals).
            merge_ops = [op for op in ops if op.getOpcode() == P.MULTIEQUAL and self._is_written_global(op.getOutput())]
            if b is entry_block:
                entry = 0
            else:
                preds = [int(b.getIn(i).getIndex()) for i in range(b.getInSize())]
                # Use a predecessor already processed in RPO (block_exit_mem set). preds[0] can be a
                # loop back-edge that is processed *after* this header, so block_exit_mem.get(preds[0],
                # 0) would wrongly default to 0; a forward predecessor is already filled in.
                entry = next((block_exit_mem[p] for p in preds if p in block_exit_mem), 0)
            if merge_ops:
                m_merge = self._next_memory_version()
                memphi_rep_seq[bid] = self._seq(merge_ops[0])
                pred_exits = [block_exit_mem.get(int(b.getIn(i).getIndex()), 0) for i in range(b.getInSize())]
                self._memphi_info[bid] = (m_merge, pred_exits)
                for op in merge_ops:
                    self._addr_version[int(op.getOutput().getUniqueId())] = m_merge
                cur = m_merge
            else:
                cur = entry
            for op in ops:
                opc = op.getOpcode()
                out = op.getOutput()
                if opc == P.INDIRECT:
                    # The output inherits the memory version of its *causing* op (the CALL/STORE/
                    # CALLOTHER that may have modified the global). Ghidra's block iterator yields
                    # the INDIRECT before its causing op, so we cannot rely on `cur` here -- we look
                    # up the causing op by the seqnum encoded in input(1) and (idempotently) allocate
                    # its memory version. The causing op itself, when reached, reuses that version.
                    if self._is_written_global(out):
                        cseq = int(op.getInput(1).getOffset())
                        m = self.memory_version_of_seq(cseq)
                        self._addr_version[int(out.getUniqueId())] = m
                        cur = m
                    continue
                has_addr_out = self._is_written_global(out)
                if opc in (P.CALL, P.CALLIND, P.STORE):
                    cur = self.memory_version_of(op)
                elif has_addr_out and opc != P.MULTIEQUAL:
                    if opc == P.COPY:
                        # COPY of a global is a no-op rename in Ghidra's memory SSA: the output
                        # holds the same value as the input, so it inherits the input's memory
                        # version. It is NOT a memory write -- it must not start a new unified
                        # memory version (which would spuriously bump every other global) and it
                        # must not be lifted as an assignment (that would define a second version
                        # of the global and make phi-sources interfere at merges). We skip it when
                        # lifting and let insert-missing-definitions / phis define the versions.
                        self._addr_version[int(out.getUniqueId())] = self._addr_version.get(int(op.getInput(0).getUniqueId()), cur)
                    else:
                        # PTRSUB / other address derivations -> a new memory version.
                        m = self._next_memory_version()
                        self._addr_version[int(out.getUniqueId())] = m
                        cur = m
            block_exit_mem[bid] = cur

        # Map each rep MULTIEQUAL seq -> (dest memory version, source memory versions) for lifting.
        self._memphi_by_seq: Dict[int, Tuple[int, List[int]]] = {seq: self._memphi_info[bid] for bid, seq in memphi_rep_seq.items()}

    def memory_version_of_seq(self, seq: int) -> int:
        """Return the memory version associated with the op whose seqnum-time is ``seq``.

        Allocates one if unseen. Used by address INDIRECTs to inherit their causing op's version
        (the causing op is identified by the seqnum encoded in the INDIRECT's input(1) constant).
        """
        if seq not in self._op_mem:
            self._op_mem[seq] = self._next_memory_version()
        return self._op_mem[seq]

    def memory_version_of(self, op) -> int:
        """Return the memory version written by the given memory-changing op, allocating one if unseen."""
        return self.memory_version_of_seq(self._seq(op))

    def _high(self, vn):
        try:
            return vn.getHigh()
        except Exception:  # noqa: BLE001
            return None

    def _var_key(self, vn) -> Tuple:
        hv = self._high(vn)
        if hv is not None:
            try:
                rep = hv.getRepresent()
                if rep is not None:
                    return ("hv", int(rep.getUniqueId()))
            except Exception:  # noqa: BLE001
                pass
            try:
                return ("hvn", hv.getName())
            except Exception:  # noqa: BLE001
                pass
        return ("vn", int(vn.getUniqueId()))

    def _version(self, vn) -> int:
        uid = int(vn.getUniqueId())
        if uid in self._vn_version:
            return self._vn_version[uid]
        key = self._var_key(vn)
        nxt = self._hv_next.get(key, 0)
        self._hv_next[key] = nxt + 1
        self._vn_version[uid] = nxt
        return nxt

    def _name_for(self, vn) -> str:
        uid = int(vn.getUniqueId())
        if uid in self._name_cache:
            return self._name_cache[uid] or f"u{uid}"
        name: Optional[str] = None
        # A stack local that occupies its slot *alone* (one HighVariable at that offset): name it by
        # the frame offset, matching ``stack_variable`` (its ``&`` form), so an address-taken local's
        # value accesses and its address-of merge into one variable (``scanf(&var_0); switch(var_0)``
        # rather than ``&var_0`` split from an undefined ``var_1``). We deliberately do NOT do this
        # when Ghidra keeps several distinct HighVariables at one offset (slot reuse / SSA split):
        # forcing them to share a name would collapse their independent versions and define, e.g.,
        # ``local_20#1`` twice ("Program is not in SSA-Form").
        stack_offset = self._stack_offset_of(vn)
        if stack_offset is not None and self._stack_offset_has_single_hv(stack_offset):
            name = self._stack_variable_name(stack_offset)
            self._name_cache[uid] = name
            return name
        hv = self._high(vn)
        if hv is not None:
            try:
                candidate = hv.getName()
                # "u..." and "UNNAMED" are Ghidra's unnamed markers. Using "UNNAMED" for every
                # unnamed HighVariable makes them all collide on one name, producing "duplicate
                # entries in copy pool for UNNAMED"; fall back to a per-HighVariable unique name.
                # NOTE: do NOT map by hv.getSymbol() here — one symbol can back several distinct
                # HighVariables (SSA splits), and the SSA version counter is keyed per HighVariable,
                # so sharing a symbol name across them yields duplicate (name, version) pairs
                # ("Variable local_1a#2 defined twice"). Recovery of the renameable symbol name is
                # done later, in the backend's originalNames map, not in the lifted SSA identity.
                if candidate and not candidate.startswith("u") and candidate != "UNNAMED":
                    name = self._purge(candidate)
            except Exception:  # noqa: BLE001
                pass
        if name is None and vn.isRegister():
            try:
                reg = vn.getRegister()
                if reg is not None:
                    name = self._purge(reg.getName())
            except Exception:  # noqa: BLE001
                pass
        if name is None:
            # Use the HighVariable's representative varnode id so the name is shared across all
            # varnodes of one HighVariable (not split per-varnode) yet distinct between unnamed
            # HighVariables (so they don't collide on "UNNAMED").
            rep_uid = uid
            if hv is not None:
                try:
                    rep = hv.getRepresent()
                    if rep is not None:
                        rep_uid = int(rep.getUniqueId())
                except Exception:  # noqa: BLE001
                    pass
            name = f"u{rep_uid}"
        self._name_cache[uid] = name
        return name

    @staticmethod
    def _purge(name: str) -> str:
        return name.translate({ord(" "): "_", ord("'"): "", ord("."): "_", ord("`"): "", ord("#"): "_", ord(":"): "_"}).replace("$", "_")

    def _is_aliased(self, vn) -> bool:
        hv = self._high(vn)
        if hv is None:
            return False
        try:
            return bool(hv.isAddrTied())
        except Exception:  # noqa: BLE001
            return False

    def _type_for_varnode(self, vn):
        hv = self._high(vn)
        dtype = None
        if hv is not None:
            try:
                dtype = hv.getDataType()
            except Exception:  # noqa: BLE001
                dtype = None
        if dtype is None:
            size = int(vn.getSize()) if vn is not None else 0
            return Integer((size or 4) * BYTE_SIZE, signed=False)
        return self.lift_type(dtype)

    def _is_bool_varnode(self, vn) -> bool:
        """True if Ghidra types this varnode as ``bool`` (so a sibling 0/1 constant means false/true)."""
        try:
            return bool(self._type_for_varnode(vn).is_boolean)
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def as_bool_constant(expr):
        """Retype an integer 0/1 constant as ``bool`` so codegen renders it ``false`` / ``true``.

        Ghidra never types a *constant* varnode as bool (only variables carry the bool datatype), so
        a boolean written to / compared with / combined with a bool value still lifts its 0/1 literal
        as an integer. When the surrounding operation has a bool operand we coerce that literal here.
        """
        from decompiler.structures.pseudo import Constant, CustomType, Integer

        if type(expr) is Constant and isinstance(expr.type, Integer) and expr.value in (0, 1):
            return Constant(expr.value, CustomType.bool())
        return expr

    # -- memory version ----------------------------------------------------
    def _next_memory_version(self) -> int:
        self._mem_version += 1
        return self._mem_version

    # -- address / symbol helpers -----------------------------------------
    def _address(self, addr: int):
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(addr)

    def _global_type(self, program, addr: int, size: int):
        try:
            if (dv := program.getListing().getDataAt(self._address(addr))) is not None and dv.getDataType() is not None:
                return self.lift_type(dv.getDataType())
        except Exception:  # noqa: BLE001
            pass
        # Use the canonical (largest) access size for this address so a global accessed at
        # multiple sizes lifts to a single typed variable (see ``_global_size``).
        size = self._global_size.get(addr, size)
        return Integer((size or 8) * BYTE_SIZE, signed=False)

    def _global_initial_value(self, addr: int, vartype):
        """The initial *contents* of the global at ``addr`` (read from the program), as a Constant.

        The global declaration should read ``d = 8`` (its initial value), not ``d = 0x104010`` (its
        own address, which is what using the address as the initial value produced), matching the
        Binary Ninja frontend. Uninitialized ``.bss`` globals have no defined data and default to 0.
        """
        from decompiler.structures.pseudo import Constant

        try:
            dv = self.program.getListing().getDataAt(self._address(addr))
            value = dv.getValue() if dv is not None else None
            if value is not None:
                if hasattr(value, "getValue"):  # ghidra Scalar
                    return Constant(int(value.getValue()), vartype)
                if hasattr(value, "getOffset"):  # ghidra Address (a pointer global's target)
                    return Constant(int(value.getOffset()), vartype)
                return Constant(int(value), vartype)
        except Exception:  # noqa: BLE001
            pass
        return Constant(0, vartype)

    def _address_size_bits(self) -> int:
        """Pointer size of the program's default address space, in bits (cached)."""
        if not hasattr(self, "_addr_bits_cache"):
            try:
                self._addr_bits_cache = int(self.program.getAddressFactory().getDefaultAddressSpace().getSize())
            except Exception:  # noqa: BLE001
                self._addr_bits_cache = 64
        return self._addr_bits_cache

    def _string_at(self, addr: int) -> Optional[str]:
        """Return the (C-escaped) string stored at ``addr``, if any, so a pointer constant lifts as a
        string literal (e.g. ``__isoc99_scanf("%d", &x)`` instead of ``__isoc99_scanf(0x10201b, &x)``),
        matching Binary Ninja's string recovery.

        Ghidra's auto-analysis leaves many ``printf``/``scanf`` format strings *undefined*, so we fall
        back to reading the bytes and recovering a NUL-terminated printable C string ourselves. The
        result is C-escaped (control chars/quotes) so the backend emits valid C -- like the Binary
        Ninja frontend, whose string values are already escaped.
        """
        raw = self._raw_string_at(addr)
        return self._escape_c_string(raw) if raw is not None else None

    def _raw_string_at(self, addr: int) -> Optional[str]:
        """The raw (unescaped) string at ``addr``: Ghidra's defined string, else a byte-read fallback."""
        try:
            dv = self.program.getListing().getDefinedDataAt(self._address(addr))
            if dv is not None:
                val = dv.getValue()
                if isinstance(val, str) and val:
                    return val
        except Exception:  # noqa: BLE001
            pass
        return self._read_c_string(addr)

    def _read_c_string(self, addr: int, max_length: int = 4096) -> Optional[str]:
        """Recover a NUL-terminated printable C string by reading program memory at ``addr``.

        Conservative to avoid turning arbitrary pointers into strings: the target must live in an
        initialized, read-only block (where string literals live, e.g. ``.rodata``), be terminated by
        a NUL within ``max_length`` bytes, and be almost entirely printable.
        """
        try:
            memory = self.program.getMemory()
            start = self._address(addr)
            block = memory.getBlock(start)
            if block is None or not block.isInitialized() or block.isWrite():
                return None
            data = bytearray()
            for offset in range(max_length):
                byte = memory.getByte(start.add(offset)) & 0xFF
                if byte == 0:
                    break
                data.append(byte)
            else:
                return None  # no NUL terminator within the limit -> not a C string
            if not data:
                return None
            text = data.decode("latin-1")
            printable = sum(1 for char in text if 0x20 <= ord(char) < 0x7F or char in "\t\n\r")
            if printable / len(text) < 0.95:
                return None
            return text
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _escape_c_string(value: str) -> str:
        """C-escape a recovered string so the backend renders a valid string literal."""
        simple = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\t": "\\t", "\r": "\\r"}
        out = []
        for char in value:
            if char in simple:
                out.append(simple[char])
            elif 0x20 <= ord(char) < 0x7F:
                out.append(char)
            else:
                out.append(f"\\x{ord(char):02x}")
        return "".join(out)

    def _global_symbol_name(self, addr: int) -> Optional[str]:
        """A real (symbol-table) name for the global at ``addr``, if any.

        Unlike Ghidra's flaky per-varnode ``DAT_`` auto-labels (which ``_global_name`` deliberately
        ignores), a primary symbol is stable per address, so using it does not split one global
        into two. Auto-generated labels (``DAT_``, ``FUN_``, ``sub_``) are skipped. We deliberately do
        NOT skip external-entry-point symbols: exported/imported data globals (``a``, ``c``, ``d``,
        ...) are marked as entry points yet carry perfectly good names, so rejecting them merely
        forced the noisy ``data_<hex>`` fallback instead of the real name Ghidra already knows.
        """
        try:
            sym = self.program.getSymbolTable().getPrimarySymbol(self._address(addr))
            if sym is None:
                return None
            name = sym.getName()
            if not name or name.startswith(("DAT_", "FUN_", "sub_", "loc_", "off_")):
                return None
            return self._purge(name)
        except Exception:  # noqa: BLE001
            return None

    def _function_symbol_at(self, program, addr: int):
        try:
            fm = program.getFunctionManager()
            func = fm.getFunctionAt(self._address(addr))
            if func is not None:
                sym = FunctionSymbol(self._purge(func.getName()), addr)
                try:
                    sym.can_return = bool(func.getReturn().canReturn()) if func.getReturn() else None
                except Exception:  # noqa: BLE001
                    sym.can_return = None
                return sym
            # Not a function at this address: a call through an import-address-table (IAT)
            # slot targets the pointer, not code. Ghidra resolves the slot to the imported
            # function via a reference; use that name (e.g. `CreateThread`) instead of a
            # `sub_<slot>` placeholder. Keep the IAT slot as the symbol's address -- it is a
            # real, navigable program address that resolves back to the import.
            imported = fm.getReferencedFunction(self._address(addr))
            if imported is not None:
                return ImportedFunctionSymbol(self._purge(imported.getName()), addr)
            ghidra_addr = self._address(addr)
            sym = program.getSymbolTable().getPrimarySymbol(ghidra_addr)
            if sym is not None and not sym.getName().startswith(("PTR_", "DAT_", "FUN_", "sub_")):
                return ImportedFunctionSymbol(self._purge(sym.getName()), addr)
            # The target is not code and has no resolved function: it is an indirect call
            # through a data pointer (`call [DAT_...]`). Name it like any other global
            # (`data_<hex>`, or its real symbol) so it renders and navigates as data, not a
            # bogus `sub_<hex>` "function".
            if program.getMemory().contains(ghidra_addr):
                data_name = self._global_symbol_name(addr) or f"data_{hex(addr)}"
                return ImportedFunctionSymbol(data_name, addr)
        except Exception as exc:  # noqa: BLE001
            logging.debug("[GhidraLifter] symbol lookup at %s failed: %s", hex(addr), exc)
        return ImportedFunctionSymbol(f"sub_{addr:x}", addr)

    def _function_symbol_for_pointer(self, vn):
        try:
            if vn.isConstant() or vn.isAddress():
                addr = int(vn.getOffset())
                return self._function_symbol_at(self.program, addr)
        except Exception:  # noqa: BLE001
            pass
        return None

    def _userop_name(self, index: int) -> Optional[str]:
        """The name of the CALLOTHER user-defined p-code op at ``index`` (e.g. ``RDTSC``), or None.

        Ghidra models instructions it has no p-code semantics for (``rdtsc``, ``cpuid``, ``LOCK``,
        vector/crypto intrinsics, syscalls, ...) as CALLOTHER with a per-language user-op index. The
        language's user-op table maps that index to a readable name, so ``callother_43(...)`` can be
        rendered as ``RDTSC(...)``.
        """
        try:
            name = self.program.getLanguage().getUserDefinedOpName(int(index))
            return self._purge(name) if name else None
        except Exception:  # noqa: BLE001
            return None

    def _param_names_for_call(self, symbol) -> list:
        try:
            addr = int(symbol.value)
            func = self.program.getFunctionManager().getFunctionAt(self._address(addr))
            if func is not None:
                # Strip Ghidra's leading-underscore convention for library parameters so the argument
                # comments read like Binary Ninja's, e.g. ``/* format */`` instead of ``/* __format */``.
                return [str(p.getName()).lstrip("_") for p in func.getParameters()]
        except Exception:  # noqa: BLE001
            pass
        return []
