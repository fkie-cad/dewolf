"""Parser building a dewolf CFG from a Ghidra HighFunction (decompiler SSA p-code)."""

import logging
import os
import sys
from typing import Dict, List, Optional

from decompiler.frontend.lifter import Lifter
from decompiler.frontend.parser import Parser
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo import Constant
from decompiler.structures.pseudo.complextypes import ComplexTypeMap
from decompiler.structures.pseudo.instructions import Instruction


class GhidraParser(Parser):
    """Parse a ghidra HighFunction into a pseudo ControlFlowGraph."""

    def __init__(self, lifter: Lifter, report_threshold: int = 3):
        self._lifter = lifter
        self._unlifted_ops: int = 0
        self._report_threshold = int(report_threshold)
        self._complex_types: Optional[ComplexTypeMap] = None

    def parse(self, high_function) -> ControlFlowGraph:
        from ghidra.program.model.pcode import PcodeOp

        # Assign SSA labels up-front so live-in values get label 0 and definitions
        # get 1, 2, ... (matches dewolf's insert-missing-definitions invariant).
        self._lifter.precompute_ssa_labels(high_function)
        # Canonical size per global address (so mixed-size accesses lift to one typed variable).
        self._lifter.precompute_global_sizes(high_function)
        # Assign memory versions to memory-writing ops and to aliased globals.
        self._lifter.precompute_memory_versions(high_function)
        # Record the stack pointer + frame so PTRSUB(stackpointer, off) lifts to &local_X.
        self._lifter.precompute_stack_variables(high_function)

        if os.environ.get("DEWOLF_DUMP_PCODE"):
            self._dump_pcode(high_function)

        cfg = ControlFlowGraph()
        blocks = {}
        block_start_addr: Dict[int, int] = {}

        for b in high_function.getBasicBlocks():
            ops = list(b.getIterator())
            try:
                block_start_addr[int(b.getIndex())] = int(b.getStart().getOffset())
            except Exception:  # noqa: BLE001
                block_start_addr[int(b.getIndex())] = int(ops[0].getSeqnum().getTarget().getOffset()) if ops else 0
            instructions: List[Instruction] = []
            for op in ops:
                lifted = self._lifter.lift(op)
                if lifted is None:
                    continue
                if not isinstance(lifted, Instruction):
                    self._unlifted_ops += 1
                    continue
                instructions.append(lifted)
            bb = BasicBlock(int(b.getIndex()), instructions=instructions)
            cfg.add_node(bb)
            blocks[int(b.getIndex())] = (bb, b, ops)

        addr_to_block = {addr: idx for idx, addr in block_start_addr.items()}

        for idx, (bb, b, ops) in blocks.items():
            last_op = ops[-1] if ops else None
            out_size = b.getOutSize()
            if out_size == 0:
                continue
            opcode = last_op.getOpcode() if last_op is not None else -1
            if opcode == PcodeOp.CBRANCH:
                true_addr = int(last_op.getInput(0).getOffset())
                true_idx = addr_to_block.get(true_addr)
                for i in range(out_size):
                    ob = b.getOut(i)
                    ob_idx = int(ob.getIndex())
                    target = blocks[ob_idx][0]
                    if ob_idx == true_idx:
                        cfg.add_edge(TrueCase(bb, target))
                    else:
                        cfg.add_edge(FalseCase(bb, target))
            elif opcode == PcodeOp.BRANCHIND:
                # Model indirect jumps (switches / jump tables) as SwitchCase edges
                # with crafted per-target case constants. The restructuring pipeline
                # expects switch edges to carry `.cases`; a bare IndirectEdge would
                # crash `empty_basic_block_remover`.
                for i in range(out_size):
                    ob = b.getOut(i)
                    cfg.add_edge(SwitchCase(bb, blocks[int(ob.getIndex())][0], [Constant(i)]))
            else:  # BRANCH or fall-through -> unconditional
                ob = b.getOut(0)
                cfg.add_edge(UnconditionalEdge(bb, blocks[int(ob.getIndex())][0]))

        # Ensure the CFG root is the function entry block. Ghidra sometimes emits an *empty*
        # entry basic block that shares its start address with the first real block (the entry
        # p-code marker block). Looking the root up by entry address collides on that shared
        # address (the dict dedup keeps the wrong block), so the empty entry block ends up a
        # non-root predecessor and phi-function-fixer crashes ("Predecessor block ... is not
        # dominated by any variable"). The unambiguous entry is the block with no predecessors.
        entry_block = None
        try:
            entry_addr = int(high_function.getFunction().getEntryPoint().getOffset())
        except Exception:  # noqa: BLE001
            entry_addr = None
        for idx, (bb, b, ops) in blocks.items():
            if b.getInSize() == 0:
                entry_block = bb
                # Prefer a no-in-edge block that also matches the entry address when several exist.
                if entry_addr is not None and block_start_addr.get(idx) == entry_addr:
                    break
        if entry_block is not None:
            cfg.root = entry_block
        elif entry_addr is not None and entry_addr in addr_to_block:
            cfg.root = blocks[addr_to_block[entry_addr]][0]

        self._materialize_constant_phi_inputs(cfg)

        self._complex_types = self._lifter.complex_types
        self._report_unlifted()
        if os.environ.get("DEWOLF_DUMP_CFG"):
            # Opt-in debug aid: dump the lifted CFG to stderr (does not pollute decompiled stdout).
            for n in cfg.nodes:
                print(f"== block {n.name} ==", file=sys.stderr)
                for ins in n.instructions:
                    print("   ", ins, file=sys.stderr)
        return cfg

    def _materialize_constant_phi_inputs(self, cfg: ControlFlowGraph) -> None:
        """Replace Constant phi operands with head-defined Variables.

        Ghidra MULTIEQUAL (phi) operands may be constants (e.g. a global's
        initial function-pointer value). dewolf's phi-function-fixer only
        tracks Variable requirements (``Phi.requirements`` excludes Constants),
        so a constant operand leaves the corresponding predecessor undominated.
        We materialize each distinct constant as ``cst_n = <constant>`` at the
        function entry and use that variable as the phi operand, which the
        fixer resolves to the (dominating) entry block.
        """
        from decompiler.structures.pseudo import Assignment, UnknownType, Variable
        from decompiler.structures.pseudo.instructions import Phi

        entry = cfg.root
        const_to_var: dict = {}
        new_assignments: list = []
        counter = 0
        for node in cfg.nodes:
            for inst in list(node.instructions):
                if not isinstance(inst, Phi):
                    continue
                for operand in list(inst.value.operands):
                    if isinstance(operand, Variable):
                        continue
                    try:
                        key = operand  # Constants/Symbols are hashable by value
                        _ = hash(key)
                    except Exception:  # noqa: BLE001
                        key = id(operand)
                    var = const_to_var.get(key)
                    if var is None:
                        counter += 1
                        var = Variable(f"cst_{counter}", getattr(operand, "type", UnknownType()), ssa_label=0)
                        const_to_var[key] = var
                        new_assignments.append(Assignment(var, operand))
                    inst._value.substitute(operand, var)
        if new_assignments and entry is not None:
            entry.instructions = new_assignments + list(entry.instructions)

    @property
    def complex_types(self) -> ComplexTypeMap:
        return self._complex_types or ComplexTypeMap()

    def _report_unlifted(self) -> None:
        if self._unlifted_ops == 0:
            return
        logging.warning("[GhidraParser] Could not lift %d p-code operations.", self._unlifted_ops)

    @staticmethod
    def _dump_pcode(high_function) -> None:
        """Opt-in debug aid (``DEWOLF_DUMP_PCODE=1``): dump Ghidra's raw high-p-code to stderr.

        Each op is printed with its output varnode id/size and its inputs (constant, address, or
        register varnode with its HighVariable name and defining op). Used to inspect what the
        lifter is working from; writes to stderr so it never pollutes decompiled stdout.
        """
        for b in high_function.getBasicBlocks():
            print(f"--- block {b.getIndex()} start={b.getStart()} ---", file=sys.stderr)
            for op in b.getIterator():
                out = op.getOutput()
                out_s = f"v{out.getUniqueId()}({out.getSize()})" if out is not None else "-"
                ins = []
                for i in range(op.getNumInputs()):
                    vn = op.getInput(i)
                    if vn is None:
                        continue
                    if vn.isConstant():
                        ins.append(f"const{vn.getSize()}:{hex(int(vn.getOffset()))}")
                    elif vn.isAddress():
                        ins.append(f"addr{vn.getSize()}:{hex(int(vn.getOffset()))}")
                    else:
                        try:
                            hv = vn.getHigh().getName()
                        except Exception:  # noqa: BLE001
                            hv = "?"
                        d = vn.getDef()
                        d_s = f"(def=v{d.getOutput().getUniqueId()})" if d is not None else "(livein)"
                        ins.append(f"v{vn.getUniqueId()}[{hv}]{d_s}")
                print(f"  {op.getMnemonic()} out={out_s} ins={ins}", file=sys.stderr)
