from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, DefaultDict, Iterator, List, Optional, Dict

from decompiler.pipeline.ssa.value_interferencegraph import ValueInterferenceGraph
from decompiler.structures.graphs.branches import UnconditionalEdge
from decompiler.task import DecompilerTask
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo.instructions import Assignment, Phi, Instruction
from decompiler.util.decoration import DecoratedCFG, DecoratedGraph 


class RevistingOutOfSSa:
    # TODO: these names are stupid
    @dataclass
    class _ParellSpace:
        begin_start_idx: Optional[int] = None
        begin_end_idx: Optional[int] = None

        end_start_idx: Optional[int] = None
        end_end_idx: Optional[int] = None

    class _CongruenceClassHelper:
        pass

    def __init__(self, task: DecompilerTask, phi_functions: DefaultDict[BasicBlock, List[Phi]]):
        self._task: DecompilerTask = task
        self._cfg: ControlFlowGraph = self._task.cfg #type: ignore
        self._phi_functions_of: DefaultDict[BasicBlock, List[Phi]] = phi_functions

        self.lifted_costant_var_name = "__lifted_constat__"
        self._label_count:DefaultDict[str, int] = defaultdict(int)
        self._parell_space_map: DefaultDict[Any[None,BasicBlock], RevistingOutOfSSa._ParellSpace] = defaultdict(RevistingOutOfSSa._ParellSpace)


        self._interference_graph: ValueInterferenceGraph

    def _compute_label_count(self) -> None:
        for var in self._cfg.get_variables():
            if not var.ssa_label: continue
            c_var_count = self._label_count.get(var.name)
            if not c_var_count or c_var_count < var.ssa_label:
                self._label_count[var.name] = var.ssa_label

    def _compute_copy_var(self, var: Variable) -> Variable:
        self._label_count[var.name] += 1
        copy_var = Variable(
            var.name,  
            ssa_label=self._label_count[var.name],
            is_aliased=var.is_aliased,
            ssa_name = None,
            tags = var.tags
        ) 
        return copy_var

    def _compute_lifted_constant_var(self) -> Variable:
        self._label_count[self.lifted_costant_var_name] += 1
        lifted_costant_var = Variable(
            self.lifted_costant_var_name,
            ssa_label=self._label_count[self.lifted_costant_var_name],
            is_aliased=False,
            ssa_name = None,
            tags = None 
        ) 
        return lifted_costant_var 


    def _get_predecessors(self, basic_block: BasicBlock) -> Iterator[Optional[BasicBlock]]:
        yield from list(self._cfg.get_predecessors(basic_block))
        if self._phi_functions_of[basic_block] and None in self._phi_functions_of[basic_block][0].origin_block:
            yield None

    def _insert_basic_block_before(self, basic_block: BasicBlock) -> BasicBlock:
        new_basic_block = self._cfg.create_block()
        self._cfg.add_edge(UnconditionalEdge(new_basic_block, basic_block))
        return new_basic_block

    def _to_cssa(self) -> None:
        self._compute_label_count()

        end_instructions_for_bb: DefaultDict[BasicBlock, List[Instruction]] = defaultdict(list)
        for basic_block in self._phi_functions_of:
            instructions_beginning = list()
            for phi_inst in self._phi_functions_of[basic_block]:
                req = phi_inst.definitions[0]
                copy_var = self._compute_copy_var(req)
                copy_assign = Assignment(req, copy_var)
                instructions_beginning.append(copy_assign)
                phi_inst.substitute(req, copy_var)

                predecessor: BasicBlock
                for predecessor in self._get_predecessors(basic_block): #type: ignore
                    req = phi_inst.origin_block[predecessor]

                    copy_var: Variable
                    if isinstance(req, Variable): 
                        copy_var = self._compute_copy_var(req)
                    elif isinstance(req, Constant):
                        copy_var = self._compute_lifted_constant_var()
                    else:
                        raise RuntimeError("Unexpected Phi requirement!")

                    block: BasicBlock
                    edge = self._cfg.get_edge(predecessor, basic_block) #type: ignore 
                    if predecessor is not None and isinstance(edge, UnconditionalEdge):
                        block = predecessor
                    else:
                        block = self._insert_basic_block_before(basic_block)
                        if predecessor:
                            self._cfg.substitute_edge(edge, edge.copy(sink=block)) #type: ignore
                        else:
                            self._cfg.root = block 

                    copy_assign = Assignment(copy_var, req)
                    end_instructions_for_bb[predecessor].append(copy_assign) 
                    phi_inst.substitute(req, copy_var)


            phi_count = len(self._phi_functions_of[basic_block])
            parallel_space = self._parell_space_map[basic_block]
            parallel_space.begin_start_idx = phi_count
            parallel_space.begin_end_idx = phi_count + len(instructions_beginning) 
            basic_block.instructions = basic_block.instructions[:phi_count] + instructions_beginning + basic_block.instructions[phi_count:]

        for basic_block, instructions in end_instructions_for_bb.items():
            parallel_space = self._parell_space_map[basic_block]
            parallel_space.end_start_idx = len(basic_block.instructions)
            parallel_space.end_end_idx = len(basic_block.instructions) + len(instructions)
            basic_block.instructions.extend(instructions)


    def perform(self) -> None:
        self._to_cssa()
        self._interference_graph = ValueInterferenceGraph(self._cfg)
