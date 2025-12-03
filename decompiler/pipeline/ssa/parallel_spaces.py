from collections import defaultdict
from dataclasses import dataclass, field
from typing import DefaultDict, List, Mapping 
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, Phi 
class ParallelSpaces:
    @dataclass
    class _Block_Spaces:
        after_phi_assigns: List[Assignment] = field(default_factory=list) 
        end_of_block_assigns: List[Assignment] = field(default_factory=list) 

    def __init__(self, phi_functions: Mapping[BasicBlock, List[Phi]]):

        self._parallel_spaces_map: DefaultDict[int, ParallelSpaces._Block_Spaces] =\
                defaultdict(lambda: ParallelSpaces._Block_Spaces())
        
        self._phi_bb_len_map: DefaultDict[int, int] = defaultdict(lambda: int(0))
        for basic_block, phi_instrs in phi_functions.items():
            self._phi_bb_len_map[basic_block.address] = len(phi_instrs)

    def add_after_phi_assign(self, basic_block_addr: int, assign: Assignment) -> None:
        self._parallel_spaces_map[basic_block_addr].after_phi_assigns.append(assign)

    def add_end_of_block_assign(self, basic_block_addr: int, assign: Assignment) -> None:
        self._parallel_spaces_map[basic_block_addr].end_of_block_assigns.append(assign)

    def instert_into_cfg(self, cfg: ControlFlowGraph) -> None:
        for basic_block in cfg:
            phi_count = self._phi_bb_len_map[basic_block.address] 
            block_space = self._parallel_spaces_map[basic_block.address]

            basic_block.instructions \
                    = basic_block.instructions[:phi_count] \
                    + block_space.after_phi_assigns \
                    + basic_block.instructions[phi_count:]

            basic_block.instructions.extend(block_space.end_of_block_assigns)


    def _remove_nop_copies_space(self, assignments: List[Assignment]) -> List[Assignment]: 
        ret = []
        for assign in assignments:
            if assign.destination != assign.value:
                ret.append(assign)
        return ret

    def remove_nop_copies(self) -> None:
        for space in self._parallel_spaces_map.values():
            space.after_phi_assigns = self._remove_nop_copies_space(space.after_phi_assigns)
            space.end_of_block_assigns = self._remove_nop_copies_space(space.end_of_block_assigns)


    def _sequentialize_space(self, assignments: List[Assignment]) -> List[Assignment]:
        loc = dict()
        pred = dict()
        to_do = list() 
        ready = list()
        ret = []

        for assign in assignments:
            loc[assign.destination] = None
            pred[assign.value] = None

        for assign in assignments:
            loc[assign.value] = assign.value
            pred[assign.destination] = assign.value
            to_do.append(assign.destination)

        for assign in assignments:
            if loc[assign.destination] == None:
                ready.append(assign.destination)

        visited = set() 
        while to_do:
            while ready:
                b = ready.pop()
                a = pred[b]
                c = loc[a]
                ret.append(Assignment(b,c))
                loc[a] = b
                if a == c and pred[a] != None:
                    ready.append(a)

                visited |= {b}

            b: Variable = to_do.pop()
            if b not in visited:
                n: Variable
                cp_suffix = "__copy__" #TODO find a reliable way to avoid collisions 
                n = Variable(
                    b.name + cp_suffix,
                    b.type,
                    None,
                    b.is_aliased,
                    None,
                    b.tags

                )
                ret.append(Assignment(n,b))
                loc[b] = n
                ready.append(b)

        return ret

    def _test_space(self) -> None:
        pass

    def sequentialize(self) -> None:
        for space in self._parallel_spaces_map.values():
            space.after_phi_assigns = self._sequentialize_space(space.after_phi_assigns)
            space.end_of_block_assigns= self._sequentialize_space(space.end_of_block_assigns)
