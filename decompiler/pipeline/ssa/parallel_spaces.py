from collections import defaultdict
from dataclasses import dataclass, field
from typing import DefaultDict, List, Mapping 
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Variable
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


    def _sequentialize_space(self, assignments: List[Assignment]) -> List[Assignment]:
        loc = dict()
        pred = dict()
        to_do = list() 
        ready = list()
        ret = []

        for assign in assignments:
            loc[assign.definitions[0]] = None
            pred[assign.requirements[0]] = None

        for assign in assignments:
            loc[assign.requirements[0]] = assign.requirements[0]
            pred[assign.definitions[0]] = assign.requirements[0]
            to_do.append(assign.definitions[0])

        for assign in assignments:
            if loc[assign.definitions[0]] == None:
                ready.append(assign.definitions[0])

        while to_do:
            while ready:
                b = ready.pop()
                a = pred[b]
                c = loc[a]
                ret.append(Assignment(b,c))
                loc[a] = b
                if a == c and pred[a] != None:
                    ready.append(a)

            b: Variable = to_do.pop()
            if b != loc[pred[b]]:
                n = Variable(
                    #TODO find a reliable way to avoid collisions 
                    b.name + "__copy__",
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

    def sequentialize(self) -> None:
        for space in self._parallel_spaces_map.values():
            space.after_phi_assigns = self._sequentialize_space(space.after_phi_assigns)
            space.end_of_block_assigns= self._sequentialize_space(space.end_of_block_assigns)
