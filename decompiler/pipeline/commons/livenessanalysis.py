"""Liveness Analysis due to Brandner et al. : Algorithms 4 (Compute liveness sets by exploring paths from variable uses"""

from collections import defaultdict
from typing import DefaultDict

from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo import Phi, Variable
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


class LivenessAnalysis:
    """
    This class creates the sets LiveOut and LiveIn of every block as well as the interference graph of a given control flow graph.
    """

    def __init__(self, cfg: ControlFlowGraph):
        """
        self._cfg: The control flow graph whose LiveIn, LiveOut and Interference graph we want to compute.
        self._uses_block: To each basic block we assign the variables that are used in this basic block, except the variables that are only
            used in a Phi-function.
        self._defs_block: To each basic block we assign the variables that are defined in this basic block, except the variables that are
            defined in a Phi-function.
        self._uses_phi_block: To each basic block we assign the variables that are used in a Phi-function of a successor basic block.
        self._defs_phi_block: To each basic block we assign the variables that are defined in a Phi-function of this basic block,
        self._live_in_block: To each basicblock we assign the set LiveIn(B) = PhiDefs(B) ⋃ ( [Uses(B) ⋃ LiveOut(B)] ∖ Defs(B)).
        self._live_out_block: To each basicblock we assign the set LiveOut(B) = ( ⋃_{S ∊ Succ(B)} [LiveIn(S)∖PhiDefs(S)] ) ⋃ PhiUses(B).
        """
        self._cfg: ControlFlowGraph = cfg

        self._uses_block: DefaultDict[BasicBlock, InsertionOrderedSet[Variable]] = defaultdict(InsertionOrderedSet)
        self._defs_block: DefaultDict[BasicBlock, InsertionOrderedSet[Variable]] = defaultdict(InsertionOrderedSet)
        self._uses_phi_block: DefaultDict[BasicBlock, InsertionOrderedSet[Variable]] = defaultdict(InsertionOrderedSet)
        self._defs_phi_block: DefaultDict[BasicBlock, InsertionOrderedSet[Variable]] = defaultdict(InsertionOrderedSet)

        self._live_in_block: DefaultDict[BasicBlock, InsertionOrderedSet[Variable]] = defaultdict(InsertionOrderedSet)
        self._live_out_block: DefaultDict[BasicBlock, InsertionOrderedSet[Variable]] = defaultdict(InsertionOrderedSet)
        self._create_live_sets()

    def live_in_of(self, basicblock: BasicBlock) -> InsertionOrderedSet[Variable]:
        """Returns the dictionary that assigns to each basic block its LiveIn set."""
        return self._live_in_block[basicblock]

    def live_out_of(self, basicblock: BasicBlock) -> InsertionOrderedSet[Variable]:
        """Returns the dictionary that assigns to each basic block its LiveOut set."""
        return self._live_out_block[basicblock]

    def defs_phi_of(self, basicblock: BasicBlock) -> InsertionOrderedSet[Variable]:
        """Returns the dictionary that assigns to each basic block the set of variables that are defined in a Phi-function of this block"""
        return self._defs_phi_block[basicblock]

    def _init_usages_definitions_of_blocks(self) -> None:
        """
        Initialize the dictionaries which tell us the variables that are used resp. defined in a basic block of a given control flow graph.
        We distinguish between Phi-instructions and other instructions.
        """
        for basicblock in self._cfg:
            for instruction in basicblock.instructions:
                if isinstance(instruction, Phi):
                    self._defs_phi_block[basicblock].update(instruction.definitions)
                    for pred_block, value in instruction.origin_block.items():
                        if isinstance(value, Variable):
                            self._uses_phi_block[pred_block].add(value)
                else:
                    self._defs_block[basicblock].update(instruction.definitions)
                    self._uses_block[basicblock].update(instruction.requirements)

    def _explore_all_paths(self, basicblock: BasicBlock, variable: Variable) -> None:
        """
        Explores all paths from a variable's use to its definition.

        :param basicblock: the current basic block where variable 'variable' is used
        :param variable: the variable whose path we explore
        """
        if variable in self._defs_block[basicblock] or variable in self._live_in_block[basicblock]:
            return
        self._live_in_block[basicblock].add(variable)
        if variable in self._defs_phi_block[basicblock]:
            return
        for predecessor_block in self._cfg.get_predecessors(basicblock):
            self._live_out_block[predecessor_block].add(variable)
            self._explore_all_paths(predecessor_block, variable)

    def _create_live_sets(self):
        """
        Computes the sets LiveIn and LiveOut for each basic block.

        LiveIn(B) = PhiDefs(B) ⋃ ( [Uses(B) ⋃ LiveOut(B)] ∖ Defs(B))
        LiveOut(B) = ( ⋃_{S ∊ Succ(B)} [LiveIn(S)∖PhiDefs(S)] ) ⋃ PhiUses(B)
        """
        self._init_usages_definitions_of_blocks()
        for basicblock in self._cfg.nodes:
            for variable in self._uses_phi_block[basicblock]:
                self._live_out_block[basicblock].add(variable)
                self._explore_all_paths(basicblock, variable)
            for variable in self._uses_block[basicblock]:
                self._explore_all_paths(basicblock, variable)
        if None in self._uses_phi_block.keys():
            self._live_out_block[None] = self._uses_phi_block[None]
