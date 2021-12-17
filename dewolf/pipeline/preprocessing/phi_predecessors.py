"""Module fixing the Control Glow Graph such that it contains all information we need for our analysis."""
from typing import Dict, List, Optional

from dewolf.pipeline.stage import PipelineStage
from dewolf.structures.graphs.cfg import BasicBlock
from dewolf.structures.pseudo.expressions import Variable
from dewolf.structures.pseudo.instructions import Phi
from dewolf.task import DecompilerTask
from networkx import DiGraph

from .util import _init_basicblocks_of_definition, _init_maps


class PhiFunctionFixer(PipelineStage):
    """
    The PhiFunctionFixer computes the origin of the variables in a phi-function

    - Given a phi-function v#0 = phi(v#1, v#2, ... , v#l) in basic block B_0 with predecessor blocks B_1, B_2, ... , B_k (l<=k)
    - For each basic block B_j, with 1<=j<=k, we compute the variable v#i, with 1<=i<=l, that is live at the end of this basic block.
    - This can only be one, because we are in Conventional SSA-Form which means that variables in the same phi-function do not interfere.
    """

    name = "phi-function-fixer"

    def run(self, task: DecompilerTask):
        self.cfg = task.graph
        self.head = task.graph.root
        self._def_map, self._use_map = _init_maps(self.cfg)
        self.extend_phi_functions()

    def extend_phi_functions(self):
        """
        The function that we call to extend the phi-function, i.e., it initializes the entry self.origin_block of all phi-functions
        """
        dominator_tree = self.cfg.dominator_tree
        for node in self.cfg:
            for instruction in [inst for inst in node if isinstance(inst, Phi)]:
                live_variable_of_block = self._find_live_variable_of_block(dominator_tree, instruction, node)

                if set(instruction.requirements) != set(live_variable_of_block.values()):
                    raise ValueError("There are variables in the phi-function that are not live at any predecessor block")

                instruction.update_phi_function(live_variable_of_block)

    @staticmethod
    def _find_origin_variable_of_basic_block(
        basic_block: BasicBlock, dominator_tree: DiGraph, defined_variables_in_basicblock: Dict[BasicBlock, Variable]
    ) -> Variable:
        """
        Finds the Variable that is live at 'basic_block', i.e. the variable that is set in the phi-function when we access the basic block
        of the phi-function over 'basic_block'

        :param basic_block: one predecessor of the basic block that contains the phi-function we consider
        :param dominator_tree: dominator tree
        :param defined_variables_in_basicblock: A dictionary with: basic block -> set of variables that are defined in this basic block
        :return: Variable in the phi-function that is live at the end of basic block 'basic_block'
        """
        current_node = basic_block
        while True:
            if current_node in defined_variables_in_basicblock.keys():
                return defined_variables_in_basicblock[current_node]

            try:
                current_node = next(iter(dominator_tree.get_predecessors(current_node)))
            except StopIteration:
                raise ValueError(f"Predecessor block {basic_block} is not dominated by any variable used in the phi-function")

    def _basicblocks_of_used_variables_in_phi_function(
        self, used_variables: List[Variable], is_head: bool
    ) -> Dict[Optional[BasicBlock], Variable]:
        """
        Computes for each Variable, that is used in the current phi-function, the BasicBlock where this Variable is defined.

        :param used_variables: a list of variables that are used in the phi-function we consider
        :return: A dictionary, where the set of keys is the set of nodes where a variable in used_variables is defined, and the value for
                each key is the variable that is defined at the node
        """
        variable_definition_nodes: Dict[BasicBlock, Variable] = dict()
        basic_block_of_definition = _init_basicblocks_of_definition(self.cfg)
        for variable in used_variables:
            if self._def_map.get(variable):
                node_with_variable_definition = basic_block_of_definition[variable]
            else:
                node_with_variable_definition = None if is_head else self.head
            if node_with_variable_definition not in variable_definition_nodes.keys():
                variable_definition_nodes[node_with_variable_definition] = variable
            else:
                raise ValueError(
                    f"Variables {variable} and {variable_definition_nodes[node_with_variable_definition]} are defined in Block "
                    f"{node_with_variable_definition}, i.e., they interfere or one of these Variables is not used in the phi-function"
                )
        return variable_definition_nodes

    def _find_live_variable_of_block(self, dominator_tree: DiGraph, instruction: Phi, node: BasicBlock) -> Dict[BasicBlock, Variable]:
        """
        The function returns a dict that has as key the predecessor blocks of the phi-function
        and as value the variable that is live at this block

        :param dominator_tree: dominator tree
        :param instruction: a Phi-function
        :param node: basic block that contains the phi-function
        :return: dictionary that has as key the predecessor blocks of the basic block 'node' and as value the variable that is live at the
                    appropriate basic block
        """
        variable_of_block: Dict[Optional[BasicBlock], Variable] = dict()
        defined_variables_in_basicblock = self._basicblocks_of_used_variables_in_phi_function(instruction.requirements, self.head == node)
        for predecessor in self.cfg.get_predecessors(node):
            variable = self._find_origin_variable_of_basic_block(predecessor, dominator_tree, defined_variables_in_basicblock)
            variable_of_block[predecessor] = variable
        if self.head == node and None in defined_variables_in_basicblock.keys():
            variable_of_block[None] = defined_variables_in_basicblock[None]
        return variable_of_block
