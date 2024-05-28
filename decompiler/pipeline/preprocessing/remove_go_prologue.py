"""Module for removing go idioms"""
import logging
from typing import Optional, Tuple
from decompiler.pipeline.preprocessing.util import match_expression

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import ConditionalEdge, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Comment, Phi
from decompiler.structures.pseudo.operations import Call, Condition, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask


class RemoveGoPrologue(PipelineStage):
    """
    RemoveGoPrologue finds and removes Go function prologues,
    Caution: this stage changes code semantic
    """

    name = "remove-go-prologue"

    def run(self, task: DecompilerTask):
        if task.options.getboolean(f"{self.name}.remove_prologue", fallback=False):
            self._cfg = task.graph
            self.r14_name = self._get_r14_name(task)
            self._function_name = task.name
            if self._check_and_remove_go_prologue():
                pass
            else:
                logging.info("No Go function prologue found")

    def _get_r14_name(self, task: DecompilerTask):
        r14_parameter_index = None
        for i, location in enumerate(task.function_parameter_locations):
            if location == "r14":
                r14_parameter_index = i
                break
        if r14_parameter_index is None:
            return None
        return task.function_parameters[r14_parameter_index].name

    def _is_root_single_indirect_successor(self, node: BasicBlock):
        successors = self._cfg.get_successors(node)

        if len(successors) != 1:
            return False
        successor = successors[0]

        if successor == self._cfg.root:
            return True

        if len(node.instructions) == 0 and self._cfg.in_degree(node) == 1:
            return self._is_root_single_indirect_successor(successor)

        return False

    def _find_morestack_node(self, node: BasicBlock):
        if len(node.instructions) != 0:
            return node

        successor = self._cfg.get_successors(node)[0]

        # To prevent endless loops?
        if successor == self._cfg.root:
            return node

        return self._find_morestack_node(successor)

    def _verify_graph_structure(self) -> Optional[Tuple[BasicBlock, BasicBlock]]:
        """
        returns morestack_node and start_node if graph structure matches go prologue, otherwise None
        """
        # In a Go function prologue one of the successors (start_node) marks the start of the function.
        # The other successor (morestack_node) contains a call to runtime_morestack(_noctxt_abi0)
        # and has the root as its only successor.
        # morestack_node is the only predecessor of root.
        # root is the only predecessor of morestack_node. EXCEPT IF A NON-RETURNING FUNCTION RIGHT BEFORE IT IS NOT DETECTED!

        # Function should have a root node
        root = self._cfg.root
        if root is None:
            return None

        # root node should only have an incomming edge from morestack_node
        if self._cfg.in_degree(root) != 1:
            return None

        # root node needs exactly two successors
        successors = self._cfg.get_successors(root)
        if len(successors) != 2:
            return None

        # The following code determines start_node and morestack_node
        morestack_node = None
        start_node = None
        for successor in successors:
            # if root in self._cfg.get_successors(successor):
            if self._is_root_single_indirect_successor(successor):
                morestack_node = self._find_morestack_node(successor)
            else:
                start_node = successor

        if (start_node is None) or (morestack_node is None):
            return None

        # Dont check (self._cfg.in_degree(morestack_node) != 1), because of non-returning functions...
        # however, check that those edges are unconditional
        conditional_in_edges = [edge for edge in self._cfg.get_in_edges(morestack_node) if isinstance(edge, ConditionalEdge)]
        if len(conditional_in_edges) > 1:  # zero is ok, because the graph could be root -> goto_node -> morestack_node
            return None

        return start_node, morestack_node

    def _match_r14(self, variable: Variable):
        if self.r14_name is not None and variable.name == self.r14_name:
            return True

        if variable.name.startswith("r14"):
            return True

        return False

    def _check_root_node(self) -> bool:
        # check if root node has an if similar to "if((&(__return_addr)) u<= (*(r14 + 0x10)))"
        # or "if((&(__return_addr)) u<= (*(*(fsbase -8) + 0x10)))".
        # or .....
        # however, the variable in lhs sometimes differs from __return_address,
        # so we just check for the address operator.

        root = self._cfg.root
        if root is None:
            return False

        root_node_if = root.instructions[-1]
        if not isinstance(root_node_if, Branch):
            return False

        # check if rhs of condition compares an address (e.g. of __return_addr)
        left_expression = root_node_if.condition.left
        match left_expression:
            case UnaryOperation(OperationType.address):
                pass
            case _:
                return False

        # match stackguard0 within g struct
        right_expression = root_node_if.condition.right

        patterns = [
            (self._match_r14, 0x10),  # 1.17+ (darwin amd64, linux amd64, windows amd64)
            ((("gsbase", 0), -4), 0x8),  # linux   386   1.5  -1.18
            (("fsbase", -8), 0x10),  # linux   amd64 1.5  -1.16
            (("gsbase", 0x468), 0x8),  # darwin  386   1.5  -1.10
            (("gsbase", 0x18), 0x8),  # darwin  386   1.11 -1.14
            (("gsbase", 0x8A0), 0x10),  # darwin  amd64 1.5  -1.10
            (("gsbase", 0x30), 0x10),  # darwin  amd64 1.11 -1.16
            ((("fsbase", 0x14), 0), 0),  # windows 386   1.2.2- 1.3
            ((("fsbase", 0x14), 0), 0x8),  # windows 386   1.4  -1.18
            ((("gsbase", 0x28), 0), 0),  # windows amd64 1.2.2- 1.3
            ((("gsbase", 0x28), 0), 0x10),  # windows amd64 1.4  -1.16
        ]
        for pattern in patterns:
            if match_expression(root, right_expression, pattern):
                return True

        return False

    def _verify_morestack_instructions(self, morestack_node: BasicBlock) -> bool:
        # check if morestack_node just contains (in this order)
        # - an arbitrary number of assignments, where value is Phi or MemPhi
        # - n assignments (storing registers)
        # - a single call call
        # - n assignments (restoring registers)
        instructions = morestack_node.instructions
        # Find end of Phi / MemPhi Assignments
        phi_pos = 0
        for i, instruction in enumerate(instructions):
            if not isinstance(instruction, Phi):  # covers MemPhi as well
                phi_pos = i
                break

        # verify there is an odd number of instructions left
        num_non_phi_instructions = len(instructions) - phi_pos
        if num_non_phi_instructions % 2 == 0:
            return False
        num_assignments = (num_non_phi_instructions - 1) // 2

        # verify call is in the middle
        morestack_instruction = instructions[phi_pos + num_assignments]
        if not isinstance(morestack_instruction, Assignment) or not isinstance(morestack_instruction.value, Call):
            return False

        # # TODO: convert to match with constant*[Subject]
        # # TODO: also require other side to be dereference?
        # # verify other assignments set and load variables
        # for instruction in instructions[phi_pos:phi_pos+num_assignments]:
        #     if not isinstance(instruction, Assignment):
        #         return False
        #     if not isinstance(instruction.value, Variable):
        #         return False

        # for instruction in instructions[phi_pos+num_assignments+1:]:
        #     if not isinstance(instruction, Assignment):
        #         return False
        #     if not isinstance(instruction.destination, Variable):
        #         return False

        # save this to restore function name later
        self._morestack_instruction = morestack_instruction
        return True

    def _remove_go_prologue(self, start_node: BasicBlock, morestack_node: BasicBlock):
        # get root_node_if
        root = self._cfg.root
        assert root is not None
        root_node_if = root.instructions[-1]
        assert isinstance(root_node_if, Branch)

        # "remove" prologue
        # Because of Phi functions and Variable Assignments,
        # things go wrong if we delete the nodes (old code below).
        # Instead we change the condition such that morestack_node is never executed.
        # The prologue will be optimized away in later stages.
        # But before we change the condition, we need to find out if it will be True or False.

        root_edges = self._cfg.get_out_edges(root)
        for root_edge in root_edges:
            if isinstance(root_edge, TrueCase):
                new_condition = root_edge.sink == start_node
                break
        else:
            # This should never happen
            raise ValueError("If condition with broken out edges")

        # TODO: This might cause problems, because Constant != Condition
        root_node_if.substitute(root_node_if.condition, self._get_constant_condition(new_condition))

        # Handle incoming edges to morestack_node from non-returning functions
        # We can't simply delete edges without causing problems to Phi functions.
        # Therefore we replace the unconditional edge with a conditional one.
        # The added condition at the end of the block makes sure the edge is never taken.
        # A conditional edge to a newly created "return_node" is added as well.
        # The return_node does nothing.
        # After dead code elmination, this will just have the effect of deleting the edge.
        return_node = BasicBlock(-1, [], self._cfg)
        self._cfg.add_node(return_node)
        unconditional_in_edges = [edge for edge in self._cfg.get_in_edges(morestack_node) if isinstance(edge, UnconditionalEdge)]
        for edge in unconditional_in_edges:
            # edge.source.add_instruction(Return([]))
            self._cfg.remove_edge(edge)
            self._cfg.add_edge(FalseCase(edge.source, edge.sink))
            self._cfg.add_edge(TrueCase(edge.source, return_node))
            # TODO: This might cause problems, because Constant != Condition
            condition = self._get_constant_condition(True)
            edge.source.add_instruction(Branch(condition))

        if unconditional_in_edges:
            self._dont_crash = True

        ## add comment
        function = self._morestack_instruction.value.function
        comment_string = f"Removed Go function prologue (calling function '{function}')."
        comment = Comment(comment_string)
        root.add_instruction_where_possible(comment)

        logging.info(comment_string)

    def _get_constant_condition(self, value: bool):
        int_value = 1 if value else 0
        return Condition(
            OperationType.equal,
            [
                Constant(1, Integer.int32_t()),
                Constant(int_value, Integer.int32_t()),
            ],
        )

    def _check_and_remove_go_prologue(self):
        """
        Remove the typical go function prologue
        """

        if (graph_result := self._verify_graph_structure()) is None:
            return False

        start_node, morestack_node = graph_result

        if not self._check_root_node():
            return False

        if not self._verify_morestack_instructions(morestack_node):
            return False

        self._remove_go_prologue(start_node, morestack_node)
        return True