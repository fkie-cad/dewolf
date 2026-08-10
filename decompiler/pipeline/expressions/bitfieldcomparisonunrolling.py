from dataclasses import dataclass
from logging import debug, warning
from typing import List, Optional, Tuple, Union

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import ConditionalEdge, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Constant, Expression
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Branch
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType, UnaryOperation
from decompiler.task import DecompilerTask


@dataclass
class FoldedCase:
    """
    Class for storing information of folded case.
    """

    basic_block: BasicBlock
    switch_variable: Expression
    case_values: List[int]
    edge_type_to_case_node: type[FalseCase] | type[TrueCase]

    def get_case_node_and_other_node(self, cfg: ControlFlowGraph) -> Tuple[BasicBlock, BasicBlock]:
        """
        Return the case node and the other node based on which branch condition corresponds to the case node.
        """
        out_edges = cfg.get_out_edges(self.basic_block)
        assert len(out_edges) == 2, "expext two out edges (TrueCase/FalseCase)"
        if isinstance(out_edges[0], self.edge_type_to_case_node):
            return out_edges[0].sink, out_edges[1].sink
        elif isinstance(out_edges[1], self.edge_type_to_case_node):
            return out_edges[1].sink, out_edges[0].sink
        raise ValueError("Outedges do not match type")


class BitFieldComparisonUnrolling(PipelineStage):
    """
    Transform bit-field compiler optimization to readable comparison:

    var = 1 << amount;
    if ((var & 0b11010) != 0) { ... }

    // becomes:

    if ( amount == 1 || amount == 3 || amount == 4 ) { ... }

    This can subsequently be used to reconstruct switch-case statements.

    This stage requires expression-propagation PipelineStage, such that bit-shift
    gets forwarded into Branch.condition:

    if ( (1 << amount) & bit_mask) == 0) ) { ... }
    """

    name = "bit-field-comparison-unrolling"
    dependencies = ["expression-propagation"]

    def run(self, task: DecompilerTask):
        """Run the pipeline stage: Check all viable Branch-instructions."""
        folded_cases: List[FoldedCase] = []
        for block in task.graph:
            if (folded_case := self._get_folded_case(block)) is not None:
                folded_cases.append(folded_case)
        for folded_case in folded_cases:
            self._modify_cfg(task.graph, folded_case)

    def _modify_cfg(self, cfg: ControlFlowGraph, folded_case: FoldedCase):
        """
        Create nested if blocks for each case in unfolded values.
        Note: with the Branch condition encountered so far (== 0x0), the node of the collected cases is adjacent to the FalseCase edge.
        However, negated conditions may exist. In this case, pass condition type (flag) and swap successor nodes accordingly.
        """
        debug("modifying cfg")
        case_node, other_node = folded_case.get_case_node_and_other_node(cfg)
        # remove condition from block
        folded_case.basic_block.remove_instruction(folded_case.basic_block[-1])
        cfg.remove_edges_from(cfg.get_out_edges(folded_case.basic_block))
        # create condition chain
        nested_if_blocks = [
            self._create_condition_block(cfg, folded_case.switch_variable, case_value) for case_value in folded_case.case_values
        ]
        for pred, succ in zip(nested_if_blocks, nested_if_blocks[1:]):
            cfg.add_edge(TrueCase(pred, case_node))
            cfg.add_edge(FalseCase(pred, succ))
        # add edges for last and first block
        cfg.add_edge(TrueCase(nested_if_blocks[-1], case_node))
        cfg.add_edge(FalseCase(nested_if_blocks[-1], other_node))
        cfg.add_edge(UnconditionalEdge(folded_case.basic_block, nested_if_blocks[0]))

    def _create_condition_block(self, cfg: ControlFlowGraph, switch_var: Expression, case_value: int) -> BasicBlock:
        """Create conditional block in CFG, e.g., `if (var == 0x42)`."""
        const = Constant(value=case_value, vartype=switch_var.type)
        return cfg.create_block([Branch(condition=Condition(OperationType.equal, [switch_var, const]))])

    def _get_folded_case(self, block: BasicBlock) -> Optional[FoldedCase]:
        """Unfold Branch condition (checking bit field) into switch variable and list of case values."""
        if not len(block):
            return None
        if not isinstance(branch_instruction := block[-1], Branch):
            return None
        match branch_instruction.condition:
            case Condition(operation=OperationType.equal, left=subexpr, right=Constant(value=0x0)):
                edge_type_to_case_node = FalseCase
            case Condition(operation=OperationType.not_equal, left=subexpr, right=Constant(value=0x0)):
                edge_type_to_case_node = TrueCase
            case Condition(operation=OperationType.equal, left=Constant(value=0x0), right=subexpr):
                edge_type_to_case_node = FalseCase
            case Condition(operation=OperationType.not_equal, left=Constant(value=0x0), right=subexpr):
                edge_type_to_case_node = TrueCase
            case _:
                return None
        if (matched_expression := self._get_switch_var_and_bitfield(subexpr)) is not None:
            switch_var, bit_field = matched_expression
            cleaned_var = self._clean_variable(switch_var)
            case_values = self._get_values(bit_field)
            if cleaned_var and case_values:
                return FoldedCase(
                    basic_block=block, switch_variable=cleaned_var, case_values=case_values, edge_type_to_case_node=edge_type_to_case_node
                )
        return None

    def _get_switch_var_and_bitfield(self, subexpr: Expression) -> Optional[Tuple[Expression, Constant]]:
        """
        Match expression of folded switch case:
            a) ((1 << (cast)var) & 0xffffffff) & bit_field_constant
            b) (0x1 << ((1: ) ecx#1)) & bit_field_constant
        Return the Variable (or Expression) that is switched on, and bit field Constant.
        """
        match subexpr:
            case BinaryOperation(
                operation=OperationType.bitwise_and,
                left=BinaryOperation(
                    operation=OperationType.bitwise_and,
                    left=BinaryOperation(operation=OperationType.left_shift, left=Constant(value=1), right=switch_var),
                    right=Constant(),
                ),
                right=Constant() as bit_field,
            ) if (
                bit_field.value != 0xFFFFFFFF
            ):
                return switch_var, bit_field
            case BinaryOperation(
                operation=OperationType.bitwise_and,
                left=BinaryOperation(operation=OperationType.left_shift, left=Constant(value=1), right=switch_var),
                right=Constant() as bit_field,
            ) if (
                bit_field.value != 0xFFFFFFFF
            ):
                return switch_var, bit_field
            case _:
                debug(f"no match for {subexpr}")
                return None

    def _get_values(self, const: Constant) -> List[int]:
        """Return positions of set bits from integer Constant."""
        bitmask = const.value
        values = []
        if not isinstance(bitmask, int):
            warning("not an integer")
            return []
        for pos, bit in enumerate(bin(bitmask)[:1:-1]):
            if bit == "1":
                values.append(pos)
        return values

    def _clean_variable(self, expr: Expression) -> Optional[Variable]:
        """Remove cast from Variable."""
        if isinstance(expr, Variable):
            return expr
        if isinstance(expr, UnaryOperation) and expr.operation == OperationType.cast:
            if len(expr.requirements) == 1:
                return expr.requirements[0]
