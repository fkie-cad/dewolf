from __future__ import annotations

from typing import Dict, Iterable, Optional, Type, Union

from decompiler.pipeline.controlflowanalysis.restructuring_commons.side_effect_handling.data_graph_visitor import (
    ASTDataGraphVisitor,
    SubtreeProperty,
)
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CaseNode, CodeNode, ConditionNode, LoopNode, SwitchNode, TrueNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import BasicBlockEdge, FalseCase, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Assignment, Branch, Call, Condition, Constant, ListOperation, Variable
from networkx import MultiDiGraph


class DataNode(BasicBlock):
    def copy(self) -> DataNode:
        """Return a deep copy of the node."""
        return DataNode(self._address, [instruction.copy() for instruction in self._instructions], graph=self._graph)

    @classmethod
    def generate_node_from(
        cls, idx: int, ast_node: AbstractSyntaxTreeNode, condition_map: Dict[LogicCondition, Condition]
    ) -> Optional[DataNode]:
        if isinstance(ast_node, CodeNode):
            return DataNode(idx, ast_node.instructions)
        if isinstance(ast_node, ConditionNode):
            return LogicNode(idx, ast_node, condition_map)
        if isinstance(ast_node, SwitchNode):
            return DataNode(idx, [Assignment(ListOperation([]), Call(Variable("switch"), [ast_node.expression]))])
        if isinstance(ast_node, LoopNode):
            return LogicNode(idx, ast_node, condition_map)
        if isinstance(ast_node, CaseNode):
            constant = ast_node.constant if isinstance(ast_node.constant, Constant) else Constant(ast_node.constant)
            return DataNode(idx, [Assignment(ListOperation([]), Call(Variable("case"), [constant]))])
        return None


class LogicNode(DataNode):
    def __init__(
        self,
        name: int,
        ast_node: Union[LoopNode, ConditionNode],
        condition_map: Dict[LogicCondition, Condition],
        graph: ControlFlowGraph = None,
    ):
        super().__init__(name, [Branch(condition_map[symbol]) for symbol in ast_node.condition.get_symbols()], graph)
        self._logic_condition = ast_node.condition
        self._condition_map = condition_map
        self._type = ast_node.loop_type.value if isinstance(ast_node, LoopNode) else "if"

    def __str__(self) -> str:
        """Return a string representation of all instructions in the basic block."""
        return f"{self._type}({self._logic_condition.rich_string_representation(self._condition_map)})"

    def __eq__(self, other: object) -> bool:
        """Basic Blocks can be equal based on their contained instructions and addresses."""
        return isinstance(other, LogicNode) and self._address == other._address

    def __hash__(self) -> int:
        """
        Basic Blocks should hash the same even then in different graphs.

        Since addresses are supposed to be unique,
        they are used for hashing in order to identify the same Block with different instruction as equal.
        """
        return hash(self._address)

    @property
    def logic_condition(self) -> LogicCondition:
        return self._logic_condition

    def copy(self) -> LogicNode:
        """Return a deep copy of the node."""
        return LogicNode(self._address, self._logic_condition, self._condition_map, graph=self._graph)


class DataGraph(ControlFlowGraph):
    NODE = DataNode
    EDGE = BasicBlockEdge

    def __init__(self, graph: Optional[MultiDiGraph] = None, root: Optional[NODE] = None):
        """
        Init a new empty instance.

        - translation_dict maps the AST-nodes to the data-nodes of the graph
        """
        super().__init__(graph, root)
        self._translation_dict: Dict[AbstractSyntaxTreeNode, DataNode] = dict()

    @classmethod
    def generate_from_ast(cls, ast: AbstractSyntaxTree) -> DataGraph:
        data_graph = cls()
        property_dict = data_graph.generate_nodes(ast)
        data_graph.generate_edges(ast, property_dict)
        return data_graph

    def generate_nodes(self, ast: AbstractSyntaxTree) -> Dict[AbstractSyntaxTreeNode, SubtreeProperty]:
        """Generate nodes from the given ast for the data graph."""
        ast_data_graph_visitor: ASTDataGraphVisitor = ASTDataGraphVisitor()
        idx = 0
        for ast_node in ast.post_order():
            base_node = DataNode.generate_node_from(idx, ast_node, ast.condition_map)
            if base_node is not None:
                self.add_node(base_node)
                self._translation_dict[ast_node] = base_node
                idx += 1
            ast_data_graph_visitor.visit(ast_node)
        return ast_data_graph_visitor.property_dict

    def generate_edges(self, ast: AbstractSyntaxTree, property_dict: Dict[AbstractSyntaxTreeNode, SubtreeProperty]) -> None:
        """Generate edges between the data-graph nodes"""
        for seq_node in ast.get_sequence_nodes_post_order():
            for source_child, sink_child in zip(seq_node.children[:-1], seq_node.children[1:]):
                self._add_edges_between(property_dict[source_child].last_nodes, {property_dict[sink_child].first_node})
        for cond_node in ast.get_condition_nodes_post_order():
            for branch in cond_node.children:
                edge_type = TrueCase if isinstance(branch, TrueNode) else FalseCase
                self._add_edges_between({cond_node}, {property_dict[branch.child].first_node}, edge_type)
        for loop_node in ast.get_loop_nodes_post_order():
            self._add_edges_between(property_dict[loop_node.body].continue_nodes | property_dict[loop_node.body].last_nodes, {loop_node})
            self._add_edges_between({loop_node}, {property_dict[loop_node.body].first_node}, TrueCase)
        for switch_node in ast.get_switch_nodes_post_order():
            self._add_edges_between({switch_node}, switch_node.children, SwitchCase)
            for source_case, sink_case in zip(switch_node.children[:-1], switch_node.children[1:]):
                if source_case.break_case:
                    continue
                self._add_edges_between(property_dict[source_case].last_nodes, {property_dict[sink_case].first_node})
            # edges for case_nodes
            for case in switch_node.children:
                self._add_edges_between({case}, {property_dict[case.child].first_node})

    def _add_edges_between(
        self,
        sources: Iterable[AbstractSyntaxTreeNode],
        sinks: Iterable[AbstractSyntaxTreeNode],
        edge_type: Type[BasicBlockEdge] = UnconditionalEdge,
    ):
        """Add edges between the corresponding base-nodes of the source nodes and the base-nodes of the sink nodes."""
        for source in sources:
            for sink in sinks:
                if edge_type == SwitchCase:
                    assert isinstance(sink, CaseNode)
                    self.add_edge(SwitchCase(self._translation_dict[source], self._translation_dict[sink], [sink.constant]))
                elif edge_type == UnconditionalEdge and isinstance(source, (ConditionNode, LoopNode)):
                    self.add_edge(FalseCase(self._translation_dict[source], self._translation_dict[sink]))
                else:
                    self.add_edge(edge_type(self._translation_dict[source], self._translation_dict[sink]))

    def get_logic_nodes(self) -> Iterable[LogicNode]:
        """Yield all logic nodes of the data-graph"""
        for node in self.nodes:
            if isinstance(node, LogicNode):
                yield node
