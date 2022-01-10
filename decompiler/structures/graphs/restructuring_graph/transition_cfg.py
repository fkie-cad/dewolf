from __future__ import annotations

from abc import ABC
from typing import Dict, Iterable, Optional

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CodeNode
from decompiler.structures.ast.condition_symbol import ConditionHandler, ConditionSymbol
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import BasicBlockEdgeCondition
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.graphs.classifiedgraph import ClassifiedGraph, EdgeProperty
from decompiler.structures.graphs.interface import GraphEdgeInterface, GraphNodeInterface
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Branch, Condition, IndirectBranch, OperationType
from networkx import DiGraph


class TransitionBlock(GraphNodeInterface):
    """Implementation of a node representing a basic block."""

    def __init__(self, address: int, ast: AbstractSyntaxTreeNode):
        """
        Init a new block BasicBlock.

        address -- The address the basic block is at (-1 indicates to take an unique one)
        ast -- The current head of the AST representing this node.
        """
        self._address: int = address
        self.ast: AbstractSyntaxTreeNode = ast

    def __str__(self) -> str:
        """Return a string representation of all instructions in the basic block."""
        return str(self.ast)

    def __repr__(self) -> str:
        """Return a debug representation of the block."""
        return f"TransitionBlock({hex(self.address)}, AST={self.ast})"

    def __eq__(self, other: object) -> bool:
        """Basic Blocks can be equal based on their contained instructions and addresses."""
        return isinstance(other, TransitionBlock) and self.ast == other.ast and self._address == other._address

    def __hash__(self) -> int:
        """
        Basic Blocks should hash the same even then in different graphs.

        Since addresses are supposed to be unique,
        they are used for hashing in order to identify the same Block with different instruction as equal.
        """
        return hash(self._address)

    @property
    def address(self) -> int:
        """Return the address of the block."""
        return self._address

    @property
    def name(self) -> str:
        """Return the 'name' of the block (legacy)."""
        if self.address < 0:
            return f"n{-self.address}"
        return str(self._address)

    def copy(self) -> TransitionBlock:
        """Return a deep copy of the node."""
        return TransitionBlock(self._address, ast=self.ast)

    def is_empty(self) -> bool:
        """Check if this basic block is empty."""
        return isinstance(self.ast, CodeNode) and len(self.ast.instructions) == 0


class TransitionEdge(GraphEdgeInterface, ABC):
    """Class representing an edge between basic blocks."""

    def __init__(
        self,
        source: TransitionBlock,
        sink: TransitionBlock,
        tag: Optional[LogicCondition],
        edge_property: Optional[EdgeProperty] = None,
    ):
        """
        Init an new basic block edge based on start, end and type.

        source -- The start of the edge
        sink -- The end of the edge
        tag -- The condition that has to be fulfilled when the flow goes over this edge
        edge_property -- The type of the edge, i.e., back-edge, retreating-edge, non-loop, tree-edge and so on.
        """
        self._source: TransitionBlock = source
        self._sink: TransitionBlock = sink
        self.tag: LogicCondition = tag
        self.property: EdgeProperty = edge_property

    @property
    def source(self) -> TransitionBlock:
        """Return the start of the edge."""
        return self._source

    @property
    def sink(self) -> TransitionBlock:
        """Return the target of the edge."""
        return self._sink

    def __eq__(self, other):
        """Check if two basic block edges have the same start and end points."""
        return isinstance(other, type(self)) and self.__dict__ == other.__dict__

    def __hash__(self) -> int:
        """Return an unique hash for the given edge."""
        return hash((self.source, self.sink))

    def copy(
        self, source: Optional[TransitionBlock] = None, sink: Optional[TransitionBlock] = None, edge_property: Optional[EdgeProperty] = None
    ) -> TransitionEdge:
        """
        Copy the edge, returning a new object.
        source -- (optional) The new source of the copied edge.
        sink -- (optional) The new sink of the copied edge.
        edge-property -- (optional) The new edge-property of the copied edge.
        """
        return TransitionEdge(
            source if source is not None else self._source,
            sink if sink is not None else self._sink,
            tag=self.tag.copy(),
            edge_property=edge_property if edge_property is not None else self.property,
        )


class TransitionCFG(ClassifiedGraph):
    """Class representing an control flow graph for the restructuring."""

    EDGE = TransitionEdge
    NODE = TransitionBlock

    def __init__(self, graph: Optional[DiGraph] = None, root: Optional[NODE] = None, conditions: Optional[ConditionHandler] = None):
        """
        Init a new transition cfg.

        graph -- The DiGraph contained in the cfg. Can be used to create initialized graphs.
        root -- The root node of the graph.
        conditions -- a condition handler, mapping symbols to conditions of Type Condition and z3-conditions.
        """
        super().__init__(graph, root)
        self.condition_handler: ConditionHandler = conditions if conditions else ConditionHandler()

    @classmethod
    def generate(cls, cfg: ControlFlowGraph) -> TransitionCFG:
        """A constructor that generates the transition cfg from a cfg."""
        transition_cfg = cls()
        if not cfg.nodes:
            return transition_cfg
        node_translation: Dict[BasicBlock, TransitionBlock] = transition_cfg._generate_nodes(cfg)

        for node in cfg:
            transition_cfg._process_node(node, cfg, node_translation)

        transition_cfg.root = node_translation[cfg.root]
        transition_cfg.refresh_edge_properties()

        return transition_cfg

    @property
    def logic_context(self):
        """Return the logic context associated with the graph."""
        return self.condition_handler.logic_context

    def add_node(self, block: NODE):
        """Add a node to the block, setting it as head if there is none defined."""
        assert isinstance(block, TransitionBlock)
        block._graph = self
        super(ClassifiedGraph, self).add_node(block)

    def collapse_region(self, nodes: Iterable[TransitionBlock], ast_node: AbstractSyntaxTreeNode) -> None:
        """
        This function collapse the region consisting of the nodes in 'nodes' into a single BasicBlock.
        The information about this region is saved in the abstract syntax tree of this node.

        :param nodes: The nodes of the region we want to collapse.
        :param ast_node: The abstract syntax tree of this region.
        """
        new_node = self.create_ast_block(ast_node)

        if self.root in nodes:
            self.root = new_node

        in_edges_current_region = set()
        out_edges_current_region = set()
        for node in nodes:
            in_edges_current_region.update([edge for edge in self.get_in_edges(node) if edge.source not in nodes])
            out_edges_current_region.update([edge for edge in self.get_out_edges(node) if edge.sink not in nodes])
        for edge in in_edges_current_region:
            new_edge = edge.copy(sink=new_node)
            assert new_edge not in self.edges, f"{edge.source} has two successors in the region, but each region is dominated by its head."
            self.add_edge(new_edge)
        for edge in out_edges_current_region:
            if (new_edge := self.get_edge(new_node, edge.sink)) in self.edges:
                new_edge.tag |= edge.tag
            else:
                new_edge = edge.copy(source=new_node)
                self.add_edge(new_edge)
        self.remove_nodes_from(nodes)

    def create_ast_block(self, ast: Optional[AbstractSyntaxTreeNode] = None) -> TransitionBlock:
        """Create a BasicBlock at an unique address."""
        address = -1
        addresses = {block.address for block in self}
        while address in addresses:
            address -= 1
        block = TransitionBlock(address, ast=ast)
        self.add_node(block)
        return block

    def substitute_block(self, replacee: TransitionBlock, replacement: TransitionBlock):
        """Substitute one BasicBlock with another, maintaining edges."""
        in_edges = self.get_in_edges(replacee)
        out_edges = self.get_out_edges(replacee)
        self.remove_node(replacee)
        self.add_node(replacement)
        for edge in in_edges:
            new_edge = edge.copy(sink=replacement)
            self.add_edge(new_edge)
        for edge in out_edges:
            new_edge = edge.copy(source=replacement)
            self.add_edge(new_edge)

    def substitute_edge(self, replacee: EDGE, replacement: EDGE):
        """Replace a rich edge with another edge."""
        self.remove_edge(replacee)
        self.add_edge(replacement)

    def refresh_edge_properties(self):
        """Updates the edge properties for the transition graph."""
        for edge, edge_property in self.classify_edges().items():
            edge.property = edge_property if edge_property in {EdgeProperty.back, EdgeProperty.retreating} else EdgeProperty.non_loop

    def _process_node(self, node: BasicBlock, cfg: ControlFlowGraph, node_transition: Dict[BasicBlock, TransitionBlock]) -> None:
        """
        Process the given node, annotating symbols at its outgoing edges and updating the condition map.
        Also, set the .ast field to the Code-node containing all instructions except for branches.
        """
        if node.condition == BasicBlock.ControlFlowType.indirect:
            self._process_switch_node(node, cfg, node_transition)
        elif node.condition == BasicBlock.ControlFlowType.conditional:
            self._process_conditional_node(node, cfg, node_transition)
        else:
            self._process_direct_node(node, cfg, node_transition)

    def _process_switch_node(self, node: BasicBlock, cfg: ControlFlowGraph, node_transition: Dict[BasicBlock, TransitionBlock]) -> None:
        """Process the given switch basic block by parsing the edge conditions, creating tags."""
        labels: Dict[int, ConditionSymbol] = {}
        jump_instruction = node.instructions[-1]
        assert isinstance(jump_instruction, IndirectBranch), f"The instruction {jump_instruction} must be an IndirectBranch."
        variable = jump_instruction.expression
        for v in set(condition for edge in cfg.get_out_edges(node) for condition in edge.cases):
            labels[v] = self.condition_handler.add_condition(Condition(operation=OperationType.equal, operands=[variable, v]))
        for edge in cfg.get_out_edges(node):
            tag = None
            if len(edge.cases) == 1:
                tag = labels[edge.cases[0]].symbol
            elif len(edge.cases) > 1:
                tag = LogicCondition.disjunction_of([labels[v].symbol for v in edge.cases])
            self.add_edge(TransitionEdge(node_transition[edge.source], node_transition[edge.sink], tag))

    def _process_direct_node(self, node: BasicBlock, cfg: ControlFlowGraph, node_transition: Dict[BasicBlock, TransitionBlock]) -> None:
        """Process the given unconditional block by marking all outgoing edges as unconditional."""
        for edge in cfg.get_out_edges(node):
            self.add_edge(TransitionEdge(node_transition[edge.source], node_transition[edge.sink], self.condition_handler.get_true_value()))

    def _process_conditional_node(
        self, node: BasicBlock, cfg: ControlFlowGraph, node_transition: Dict[BasicBlock, TransitionBlock]
    ) -> None:
        """Process the given conditional node by attributing its condition to its outgoing edges."""
        comparision = node.instructions[-1]
        assert isinstance(comparision, Branch), f"The instruction {comparision} must be a Branch."
        label = self.condition_handler.add_condition(comparision.condition)
        edge_tags = {BasicBlockEdgeCondition.true: label.symbol, BasicBlockEdgeCondition.false: ~label.symbol}
        for edge_data in cfg.get_out_edges(node):
            tag = edge_tags[edge_data.condition_type]
            self.add_edge(TransitionEdge(node_transition[edge_data.source], node_transition[edge_data.sink], tag))

    def _generate_nodes(self, cfg: ControlFlowGraph) -> Dict[BasicBlock, TransitionBlock]:
        node_translation: Dict[BasicBlock, TransitionBlock] = dict()
        for node in cfg:
            if node.condition == BasicBlock.ControlFlowType.direct:
                new_node = TransitionBlock(node.address, CodeNode(node.instructions.copy(), self.condition_handler.get_true_value()))
            else:
                new_node = TransitionBlock(node.address, CodeNode(node.instructions[:-1].copy(), self.condition_handler.get_true_value()))
            node_translation[node] = new_node
            self.add_node(new_node)
        return node_translation
