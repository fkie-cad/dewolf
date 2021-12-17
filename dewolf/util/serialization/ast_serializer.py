from typing import Dict

from dewolf.structures.ast.ast_nodes import SeqNode, SwitchNode
from dewolf.structures.ast.syntaxtree import AbstractSyntaxTree
from dewolf.structures.logic.logic_condition import LogicCondition
from dewolf.util.serialization.astnode_serializer import AstNodeSerializer
from dewolf.util.serialization.interface import Serializer
from dewolf.util.serialization.pseudo_serializer import PseudoSerializer


class AstSerializer(Serializer):
    """Serializes and Deserializes AbstractSyntaxTrees to and from a dict representation."""

    def __init__(self):
        """Init an AstSerializer and all off its direct sub serializers."""
        self._node_serializer = AstNodeSerializer()
        self._pseudo_serializer = PseudoSerializer()

    def serialize(self, ast: AbstractSyntaxTree) -> Dict:
        """Serialize the given AST into a dict representation."""
        return {
            "type": "ast",
            "root_id": id(ast.root),
            "nodes": [self._node_serializer.serialize(node) for node in ast.pre_order()],
            "edges": [(id(source), id(sink)) for source, sink in ast.edges if source is not ast._root],
            "condition_map": {k.serialize(): self._pseudo_serializer.serialize(v) for (k, v) in ast.condition_map.items()},
            "code_node_reachability": [(id(source), id(sink)) for source, sink in ast._code_node_reachability_graph.edges],
        }

    def deserialize(self, data: Dict) -> AbstractSyntaxTree:
        """Deserialize the given projection of an AST."""
        id_to_node = {node["id"]: self._node_serializer.deserialize(node) for node in data["nodes"]}
        deserialized_edges = [(id_to_node[source], id_to_node[sink]) for source, sink in data["edges"]]
        ast = AbstractSyntaxTree(
            root=id_to_node[data["root_id"]],
            condition_map={
                LogicCondition.deserialize(k, self._node_serializer.new_context): self._pseudo_serializer.deserialize(v)
                for (k, v) in data["condition_map"].items()
            },
        )
        ast._add_nodes_from(id_to_node.values())
        ast._add_edges_from(deserialized_edges)
        ast._code_node_reachability_graph.add_reachability_from(
            ((id_to_node[source], id_to_node[sink]) for source, sink in data["code_node_reachability"])
        )
        for node in ast.nodes:
            if isinstance(node, SwitchNode):
                node.sort_cases()
            elif isinstance(node, SeqNode):
                node.sort_children()
        return ast
