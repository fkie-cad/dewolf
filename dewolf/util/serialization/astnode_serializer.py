"""Module implementing the serialization of AbstractSyntaxTreeNode subclasses."""
from abc import ABC
from typing import Dict, Optional

from dewolf.structures.ast.ast_nodes import (
    AbstractSyntaxTreeNode,
    CaseNode,
    CodeNode,
    ConditionNode,
    DoWhileLoopNode,
    FalseNode,
    ForLoopNode,
    LoopNode,
    SeqNode,
    SwitchNode,
    TrueNode,
    WhileLoopNode,
)

from ...structures.logic.logic_condition import LogicCondition
from .interface import Serializer, SerializerGroup, T
from .pseudo_serializer import PseudoSerializer


class AstNodeSerializer(SerializerGroup):
    """Serializes and Deserializes AST nodes to and from a dict representation."""

    def __init__(self):
        """Init the serializer utilizing the default ast node serializers."""
        super(AstNodeSerializer, self).__init__()
        self._node_to_id: Dict[AbstractSyntaxTreeNode, int] = {}
        self._id_to_node: Dict[int, AbstractSyntaxTreeNode] = {}
        self.register(SeqNode, SeqNodeSerializer(self))
        self.register(CodeNode, CodeNodeSerializer(self))
        self.register(ConditionNode, ConditionNodeSerializer(self))
        self.register(TrueNode, TrueNodeSerializer(self))
        self.register(FalseNode, FalseNodeSerializer(self))
        self.register(WhileLoopNode, WhileLoopNodeSerializer(self))
        self.register(DoWhileLoopNode, DoWhileLoopNodeSerializer(self))
        self.register(ForLoopNode, ForLoopNodeSerializer(self))
        self.register(SwitchNode, SwitchNodeSerializer(self))
        self.register(CaseNode, CaseNodeSerializer(self))

    def get_node(self, node_id: int) -> Optional[AbstractSyntaxTreeNode]:
        return self._id_to_node[node_id]

    def get_id(self, node: AbstractSyntaxTreeNode) -> int:
        node_id = self._node_to_id.setdefault(node, id(node))
        self._id_to_node[node_id] = node
        return node_id


class AbstractSyntaxTreeNodeSerializer(Serializer, ABC):
    """Base class to group functionality shared among ast node serializers."""

    def __init__(self, serializer_group: AstNodeSerializer):
        """Create a new instance linking the parent get_node function."""
        self._group = serializer_group
        self._pseudo = PseudoSerializer()

    def serialize(self, node: AbstractSyntaxTreeNode) -> Dict:
        """Serialize data common to all node types."""
        return {"id": self._group.get_id(node), "type": node.__class__.__name__, "rc": node.reaching_condition.serialize()}


class SeqNodeSerializer(AbstractSyntaxTreeNodeSerializer):
    """Class implementing the serialization of SeqNodes in an AST."""

    def serialize(self, node: SeqNode) -> Dict:
        return super().serialize(node)

    def deserialize(self, data: dict) -> SeqNode:
        return SeqNode(reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context))


class CodeNodeSerializer(AbstractSyntaxTreeNodeSerializer):
    """Class implementing the serialization of CodeNodes in an AST."""

    def serialize(self, node: CodeNode) -> Dict:
        data = super().serialize(node)
        data.update({"instructions": [self._pseudo.serialize(instruction) for instruction in node.instructions]})
        return data

    def deserialize(self, data: dict) -> CodeNode:
        return CodeNode(
            stmts=[self._pseudo.deserialize(instruction) for instruction in data["instructions"]],
            reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context),
        )


class ConditionNodeSerializer(AbstractSyntaxTreeNodeSerializer):
    """Class implementing the serialization of ConditionNodes in an AST."""

    def serialize(self, node: ConditionNode) -> Dict:
        data = super().serialize(node)
        data.update({"condition": node.condition.serialize()})
        return data

    def deserialize(self, data: dict) -> ConditionNode:
        return ConditionNode(
            condition=LogicCondition.deserialize(data["condition"], self._group.new_context),
            reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context),
        )


class TrueNodeSerializer(AbstractSyntaxTreeNodeSerializer):
    """Class implementing the serialization of TrueNodes in an AST."""

    def serialize(self, node: TrueNode) -> Dict:
        return super().serialize(node)

    def deserialize(self, data: Dict) -> T:
        return TrueNode(reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context))


class FalseNodeSerializer(AbstractSyntaxTreeNodeSerializer):
    """Class implementing the serialization of FalseNodes in an AST."""

    def serialize(self, node: TrueNode) -> Dict:
        return super().serialize(node)

    def deserialize(self, data: Dict) -> T:
        return FalseNode(reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context))


class LoopNodeSerializer(AbstractSyntaxTreeNodeSerializer):
    """Class implementing the serialization of LoopNodes in an AST."""

    def serialize(self, node: LoopNode) -> Dict:
        data = super().serialize(node)
        data.update({"condition": node.condition.serialize()})
        return data

    def deserialize(self, data: dict) -> T:
        pass


class WhileLoopNodeSerializer(LoopNodeSerializer):
    """Class implementing the serialization of WhileLoopNodes in an AST."""

    def serialize(self, node: WhileLoopNode) -> Dict:
        return super().serialize(node)

    def deserialize(self, data: dict) -> WhileLoopNode:
        return WhileLoopNode(
            condition=LogicCondition.deserialize(data["condition"], self._group.new_context),
            reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context),
        )


class DoWhileLoopNodeSerializer(LoopNodeSerializer):
    """Class implementing the serialization of DoWhileLoopNodes in an AST."""

    def serialize(self, node: DoWhileLoopNode) -> Dict:
        return super().serialize(node)

    def deserialize(self, data: dict) -> DoWhileLoopNode:
        return DoWhileLoopNode(
            condition=LogicCondition.deserialize(data["condition"], self._group.new_context),
            reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context),
        )


class ForLoopNodeSerializer(LoopNodeSerializer):
    """Class implementing the serialization of ForLoopNodes in an AST."""

    def serialize(self, node: ForLoopNode) -> Dict:
        data = super().serialize(node)
        data.update(
            {
                "declaration": self._pseudo.serialize(node.declaration),
                "modification": self._pseudo.serialize(node.modification),
            }
        )
        return data

    def deserialize(self, data: dict) -> ForLoopNode:
        return ForLoopNode(
            declaration=self._pseudo.deserialize(data["declaration"]),
            condition=LogicCondition.deserialize(data["condition"], self._group.new_context),
            modification=self._pseudo.deserialize(data["modification"]),
            reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context),
        )


class SwitchNodeSerializer(AbstractSyntaxTreeNodeSerializer):
    """Class implementing the serialization of SwitchNodes in an AST."""

    def serialize(self, node: SwitchNode) -> Dict:
        data = super().serialize(node)
        data.update({"expression": self._pseudo.serialize(node.expression)})
        return data

    def deserialize(self, data: dict) -> SwitchNode:
        return SwitchNode(
            expression=self._pseudo.deserialize(data["expression"]),
            reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context),
        )


class CaseNodeSerializer(AbstractSyntaxTreeNodeSerializer):
    """Class implementing the serialization of CaseNodes in an AST."""

    def serialize(self, node: CaseNode) -> Dict:
        data = super().serialize(node)
        data.update(
            {
                "expression": self._pseudo.serialize(node.expression),
                "constant": self._pseudo.serialize(node.constant),
                "break_case": node.break_case,
            }
        )
        return data

    def deserialize(self, data: dict) -> CaseNode:
        return CaseNode(
            expression=self._pseudo.deserialize(data["expression"]),
            constant=self._pseudo.deserialize(data["constant"]),
            reaching_condition=LogicCondition.deserialize(data["rc"], self._group.new_context),
            break_case=data["break_case"],
        )
