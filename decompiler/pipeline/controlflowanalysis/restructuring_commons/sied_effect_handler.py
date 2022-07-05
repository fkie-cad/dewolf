from typing import Dict

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CodeNode, ConditionNode, LoopNode, SwitchNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph


class SideEffectHandler:

    def __init__(self, ast: AbstractSyntaxTree):
        self._ast: AbstractSyntaxTree = ast
        self._cfg = ControlFlowGraph()

    @classmethod
    def resolve(cls, ast: AbstractSyntaxTree):
        side_effect_handler = cls(ast)
        side_effect_handler._create_cfg_from_ast()

    def _create_cfg_from_ast(self):
        translation_dict: Dict[AbstractSyntaxTreeNode, int] = dict()
        for idx, ast_node in enumerate(self._ast.nodes):
            if isinstance(ast_node, CodeNode):
                self._cfg.add_node(BasicBlock(idx, ast_node.instructions))
            elif isinstance(ast_node, ConditionNode):
                self._cfg.add_node(BasicBlock(idx, [ast_node.condition]))
            elif isinstance(ast_node, SwitchNode):
                self._cfg.add_node(BasicBlock(idx, [ast_node.expression]))
            elif isinstance(ast_node, LoopNode):
                self._cfg.add_node(BasicBlock(idx, []))
