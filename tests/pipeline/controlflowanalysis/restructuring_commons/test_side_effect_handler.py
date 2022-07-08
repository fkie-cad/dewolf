from decompiler.pipeline.controlflowanalysis.restructuring_commons.side_effect_handling.side_effect_handler import SideEffectHandler
from decompiler.structures.ast.ast_nodes import CodeNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition


def test_create_ast_from_code_node():
    ast = AbstractSyntaxTree(
        root=CodeNode([], reaching_condition=LogicCondition.initialize_true(LogicCondition.generate_new_context())), condition_map=dict()
    )
    side_effect_handler = SideEffectHandler(ast)
    side_effect_handler._create_cfg_from_ast()
    assert len(side_effect_handler._data_graph) == 1