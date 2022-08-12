from decompiler.pipeline.controlflowanalysis.restructuring_commons.side_effect_handling.data_graph import DataGraph
from decompiler.pipeline.controlflowanalysis.restructuring_commons.side_effect_handling.side_effect_handler import SideEffectHandler
from decompiler.structures.ast.ast_nodes import CodeNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition


def test_create_ast_from_code_node():
    ast = AbstractSyntaxTree(
        root=CodeNode([], reaching_condition=LogicCondition.initialize_true(LogicCondition.generate_new_context())), condition_map=dict()
    )
    data_graph = DataGraph.generate_from_ast(ast)
    assert len(data_graph) == 1
