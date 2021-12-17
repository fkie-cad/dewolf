""" Tests for the AbstractSyntaxTree base class."""
from itertools import combinations

from dewolf.structures.ast.ast_comparator import ASTComparator
from dewolf.structures.ast.ast_nodes import CodeNode, ConditionNode, SeqNode, VirtualRootNode
from dewolf.structures.ast.condition_symbol import ConditionHandler, ConditionSymbol
from dewolf.structures.ast.syntaxforest import AbstractSyntaxForest
from dewolf.structures.graphs.classifiedgraph import EdgeProperty
from dewolf.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG, TransitionEdge
from dewolf.structures.logic.logic_condition import LogicCondition, PseudoLogicCondition
from dewolf.structures.pseudo import Assignment, BinaryOperation, Break, Condition, Constant, Integer, OperationType, Return, Variable


def var(name: str) -> Variable:
    return Variable(name, Integer.int32_t())


def const(val: int) -> Constant:
    return Constant(val, Integer.int32_t())


def test_create_empty_ast():
    """Create an empty AS Forest"""
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    assert (
        len(asforest) == 1
        and asforest.nodes == (VirtualRootNode(asforest.condition_handler.get_true_value()),)
        and asforest.condition_handler == ConditionHandler()
    )


def test_add_empty_code_node():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node = asforest.add_code_node()
    assert len(asforest) == 2 and asforest.condition_handler == ConditionHandler()
    assert (
        len(roots := asforest.get_roots) == 2
        and code_node in roots
        and VirtualRootNode(asforest.condition_handler.get_true_value()) in roots
    )


def test_create_add_code_node_with():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())

    assignment_a = [Assignment(var("a"), const(2))]
    assignments_a_b = assignment_a + [Assignment(var("b"), const(5))]
    code_node_1 = asforest.add_code_node(assignment_a.copy())
    true_condtition = asforest.condition_handler.get_true_value()

    assert len(asforest) == 2 and code_node_1 == CodeNode(assignment_a.copy(), true_condtition.copy())
    assert len(roots := asforest.get_roots) == 2 and code_node_1 in roots and VirtualRootNode(true_condtition.copy()) in roots

    code_node_2 = asforest.add_code_node(assignments_a_b.copy())
    assert len(asforest) == 3 and code_node_2 == CodeNode(assignments_a_b.copy(), true_condtition.copy())
    assert (
        len(roots := asforest.get_roots) == 3
        and code_node_1 in roots
        and code_node_2 in roots
        and VirtualRootNode(true_condtition.copy()) in roots
    )


def test_add_code_node():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    asforest.add_code_node(code_node_1 := asforest.factory.create_code_node([]))
    assert len(asforest) == 2 and set(asforest.get_roots) == {code_node_1, asforest._current_root}

    asforest.add_code_node(
        code_node_2 := CodeNode(
            [Assignment(var("a"), const(2)), Assignment(var("b"), const(5))], asforest.condition_handler.get_true_value()
        )
    )
    assert len(asforest) == 3 and asforest.condition_handler == ConditionHandler()
    assert set(asforest.get_roots) == {code_node_1, code_node_2, asforest._current_root}


def test_combine_break_nodes():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = asforest.add_code_node([Break()])
    code_node_1.reaching_condition = LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
    code_node_2 = asforest.add_code_node([Break()])
    code_node_3 = asforest.add_code_node([Break()])
    code_node_3.reaching_condition = LogicCondition.initialize_symbol("e", asforest.factory.logic_context)
    code_node_4 = asforest.add_code_node([Assignment(var("d"), const(9))])
    code_node_5 = asforest.add_code_node([Assignment(var("e"), const(6))])
    code_node_6 = asforest.add_code_node([Break()])
    code_node_6.reaching_condition = LogicCondition.initialize_symbol("f", asforest.factory.logic_context)
    seq_node = asforest.factory.create_seq_node()
    asforest._add_node(seq_node)
    condition_2 = asforest._add_condition_node_with(LogicCondition.initialize_symbol("b", asforest.factory.logic_context), code_node_2)
    condition_2.reaching_condition = LogicCondition.initialize_symbol("c", asforest.factory.logic_context)
    condition_3 = asforest._add_condition_node_with(LogicCondition.initialize_symbol("d", asforest.factory.logic_context), code_node_3)
    asforest._add_edges_from(
        (
            (seq_node, code_node_1),
            (seq_node, condition_2),
            (seq_node, condition_3),
            (seq_node, code_node_4),
            (seq_node, code_node_5),
            (seq_node, code_node_6),
        )
    )
    asforest._code_node_reachability_graph.add_reachability_from(
        combinations([code_node_1, code_node_2, code_node_3, code_node_4, code_node_5, code_node_6], 2)
    )
    seq_node.sort_children()

    assert asforest.combine_break_nodes(seq_node, set()) is None

    node = asforest.combine_break_nodes(seq_node, {code_node_1})
    assert isinstance(node, CodeNode) and node == code_node_1 and len(seq_node.children) == 6

    condition_node = asforest.combine_break_nodes(seq_node, {code_node_1, condition_2, condition_3})
    assert (
        isinstance(condition_node, ConditionNode)
        and seq_node.children == (condition_node, code_node_4, code_node_5, code_node_6)
        and condition_node.true_branch_child == CodeNode([Break()], asforest.condition_handler.get_true_value())
        and condition_node.false_branch is None
        and condition_node.condition.is_equal_to(
            (
                LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
                | LogicCondition.initialize_symbol("b", asforest.factory.logic_context)
                | LogicCondition.initialize_symbol("d", asforest.factory.logic_context)
            )
            & (
                LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
                | LogicCondition.initialize_symbol("b", asforest.factory.logic_context)
                | LogicCondition.initialize_symbol("e", asforest.factory.logic_context)
            )
            & (
                LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
                | LogicCondition.initialize_symbol("c", asforest.factory.logic_context)
                | LogicCondition.initialize_symbol("d", asforest.factory.logic_context)
            )
            & (
                LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
                | LogicCondition.initialize_symbol("c", asforest.factory.logic_context)
                | LogicCondition.initialize_symbol("e", asforest.factory.logic_context)
            )
        )
    )


def test_combine_break_nodes_true():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = asforest.add_code_node([Assignment(var("d"), const(9))])
    code_node_2 = asforest.add_code_node([Assignment(var("e"), const(6))])
    code_node_3 = asforest.add_code_node([Break()])
    code_node_3.reaching_condition = LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
    code_node_4 = asforest.add_code_node([Break()])
    seq_node = asforest.factory.create_seq_node()
    asforest._add_node(seq_node)
    condition_4 = asforest._add_condition_node_with(~LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node_4)
    asforest._add_edges_from(
        (
            (seq_node, code_node_1),
            (seq_node, code_node_2),
            (seq_node, code_node_3),
            (seq_node, condition_4),
        )
    )
    asforest._code_node_reachability_graph.add_reachability_from(combinations([code_node_1, code_node_2, code_node_3, code_node_4], 2))
    seq_node.sort_children()

    code_node = asforest.combine_break_nodes(seq_node, {code_node_3, condition_4})
    assert code_node.is_break_node and seq_node.children == (code_node_1, code_node_2, code_node)


def test_replace_condition_node_by_single_branch_no_parent():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node = asforest.add_code_node([Assignment(var("e"), const(9))])
    condition = asforest._add_condition_node_with(LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node)
    asforest.replace_condition_node_by_single_branch(condition)

    assert set(asforest.nodes) == {code_node, asforest._current_root}


def test_replace_condition_node_by_single_branch():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = asforest.add_code_node([Assignment(var("d"), const(9))])
    code_node_2 = asforest.add_code_node([Assignment(var("e"), const(9))])
    seq_node = asforest.factory.create_seq_node()
    asforest._add_node(seq_node)
    condition = asforest._add_condition_node_with(LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node_2)
    asforest._add_edges_from(((seq_node, code_node_1), (seq_node, condition)))
    asforest._code_node_reachability_graph.add_reachability(code_node_1, code_node_2)
    seq_node.sort_children()

    asforest.replace_condition_node_by_single_branch(condition)

    assert set(asforest.get_roots) == {seq_node, asforest._current_root} and seq_node.children == (code_node_1, code_node_2)


def test_extract_branch_from_condition_node_no_parent():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = asforest.add_code_node([Assignment(var("e"), const(9))])
    code_node_2 = asforest.add_code_node([Break()])
    condition = asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node_1, code_node_2
    )

    asforest.extract_branch_from_condition_node(condition, condition.true_branch)

    assert (
        len(asforest) == 6
        and len(asforest.get_roots) == 2
        and any(not isinstance(seq_node := root, VirtualRootNode) for root in asforest.get_roots)
        and isinstance(seq_node, SeqNode)
        and seq_node.children == (condition, code_node_1)
        and condition.condition == ~LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
        and condition.true_branch_child == code_node_2
        and condition.false_branch is None
        and asforest._code_node_reachability_graph.reaches(code_node_2, code_node_1)
    )


def test_extract_branch_from_condition_node_with_parent():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = asforest.add_code_node([Assignment(var("e"), const(9))])
    code_node_2 = asforest.add_code_node([Break()])
    code_node_3 = asforest.add_code_node([Assignment(var("f"), const(9))])
    condition = asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node_1, code_node_2
    )
    parent_condition = asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("b", asforest.factory.logic_context), condition, code_node_3
    )

    asforest.extract_branch_from_condition_node(condition, condition.true_branch)

    assert (
        len(asforest) == 10
        and set(asforest.get_roots) == {parent_condition, asforest._current_root}
        and isinstance(seq_node := parent_condition.true_branch_child, SeqNode)
        and parent_condition.false_branch_child == code_node_3
        and seq_node.children == (condition, code_node_1)
        and condition.condition == ~LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
        and condition.true_branch_child == code_node_2
        and condition.false_branch is None
        and asforest._code_node_reachability_graph.reaches(code_node_2, code_node_1)
    )


def test_extract_branch_from_condition_node_with_seq_node_parent():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = asforest.add_code_node([Assignment(var("e"), const(9))])
    code_node_2 = asforest.add_code_node([Break()])
    code_node_3 = asforest.add_code_node([Assignment(var("f"), const(9))])
    condition = asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node_2, code_node_1
    )
    seq_node = asforest.factory.create_seq_node()
    asforest._add_node(seq_node)
    asforest._add_edges_from(((seq_node, condition), (seq_node, code_node_3)))
    asforest._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_3), (code_node_2, code_node_3)))

    asforest.extract_branch_from_condition_node(condition, condition.false_branch)

    assert (
        len(asforest) == 7
        and set(asforest.get_roots) == {seq_node, asforest._current_root}
        and seq_node.children == (condition, code_node_1, code_node_3)
        and condition.condition == LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
        and condition.true_branch_child == code_node_2
        and condition.false_branch is None
        and asforest._code_node_reachability_graph.reaches(code_node_2, code_node_1)
        and asforest._code_node_reachability_graph.reaches(code_node_1, code_node_3)
        and asforest._code_node_reachability_graph.reaches(code_node_2, code_node_3)
    )


def test_substitute_branches_by():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = asforest.add_code_node([Assignment(var("u"), const(9))])
    code_node_2 = asforest.add_code_node([Break()])
    code_node_3 = asforest.add_code_node([Assignment(var("v"), const(9))])
    code_node_4 = asforest.add_code_node([Assignment(var("w"), const(9))])
    code_node_5 = asforest.add_code_node([Assignment(var("x"), const(9))])
    condition = asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node_2, code_node_3
    )
    seq_node = asforest.factory.create_seq_node()
    asforest._add_node(seq_node)
    asforest._add_edges_from(((seq_node, code_node_1), (seq_node, condition), (seq_node, code_node_4)))
    asforest._code_node_reachability_graph.add_reachability_from(
        ((code_node_1, code_node_3), (code_node_1, code_node_2), (code_node_1, code_node_4), (code_node_3, code_node_4))
    )
    seq_node.sort_children()
    branch = asforest._add_condition_node_with(LogicCondition.initialize_symbol("b", asforest.factory.logic_context), code_node_5)

    asforest.substitute_branches_by(branch, condition)

    assert (
        len(asforest) == 9
        and set(asforest.get_roots) == {seq_node, asforest._current_root}
        and seq_node.children == (code_node_1, condition, code_node_4)
        and condition.true_branch_child == branch
        and condition.false_branch is None
        and asforest._code_node_reachability_graph.reaches(code_node_1, code_node_5)
        and asforest._code_node_reachability_graph.reaches(code_node_1, code_node_4)
        and asforest._code_node_reachability_graph.reaches(code_node_5, code_node_4)
    )


def test_extract_all_breaks_from_condition_node():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = asforest.add_code_node([Assignment(var("u"), const(9))])
    code_node_2 = asforest.add_code_node([Break()])
    code_node_3 = asforest.add_code_node([Assignment(var("v"), const(9)), Break()])
    condition_node = asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node_2, code_node_3
    )
    seq_node = asforest.factory.create_seq_node()
    asforest._add_node(seq_node)
    asforest._add_edges_from(((seq_node, code_node_1), (seq_node, condition_node)))
    asforest._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_3), (code_node_1, code_node_2)))
    seq_node.sort_children()

    asforest.extract_all_breaks_from_condition_node(condition_node)

    assert (
        len(asforest) == 7
        and code_node_3.instructions == [Assignment(var("v"), const(9))]
        and seq_node.children == (code_node_1, condition_node, CodeNode([Break()], asforest.condition_handler.get_true_value()))
        and condition_node.true_branch_child == code_node_3
        and condition_node.false_branch is None
        and condition_node.condition == ~LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
        and asforest._code_node_reachability_graph.reaches(code_node_3, seq_node.children[2])
    )


def test_resolve_unresolved_reaching_conditions():
    asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = asforest.add_code_node([Assignment(var("u"), const(9))])
    code_node_1.reaching_condition = LogicCondition.initialize_symbol("R2", asforest.factory.logic_context)
    code_node_2 = asforest.add_code_node([Break()])
    code_node_3 = asforest.add_code_node([Assignment(var("v"), const(9)), Break()])
    code_node_3.reaching_condition = LogicCondition.initialize_symbol("R3", asforest.factory.logic_context)
    condition_node = asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node_2, code_node_3
    )
    seq_node = SeqNode(LogicCondition.initialize_symbol("R1", asforest.factory.logic_context))
    asforest._add_node(seq_node)
    asforest._add_edges_from(((seq_node, code_node_1), (seq_node, condition_node)))
    asforest._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_3), (code_node_1, code_node_2)))
    seq_node.sort_children()

    asforest.resolve_unresolved_reaching_conditions()

    resulting_asforest = AbstractSyntaxForest(condition_handler=ConditionHandler())
    code_node_1 = resulting_asforest.add_code_node([Assignment(var("u"), const(9))])
    code_node_2 = resulting_asforest.add_code_node([Break()])
    code_node_3 = resulting_asforest.add_code_node([Assignment(var("v"), const(9)), Break()])
    seq_node = asforest.factory.create_seq_node()
    resulting_asforest._add_node(seq_node)
    condition_node_r1 = resulting_asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("R1", asforest.factory.logic_context), seq_node
    )
    condition_node_r2 = resulting_asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("R2", asforest.factory.logic_context), code_node_1
    )
    condition_node_r3 = resulting_asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("R3", asforest.factory.logic_context), code_node_3
    )
    condition_node = resulting_asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asforest.factory.logic_context), code_node_2, condition_node_r3
    )
    resulting_asforest._add_edges_from(((seq_node, condition_node_r2), (seq_node, condition_node)))
    resulting_asforest._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_3), (code_node_1, code_node_2)))
    seq_node.sort_children()

    assert (
        len(asforest.get_roots) == 2
        and any(root == condition_node_r1 for root in asforest.get_roots)
        and ASTComparator.compare(asforest, resulting_asforest)
    )


def test_generate_from_code_nodes():
    context = LogicCondition.generate_new_context()
    true_value = LogicCondition.initialize_true(context)
    t_cfg = TransitionCFG()
    t_cfg.add_nodes_from(
        vertices := [
            TransitionBlock(0, CodeNode([Assignment(var("i"), Constant(0)), Assignment(var("x"), Constant(42))], true_value.copy())),
            TransitionBlock(1, CodeNode([], true_value.copy())),
            TransitionBlock(
                2,
                CodeNode(
                    [
                        Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), Constant(1)])),
                        Assignment(var("x"), BinaryOperation(OperationType.minus, [var("x"), var("i")])),
                    ],
                    true_value.copy(),
                ),
            ),
            TransitionBlock(3, CodeNode([Return([var("x")])], true_value.copy())),
        ]
    )
    t_cfg.add_edges_from(
        [
            TransitionEdge(vertices[0], vertices[1], LogicCondition.initialize_true(context), EdgeProperty.non_loop),
            TransitionEdge(vertices[1], vertices[2], LogicCondition.initialize_symbol("x1", context), EdgeProperty.non_loop),
            TransitionEdge(vertices[1], vertices[3], ~LogicCondition.initialize_symbol("x1", context), EdgeProperty.non_loop),
            TransitionEdge(vertices[2], vertices[1], LogicCondition.initialize_true(context), EdgeProperty.back),
        ]
    )
    t_cfg.condition_handler = ConditionHandler(
        {LogicCondition.initialize_symbol("x1", context): Condition(OperationType.not_equal, [var("i"), Constant(3)])}
    )

    asforest = AbstractSyntaxForest.generate_from_code_nodes([node.ast for node in vertices], t_cfg.condition_handler)

    assert (
        len(asforest) == 5
        and set(asforest.nodes) == {node.ast for node in vertices}.union({asforest._current_root})
        and asforest.condition_handler == t_cfg.condition_handler
    )


def test_construct_initial_ast_for_region():
    context = LogicCondition.generate_new_context()
    asforest = AbstractSyntaxForest(
        ConditionHandler({LogicCondition.initialize_symbol("x1", context): Condition(OperationType.not_equal, [var("i"), Constant(3)])})
    )
    code_node_0 = asforest.add_code_node([Assignment(var("i"), Constant(0)), Assignment(var("x"), Constant(42))])
    code_node_1 = asforest.add_code_node()
    code_node_2 = asforest.add_code_node(
        [
            Assignment(var("i"), BinaryOperation(OperationType.plus, [var("i"), Constant(1)])),
            Assignment(var("x"), BinaryOperation(OperationType.minus, [var("x"), var("i")])),
        ]
    )
    code_node_3 = asforest.add_code_node([Return([var("x")])])
    transition_blocks = [
        TransitionBlock(0, code_node_0),
        TransitionBlock(1, code_node_1),
        TransitionBlock(2, code_node_2),
        TransitionBlock(3, code_node_3),
    ]

    reaching_conditions = {
        transition_blocks[1]: LogicCondition.initialize_true(context),
        transition_blocks[2]: LogicCondition.initialize_symbol("a", asforest.factory.logic_context),
        transition_blocks[3]: ~LogicCondition.initialize_symbol("a", asforest.factory.logic_context),
    }
    reachability_sets = {
        transition_blocks[1]: {transition_blocks[2], transition_blocks[3]},
        transition_blocks[2]: set(),
        transition_blocks[3]: set(),
    }
    seq_node = asforest.construct_initial_ast_for_region(reaching_conditions, reachability_sets)

    assert isinstance(seq_node, SeqNode) and len(seq_node.children) == 3
    assert (
        code_node_1.reaching_condition == LogicCondition.initialize_true(context)
        and code_node_2.reaching_condition == LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
        and code_node_3.reaching_condition == ~LogicCondition.initialize_symbol("a", asforest.factory.logic_context)
    )
    assert seq_node.children == (code_node_1, code_node_2, code_node_3) or seq_node.children == (code_node_1, code_node_3, code_node_2)
    assert (
        len(asforest._code_node_reachability_graph.nodes) == 4
        and len(asforest._code_node_reachability_graph.edges) == 2
        and asforest._code_node_reachability_graph.reaches(code_node_1, code_node_2)
        and asforest._code_node_reachability_graph.reaches(code_node_1, code_node_3)
    )


def test_combine_condition_nodes():
    context = LogicCondition.generate_new_context()
    condition_handler = ConditionHandler(
        {
            LogicCondition.initialize_symbol("a", context): ConditionSymbol(
                cond := Condition(OperationType.less_or_equal, [var("a"), Constant(5, Integer.int32_t())]),
                LogicCondition.initialize_symbol("a", context),
                ps_a := PseudoLogicCondition.initialize_from_condition(cond, context),
            ),
            LogicCondition.initialize_symbol("b", context): ConditionSymbol(
                cond := Condition(OperationType.less_or_equal, [var("b"), Constant(5, Integer.int32_t())]),
                LogicCondition.initialize_symbol("b", context),
                ps_b := PseudoLogicCondition.initialize_from_condition(cond, context),
            ),
            LogicCondition.initialize_symbol("c", context): ConditionSymbol(
                cond := Condition(OperationType.less_or_equal, [var("c"), Constant(5, Integer.int32_t())]),
                LogicCondition.initialize_symbol("c", context),
                ps_c := PseudoLogicCondition.initialize_from_condition(cond, context),
            ),
            LogicCondition.initialize_symbol("RC", context): ConditionSymbol(
                cond := Condition(OperationType.less_or_equal, [var("RC"), Constant(5, Integer.int32_t())]),
                LogicCondition.initialize_symbol("RC", context),
                ps_rc := PseudoLogicCondition.initialize_from_condition(cond, context),
            ),
        }
    )
    asforest = AbstractSyntaxForest(condition_handler)
    code_node_1 = asforest._add_code_node([Assignment(var("d"), const(9))])
    code_node_2 = asforest._add_code_node([Assignment(var("e"), const(9))])
    code_node_3 = asforest._add_code_node([Assignment(var("f"), const(9))])
    seq_node = asforest.factory.create_seq_node()
    asforest._add_node(seq_node)
    not_simplifiable_condition = asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("c", asforest.factory.logic_context), code_node_2, code_node_3
    )
    nested_condition = asforest._add_condition_node_with(
        LogicCondition.initialize_symbol("b", asforest.factory.logic_context), false_branch=not_simplifiable_condition
    )
    nested_condition.reaching_condition = LogicCondition.initialize_symbol("RC", context)
    condition = asforest._add_condition_node_with(LogicCondition.initialize_symbol("a", asforest.factory.logic_context), nested_condition)
    asforest._add_edges_from(((seq_node, code_node_1), (seq_node, condition)))
    asforest._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_2), (code_node_1, code_node_3)))
    seq_node.sort_children()

    check = asforest.condition_handler.get_z3_condition_map() == {
        LogicCondition.initialize_symbol("a", asforest.factory.logic_context): ps_a,
        LogicCondition.initialize_symbol("b", asforest.factory.logic_context): ps_b,
        LogicCondition.initialize_symbol("c", asforest.factory.logic_context): ps_c,
        LogicCondition.initialize_symbol("RC", asforest.factory.logic_context): ps_rc,
    }
    asforest.combine_cascading_single_branch_conditions()

    assert len(asforest) == 10 and condition.condition == LogicCondition.initialize_symbol(
        "a", asforest.factory.logic_context
    ) & ~LogicCondition.initialize_symbol("b", asforest.factory.logic_context) & LogicCondition.initialize_symbol(
        "RC", asforest.factory.logic_context
    )
