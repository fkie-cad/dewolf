""" Tests for the AbstractSyntaxTree base class."""

from itertools import combinations

from decompiler.structures.ast.syntaxforest import AbstractSyntaxInterface
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Assignment, Break, Constant, Integer, Variable


def var(name: str) -> Variable:
    return Variable(name, Integer.int32_t())


def const(val: int) -> Constant:
    return Constant(val, Integer.int32_t())


def test_create_empty_ast():
    """Create an empty AS Graph"""
    asgraph = AbstractSyntaxInterface()
    assert len(asgraph) == 0


def test_construct_endless_loop_with_body():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("a"), const(2))])

    loop = asgraph.add_endless_loop_with_body(code_node_1)

    assert asgraph.edges == ((loop, code_node_1),) and len(asgraph.nodes) == 2 and asgraph.get_roots == (loop,)


def test_substitute_loop_node_no_parent():
    asgraph = AbstractSyntaxInterface()
    code_node = asgraph._add_code_node([Assignment(var("a"), const(2))])
    loop = asgraph.add_endless_loop_with_body(code_node)
    replacement_loop = asgraph.factory.create_while_loop_node(
        condition=LogicCondition.initialize_symbol("a", asgraph.factory.logic_context)
    )

    asgraph.substitute_loop_node(loop, replacement_loop)

    assert asgraph.edges == ((replacement_loop, code_node),) and len(asgraph.nodes) == 2 and asgraph.get_roots == (replacement_loop,)


def test_substitute_loop_node_with_parent():
    asgraph = AbstractSyntaxInterface()
    code_node = asgraph._add_code_node([Assignment(var("a"), const(2))])
    inner_loop = asgraph.add_endless_loop_with_body(code_node)
    outer_loop = asgraph.add_endless_loop_with_body(inner_loop)
    replacement_loop = asgraph.factory.create_while_loop_node(
        condition=LogicCondition.initialize_symbol("a", asgraph.factory.logic_context)
    )

    asgraph.substitute_loop_node(inner_loop, replacement_loop)

    assert (
        set(asgraph.edges) == {(replacement_loop, code_node), (outer_loop, replacement_loop)}
        and len(asgraph.nodes) == 3
        and asgraph.get_roots == (outer_loop,)
    )


def test_substitute_loop_node_with_sequence_parent():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("a"), const(2))])
    code_node_2 = asgraph._add_code_node([Assignment(var("b"), const(4))])
    loop = asgraph.add_endless_loop_with_body(code_node_1)
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, code_node_2), (seq_node, loop)))
    asgraph._code_node_reachability_graph.add_reachability(code_node_1, code_node_2)
    seq_node.sort_children()
    replacement_loop = asgraph.factory.create_while_loop_node(
        condition=LogicCondition.initialize_symbol("a", asgraph.factory.logic_context)
    )

    asgraph.substitute_loop_node(loop, replacement_loop)

    assert (
        set(asgraph.edges) == {(replacement_loop, code_node_1), (seq_node, replacement_loop), (seq_node, code_node_2)}
        and len(asgraph.nodes) == 4
        and asgraph.get_roots == (seq_node,)
        and seq_node.children == (replacement_loop, code_node_2)
    )


def test_substitute_seq_node_by_single_child_no_parent():
    asgraph = AbstractSyntaxInterface()
    code_node = asgraph._add_code_node([Assignment(var("a"), const(2))])
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edge(seq_node, code_node)
    seq_node.sort_children()

    asgraph.replace_seq_node_by_single_child(seq_node)

    assert asgraph.nodes == (code_node,)


def test_substitute_seq_node_by_single_child_with_parent():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("a"), const(2))])
    code_node_2 = asgraph._add_code_node([Assignment(var("b"), const(5))])
    seq_node = asgraph.factory.create_seq_node()
    seq_node_single_child = asgraph.factory.create_seq_node()
    asgraph._add_nodes_from((seq_node, seq_node_single_child))
    asgraph._add_edges_from(((seq_node, code_node_2), (seq_node, seq_node_single_child), (seq_node_single_child, code_node_1)))
    asgraph._code_node_reachability_graph.add_reachability(code_node_1, code_node_2)
    seq_node_single_child.sort_children()
    seq_node.sort_children()

    asgraph.replace_seq_node_by_single_child(seq_node_single_child)

    assert (
        set(asgraph.nodes) == {code_node_1, code_node_2, seq_node}
        and set(asgraph.edges)
        == {
            (seq_node, code_node_1),
            (seq_node, code_node_2),
        }
        and seq_node.children == (code_node_1, code_node_2)
    )


def test_flatten_nested_sequence_nodes():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("a"), const(2))])
    code_node_2 = asgraph._add_code_node([Assignment(var("b"), const(5))])
    code_node_3 = asgraph._add_code_node([Assignment(var("c"), const(4))])
    code_node_4 = asgraph._add_code_node([Assignment(var("d"), const(9))])
    code_node_5 = asgraph._add_code_node([Assignment(var("e"), const(6))])
    seq_node = asgraph.factory.create_seq_node()
    nested_seq_node = asgraph.factory.create_seq_node()
    asgraph._add_nodes_from((seq_node, nested_seq_node))
    asgraph._add_edges_from(
        (
            (seq_node, nested_seq_node),
            (seq_node, code_node_1),
            (nested_seq_node, code_node_2),
            (nested_seq_node, code_node_3),
            (seq_node, code_node_4),
            (seq_node, code_node_5),
        )
    )
    asgraph._code_node_reachability_graph.add_reachability_from(
        combinations([code_node_1, code_node_2, code_node_3, code_node_4, code_node_5], 2)
    )
    nested_seq_node.sort_children()
    seq_node.sort_children()

    asgraph.flatten_sequence_node(seq_node)

    assert (
        len(asgraph.nodes) == 6
        and len(asgraph.edges) == 5
        and seq_node.children == (code_node_1, code_node_2, code_node_3, code_node_4, code_node_5)
    )


def test_switch_branches_only_one_branch():
    asgraph = AbstractSyntaxInterface()
    code_node = asgraph._add_code_node([Assignment(var("e"), const(9))])
    condition = asgraph._add_condition_node_with(LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), code_node)

    asgraph.switch_branches(condition)

    assert (
        len(asgraph) == 3
        and condition.condition == ~LogicCondition.initialize_symbol("a", asgraph.factory.logic_context)
        and condition.true_branch is None
        and condition.false_branch_child == code_node
    )

    asgraph.switch_branches(condition)

    assert (
        len(asgraph) == 3
        and condition.condition == LogicCondition.initialize_symbol("a", asgraph.factory.logic_context)
        and condition.false_branch is None
        and condition.true_branch_child == code_node
    )


def test_switch_branches():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("e"), const(9))])
    code_node_2 = asgraph._add_code_node([Assignment(var("d"), const(9))])
    condition = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), code_node_1, code_node_2
    )

    asgraph.switch_branches(condition)

    assert (
        len(asgraph) == 5
        and condition.condition == ~LogicCondition.initialize_symbol("a", asgraph.factory.logic_context)
        and condition.true_branch_child == code_node_2
        and condition.false_branch_child == code_node_1
    )


def test_add_instruction_after_code_node():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("u"), const(9))])
    code_node_2 = asgraph._add_code_node([Break()])
    code_node_3 = asgraph._add_code_node([Assignment(var("v"), const(9))])
    condition_node = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), code_node_2, code_node_3
    )
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, code_node_1), (seq_node, condition_node)))
    asgraph._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_3), (code_node_1, code_node_2)))
    seq_node.sort_children()

    asgraph.add_instructions_after(code_node_1, Assignment(var("z"), const(9)))

    assert (
        len(asgraph) == 7
        and code_node_1.instructions == [Assignment(var("u"), const(9)), Assignment(var("z"), const(9))]
        and seq_node.children == (code_node_1, condition_node)
    )

    asgraph.add_instructions_after(code_node_1, Assignment(var("x"), const(9)), Assignment(var("y"), const(9)))

    assert (
        len(asgraph) == 7
        and code_node_1.instructions
        == [Assignment(var("u"), const(9)), Assignment(var("z"), const(9)), Assignment(var("x"), const(9)), Assignment(var("y"), const(9))]
        and seq_node.children == (code_node_1, condition_node)
    )


def test_add_instruction_after_code_node_with_reaching_condition():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("u"), const(9))])
    code_node_1.reaching_condition = LogicCondition.initialize_symbol("b", asgraph.factory.logic_context)
    code_node_2 = asgraph._add_code_node([Break()])
    code_node_3 = asgraph._add_code_node([Assignment(var("v"), const(9))])
    condition_node = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), code_node_2, code_node_3
    )
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, code_node_1), (seq_node, condition_node)))
    asgraph._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_3), (code_node_1, code_node_2)))
    seq_node.sort_children()

    new_seq_node = asgraph.add_instructions_after(code_node_1, Assignment(var("z"), const(9)))

    assert (
        len(asgraph) == 8
        and code_node_1.instructions == [Assignment(var("u"), const(9))]
        and seq_node.children == (code_node_1, asgraph.factory.create_code_node([Assignment(var("z"), const(9))]), condition_node)
        and new_seq_node == seq_node
    )


def test_add_instruction_after_seq_exists():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("u"), const(9))])
    code_node_2 = asgraph._add_code_node([Break()])
    code_node_3 = asgraph._add_code_node([Assignment(var("v"), const(9))])
    condition_node = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), code_node_2, code_node_3
    )
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, code_node_1), (seq_node, condition_node)))
    asgraph._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_3), (code_node_1, code_node_2)))
    seq_node.sort_children()

    new_seq_node = asgraph.add_instructions_after(condition_node, Assignment(var("z"), const(9)))
    new_code_node = asgraph.factory.create_code_node([Assignment(var("z"), const(9))])

    assert (
        len(asgraph) == 8
        and seq_node.children == (code_node_1, condition_node, new_code_node)
        and asgraph._code_node_reachability_graph.reaches(code_node_2, seq_node.children[2])
        and asgraph._code_node_reachability_graph.reaches(code_node_3, seq_node.children[2])
        and new_seq_node == seq_node
    )


def test_add_instruction_after_new_seq():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("u"), const(9))])
    code_node_2 = asgraph._add_code_node([Break()])
    code_node_3 = asgraph._add_code_node([Assignment(var("v"), const(9))])
    code_node_4 = asgraph._add_code_node([Assignment(var("w"), const(9))])
    condition_node_1 = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), code_node_2, code_node_3
    )
    condition_node_2 = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("b", asgraph.factory.logic_context), code_node_1, condition_node_1
    )
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, condition_node_2), (seq_node, code_node_4)))
    asgraph._code_node_reachability_graph.add_reachability_from(
        ((code_node_1, code_node_4), (code_node_2, code_node_4), (code_node_3, code_node_4))
    )
    seq_node.sort_children()

    new_seq_node = asgraph.add_instructions_after(condition_node_1, Assignment(var("z"), const(9)))
    new_code_node = asgraph.factory.create_code_node([Assignment(var("z"), const(9))])

    assert (
        len(asgraph) == 13
        and condition_node_2.false_branch_child == new_seq_node
        and new_seq_node.children == (condition_node_1, new_code_node)
        and asgraph._code_node_reachability_graph.reaches(code_node_2, new_seq_node.children[1])
        and asgraph._code_node_reachability_graph.reaches(code_node_3, new_seq_node.children[1])
        and asgraph._code_node_reachability_graph.reaches(new_seq_node.children[1], code_node_4)
    )


def test_remove_subtree_with_root():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("u"), const(9))])
    code_node_2 = asgraph._add_code_node([Break()])
    code_node_3 = asgraph._add_code_node([Assignment(var("v"), const(9))])
    code_node_4 = asgraph._add_code_node([Assignment(var("w"), const(9))])
    condition_node_1 = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), code_node_2, code_node_3
    )
    condition_node_2 = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("b", asgraph.factory.logic_context), code_node_1, condition_node_1
    )
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, condition_node_2), (seq_node, code_node_4)))
    asgraph._code_node_reachability_graph.add_reachability_from(
        ((code_node_1, code_node_4), (code_node_2, code_node_4), (code_node_3, code_node_4))
    )
    seq_node.sort_children()

    asgraph.remove_subtree(condition_node_1)

    assert len(asgraph) == 6 and condition_node_2.false_branch_child is None and condition_node_2.false_branch

    asgraph.remove_subtree(seq_node)

    assert len(asgraph) == 0


def test_remove_empty_nodes_no_empty_loop_1():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([])
    code_node_2 = asgraph._add_code_node([Assignment(var("b"), const(2))])
    loop = asgraph.add_endless_loop_with_body(code_node_1)
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, loop), (seq_node, code_node_2)))
    seq_node.sort_children()
    asgraph._code_node_reachability_graph.add_reachability(code_node_1, code_node_2)

    asgraph.remove_empty_nodes()

    assert len(asgraph) == 4 and asgraph._code_node_reachability_graph.reaches(loop.body, code_node_2)


def test_remove_empty_nodes_no_empty_loop_2():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([])
    code_node_2 = asgraph._add_code_node([])
    code_node_3 = asgraph._add_code_node([Assignment(var("b"), const(2))])
    condition_node = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), code_node_1, code_node_2
    )
    loop = asgraph.add_endless_loop_with_body(condition_node)
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, loop), (seq_node, code_node_3)))
    seq_node.sort_children()
    asgraph._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_3), (code_node_2, code_node_3)))

    asgraph.remove_empty_nodes()

    assert len(asgraph) == 4 and asgraph._code_node_reachability_graph.reaches(loop.body, code_node_3)


def test_remove_empty_nodes():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([])
    code_node_2 = asgraph._add_code_node([])
    code_node_3 = asgraph._add_code_node([Assignment(var("b"), const(2))])
    condition_node = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), code_node_1, code_node_2
    )
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, condition_node), (seq_node, code_node_3)))
    seq_node.sort_children()
    asgraph._code_node_reachability_graph.add_reachability_from(((code_node_1, code_node_3), (code_node_2, code_node_3)))

    asgraph.remove_empty_nodes()

    assert len(asgraph) == 2 and seq_node.children == (code_node_3,)


def test_remove_empty_nodes_empty_graph():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([])
    code_node_1.reaching_condition = LogicCondition.initialize_symbol("a", asgraph.factory.logic_context)
    code_node_2 = asgraph._add_code_node([])
    seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node)
    asgraph._add_edges_from(((seq_node, code_node_1), (seq_node, code_node_2)))
    seq_node.sort_children()
    asgraph._code_node_reachability_graph.add_reachability(code_node_1, code_node_2)

    asgraph.remove_empty_nodes()

    assert len(asgraph) == 0


def test_clean_up_ast():
    asgraph = AbstractSyntaxInterface()
    code_node_1 = asgraph._add_code_node([Assignment(var("u"), const(9))])
    code_node_2 = asgraph._add_code_node([Break()])
    code_node_3 = asgraph._add_code_node([Assignment(var("v"), const(9))])
    root_seq_node = asgraph.factory.create_seq_node()
    asgraph._add_node(root_seq_node)
    seq_node_1 = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node_1)
    seq_node_2 = asgraph.factory.create_seq_node()
    asgraph._add_node(seq_node_2)
    condition_node = asgraph._add_condition_node_with(
        LogicCondition.initialize_symbol("a", asgraph.factory.logic_context), false_branch=seq_node_2
    )
    asgraph._add_edges_from(
        (
            (root_seq_node, seq_node_1),
            (root_seq_node, condition_node),
            (seq_node_1, code_node_1),
            (seq_node_1, code_node_2),
            (seq_node_2, code_node_3),
        )
    )
    asgraph._code_node_reachability_graph.add_reachability_from(
        ((code_node_1, code_node_3), (code_node_1, code_node_2), (code_node_2, code_node_3))
    )
    root_seq_node.sort_children()

    asgraph.clean_up()

    assert (
        len(asgraph) == 6
        and root_seq_node.children == (code_node_1, code_node_2, condition_node)
        and condition_node.false_branch is None
        and condition_node.true_branch_child == code_node_3
        and condition_node.condition == ~LogicCondition.initialize_symbol("a", asgraph.factory.logic_context)
    )


# Generic Tests
def test_root_empty():
    """Check if an empty AST has no root."""
    ast = AbstractSyntaxInterface()
    assert ast.get_roots == ()


def test_root_set():
    """Check if the AST root is correct"""
    ast = AbstractSyntaxInterface()
    node = ast._add_code_node([])
    assert ast.get_roots == (node,)


# Ordering Tests
def test_postorder_trivial():
    """Trivial postorder test: return the single node."""
    ast = AbstractSyntaxInterface()
    node = ast._add_code_node([])
    assert list(ast.post_order()) == [node]


def test_postorder():
    """Test if nodes are returned in correct postorder."""
    ast = AbstractSyntaxInterface()
    node_1 = ast._add_code_node([Break()])
    node_2 = ast._add_code_node([])
    cond_node = ast._add_condition_node_with(LogicCondition.initialize_symbol("a", ast.factory.logic_context), node_1, node_2)
    assert list(ast.post_order()) == [node_1, ast.factory.create_true_node(), node_2, ast.factory.create_false_node(), cond_node]


def test_preorder_trivial():
    """Trivial preorder test: return the single node."""
    ast = AbstractSyntaxInterface()
    node = ast._add_code_node([])
    assert list(ast.topological_order()) == [node]


def test_preorder():
    """Test if nodes are returned in correct preorder."""
    ast = AbstractSyntaxInterface()
    node_1 = ast._add_code_node([Break()])
    node_2 = ast._add_code_node([])
    cond_node = ast._add_condition_node_with(LogicCondition.initialize_symbol("a", ast.factory.logic_context), node_1, node_2)
    assert list(ast.topological_order()) == [cond_node, ast.factory.create_true_node(), node_1, ast.factory.create_false_node(), node_2]
