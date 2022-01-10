from decompiler.structures.ast.ast_nodes import CodeNode
from decompiler.structures.ast.condition_symbol import ConditionHandler, ConditionSymbol
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.classifiedgraph import EdgeProperty
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.structures.logic.logic_condition import LogicCondition, PseudoLogicCondition
from decompiler.structures.pseudo import Integer
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, IndirectBranch, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType


def variable(name="a", version=0, ssa_name=None) -> Variable:
    """A test variable as an unsigned 32bit integer."""
    return Variable(name, ssa_label=version, vartype=Integer.int32_t(), ssa_name=ssa_name)


def test_unconditional_node():
    """Check that no symbol is generated for unconditional nodes."""
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, []),
            BasicBlock(1, []),
        ]
    )
    graph.add_edges_from([UnconditionalEdge(vertices[0], vertices[1])])

    t_cfg = TransitionCFG.generate(graph)

    true_condition = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    new_nodes = [TransitionBlock(0, CodeNode([], true_condition.copy())), TransitionBlock(1, CodeNode([], true_condition.copy()))]
    assert (
        set(t_cfg.nodes) == {new_nodes[0], new_nodes[1]}
        and t_cfg.get_edge(new_nodes[0], new_nodes[1]).tag.is_true
        and t_cfg.get_edge(new_nodes[0], new_nodes[1]).property == EdgeProperty.non_loop
    )
    assert len(t_cfg.condition_handler) == 0


def test_conditional_node():
    """Test whether a symbol is created and the tags are properly set when a conditional node is parsed."""
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, [Branch(condition := Condition(OperationType.equal, [Constant(1), Constant(2)]))]),
            BasicBlock(1, []),
            BasicBlock(2, []),
        ]
    )
    graph.add_edges_from([TrueCase(vertices[0], vertices[1]), FalseCase(vertices[0], vertices[2])])

    t_cfg = TransitionCFG.generate(graph)

    true_condition = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    new_nodes = [
        TransitionBlock(0, CodeNode([], true_condition.copy())),
        TransitionBlock(1, CodeNode([], true_condition.copy())),
        TransitionBlock(2, CodeNode([], true_condition.copy())),
    ]
    assert set(t_cfg.nodes) == set(new_nodes)
    assert t_cfg.get_edge(new_nodes[0], new_nodes[1]).tag.is_equivalent_to(~t_cfg.get_edge(new_nodes[0], new_nodes[2]).tag)
    assert (
        t_cfg.get_edge(new_nodes[0], new_nodes[1]).property == t_cfg.get_edge(new_nodes[0], new_nodes[2]).property == EdgeProperty.non_loop
    )
    assert t_cfg.condition_handler.get_condition_of(t_cfg.get_edge(new_nodes[0], new_nodes[1]).tag) == condition


def test_switch_node():
    """Test whether switch cases are correctly translated into symbols."""
    graph = ControlFlowGraph()
    graph.add_nodes_from(
        vertices := [
            BasicBlock(0, [IndirectBranch(var := Variable("x", ssa_label=0))]),
            BasicBlock(1, []),
            BasicBlock(2, []),
            BasicBlock(3, []),
            BasicBlock(4, []),
        ]
    )
    graph.add_edges_from(
        [
            SwitchCase(vertices[0], vertices[1], [Constant(1), Constant(3)]),
            SwitchCase(vertices[0], vertices[2], [Constant(2)]),
            SwitchCase(vertices[0], vertices[3], [Constant(0), Constant(1337)]),
            UnconditionalEdge(vertices[1], vertices[4]),
            UnconditionalEdge(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[3], vertices[4]),
        ]
    )

    t_cfg = TransitionCFG.generate(graph)

    true_condition = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    new_nodes = [
        TransitionBlock(0, CodeNode([], true_condition.copy())),
        TransitionBlock(1, CodeNode([], true_condition.copy())),
        TransitionBlock(2, CodeNode([], true_condition.copy())),
        TransitionBlock(3, CodeNode([], true_condition.copy())),
        TransitionBlock(4, CodeNode([], true_condition.copy())),
    ]
    assert set(t_cfg.nodes) == set(new_nodes)
    condition_edge_01 = t_cfg.get_edge(new_nodes[0], new_nodes[1]).tag
    assert condition_edge_01.is_disjunction and len(operands := condition_edge_01.operands) == 2
    assert {t_cfg.condition_handler.get_condition_of(operands[0]), t_cfg.condition_handler.get_condition_of(operands[1])} == {
        Condition(OperationType.equal, [var, Constant(i)]) for i in [1, 3]
    }

    assert t_cfg.condition_handler.get_condition_of(t_cfg.get_edge(new_nodes[0], new_nodes[2]).tag) == Condition(
        OperationType.equal, [var, Constant(2)]
    )
    condition_edge_03 = t_cfg.get_edge(new_nodes[0], new_nodes[3]).tag
    assert condition_edge_03.is_disjunction and len(operands := condition_edge_03.operands) == 2
    assert {t_cfg.condition_handler.get_condition_of(operands[0]), t_cfg.condition_handler.get_condition_of(operands[1])} == {
        Condition(OperationType.equal, [var, Constant(i)]) for i in [0, 1337]
    }


def test_generate():
    """
                       +-----------------+
                       |       0.        |
                       |    i#0 = 0x0    |
                       |   x#0 = 0x2a    |
                       +-----------------+
                         |
                         |
                         v
    +------------+     +-----------------+
    |     3.     |     |       1.        |
    | return x#0 | <-- | if(i#0 != 0x3)  | <+
    +------------+     +-----------------+  |
                         |                  |
                         |                  |
                         v                  |
                       +-----------------+  |
                       |       2.        |  |
                       | i#0 = i#0 + 0x1 |  |
                       | x#0 = x#0 - i#0 | -+
                       +-----------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(0, instructions=[Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))]),
            BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]))]),
            BasicBlock(
                2,
                instructions=[
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                ],
            ),
            BasicBlock(3, instructions=[Return([variable(name="x")])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[1]),
        ]
    )

    t_cfg = TransitionCFG.generate(cfg)

    true_condition = LogicCondition.initialize_true(context := LogicCondition.generate_new_context())
    new_nodes = [
        TransitionBlock(
            0, CodeNode([Assignment(variable(name="i"), Constant(0)), Assignment(variable(name="x"), Constant(42))], true_condition.copy())
        ),
        TransitionBlock(1, CodeNode([], true_condition.copy())),
        TransitionBlock(
            2,
            CodeNode(
                [
                    Assignment(variable(name="i"), BinaryOperation(OperationType.plus, [variable(name="i"), Constant(1)])),
                    Assignment(variable(name="x"), BinaryOperation(OperationType.minus, [variable(name="x"), variable(name="i")])),
                ],
                true_condition.copy(),
            ),
        ),
        TransitionBlock(3, CodeNode([Return([variable(name="x")])], true_condition.copy())),
    ]
    assert set(t_cfg.nodes) == set(new_nodes) and len(t_cfg.edges) == 4
    assert (
        t_cfg.get_edge(new_nodes[0], new_nodes[1]).tag.is_true
        and t_cfg.get_edge(new_nodes[0], new_nodes[1]).property == EdgeProperty.non_loop
    )
    assert (
        t_cfg.condition_handler.get_condition_of(t_cfg.get_edge(new_nodes[1], new_nodes[2]).tag)
        == Condition(OperationType.not_equal, [variable(name="i"), Constant(3)])
        and t_cfg.get_edge(new_nodes[1], new_nodes[2]).property == EdgeProperty.non_loop
    )
    assert (
        t_cfg.get_edge(new_nodes[1], new_nodes[3]).tag.is_negation
        and t_cfg.condition_handler.get_condition_of(t_cfg.get_edge(new_nodes[1], new_nodes[3]).tag.operands[0])
        == Condition(OperationType.not_equal, [variable(name="i"), Constant(3)])
        and t_cfg.get_edge(new_nodes[1], new_nodes[3]).property == EdgeProperty.non_loop
    )
    assert (
        t_cfg.get_edge(new_nodes[2], new_nodes[1]).tag.is_true and t_cfg.get_edge(new_nodes[2], new_nodes[1]).property == EdgeProperty.back
    )
    assert t_cfg.condition_handler == ConditionHandler(
        {
            LogicCondition.initialize_symbol("x1", context): ConditionSymbol(
                Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]),
                LogicCondition.initialize_symbol("x1", context),
                PseudoLogicCondition.initialize_from_condition(
                    Condition(OperationType.not_equal, [variable(name="i"), Constant(3)]), context
                ),
            )
        }
    )
