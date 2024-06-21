""" Tests for the PatternIndependentRestructuring pipeline stage"""

import pytest
from decompiler.pipeline.controlflowanalysis.restructuring import PatternIndependentRestructuring
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.base_class_car import (
    CaseNodeCandidate,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.missing_case_finder_intersecting_constants import (
    MissingCaseFinderIntersectingConstants,
)
from decompiler.pipeline.controlflowanalysis.restructuring_commons.condition_aware_refinement_commons.switch_extractor import (
    SwitchExtractor,
)
from decompiler.pipeline.controlflowanalysis.restructuring_options import LoopBreakOptions, RestructuringOptions
from decompiler.structures.ast.ast_nodes import ConditionNode, SeqNode, SwitchNode, CodeNode
from decompiler.structures.ast.condition_symbol import ConditionHandler
from decompiler.structures.ast.reachability_graph import SiblingReachabilityGraph
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, Variable, ImportedFunctionSymbol
from decompiler.structures.pseudo.instructions import Assignment, Branch, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType, ListOperation, Call
from decompiler.structures.pseudo.typing import CustomType, Integer
from decompiler.task import DecompilerTask

var_b = Variable("b", Integer.int32_t())
var_c = Variable("c", Integer.int32_t())
const = [Constant(i, Integer.int32_t()) for i in range(4)]


@pytest.fixture
def task() -> DecompilerTask:
    """A mock task with an empty cfg."""
    return DecompilerTask(name="test", function_identifier="", cfg=ControlFlowGraph())


def test_no_crash_missing_case_finder(task):
    """
    Crashing example from Issue #218, #249
    CFG extracted from ed8da0853c9c402464f548ee53f3cb60fb6f4b627f1bcca7997dd9a2cd63b86f sub_2ca0

    Test if no ValueError is raised.
    """
    var_2 = Variable("var_2", Integer(32, False), ssa_name=Variable("rcx_1", Integer(32, False), 2))
    var_3 = Variable("var_3", Integer(32, False), ssa_name=Variable("rbx_1", Integer(32, False), 2))
    var_4 = Variable("var_4", Integer(32, False), ssa_name=Variable("rbx_2", Integer(32, False), 2))
    var_5 = Variable("var_5", Integer(32, False), ssa_name=Variable("rax_1", Integer(32, False), 2))
    var_6 = Variable("var_6", Integer(32, False), ssa_name=Variable("rax_2", Integer(32, False), 2))
    task.cfg.add_nodes_from(
        [
            b0 := BasicBlock(
                0,
                [Branch(Condition(OperationType.less_or_equal, [var_2, Constant(0x2, Integer(32, True))], CustomType("bool", 1)))],
            ),
            b1 := BasicBlock(1, [Assignment(var_3, Constant(-0x3, Integer(32, True)))]),
            b3 := BasicBlock(
                3,
                [Branch(Condition(OperationType.equal, [var_5, Constant(0x2, Integer(32, True))], CustomType("bool", 1)))],
            ),
            b4 := BasicBlock(4, [Return([Constant(0xFFFFFFFF, Integer(32, True))])]),
            b5 := BasicBlock(
                5,
                [
                    Assignment(var_6, BinaryOperation(OperationType.plus, [var_5, Constant(-0x3, Integer(32, True))])),
                    Branch(Condition(OperationType.greater_us, [var_5, Constant(0x2, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            b7 := BasicBlock(7, [Branch(Condition(OperationType.equal, [var_5, Constant(0x0, Integer(32, True))], CustomType("bool", 1)))]),
            b10 := BasicBlock(10, [Assignment(var_6, Constant(0x0, Integer(32, True)))]),
            b11 := BasicBlock(
                11, [Branch(Condition(OperationType.not_equal, [var_5, Constant(0x1, Integer(32, True))], CustomType("bool", 1)))]
            ),
            b15 := BasicBlock(15, [Return([var_6])]),
            b17 := BasicBlock(17, [Assignment(var_6, Constant(0x1, Integer(32, True)))]),
            b22 := BasicBlock(
                22, [Return([BinaryOperation(OperationType.plus, [var_3, BinaryOperation(OperationType.plus, [var_4, var_5])])])]
            ),
        ]
    )
    task.cfg.add_edges_from(
        [
            TrueCase(b0, b1),
            FalseCase(b0, b3),
            UnconditionalEdge(b1, b3),
            FalseCase(b3, b5),
            TrueCase(b3, b4),
            TrueCase(b5, b22),
            FalseCase(b5, b7),
            TrueCase(b7, b10),
            FalseCase(b7, b11),
            UnconditionalEdge(b10, b15),
            TrueCase(b11, b22),
            FalseCase(b11, b17),
            UnconditionalEdge(b17, b15),
        ]
    )
    PatternIndependentRestructuring().run(task)


def test_insert_intersecting_cases_before(task):
    """Test, node is not insertable."""
    condition_handler = ConditionHandler()
    # cond_1_symbol = condition_handler.add_condition(Condition(OperationType.equal, [var_c, const[1]]))
    cond_2_symbol = condition_handler.add_condition(Condition(OperationType.equal, [var_c, const[2]]))

    ast = AbstractSyntaxForest(condition_handler=condition_handler)
    root = ast.factory.create_seq_node()
    missing_case = ast.factory.create_condition_node(condition=cond_2_symbol)
    switch = ast.factory.create_switch_node(var_c)
    true_branch = ast.factory.create_true_node()
    case1 = ast.factory.create_case_node(var_c, const[1])
    case2 = ast.factory.create_case_node(var_c, const[2], break_case=True)
    code_nodes = [
        ast.factory.create_code_node([Assignment(var_b, BinaryOperation(OperationType.plus, [var_b, const[i + 1]]))]) for i in range(3)
    ]
    ast._add_nodes_from(code_nodes + [root, missing_case, switch, case1, case2, true_branch])
    ast._add_edges_from(
        [
            (root, missing_case),
            (root, switch),
            (missing_case, true_branch),
            (true_branch, code_nodes[0]),
            (switch, case1),
            (switch, case2),
            (case1, code_nodes[1]),
            (case2, code_nodes[2]),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(((code_nodes[0], code_nodes[2]), (code_nodes[1], code_nodes[2])))
    root.sort_children()
    switch.sort_cases()
    sibling_reachability = ast.get_sibling_reachability_of_children_of(root)
    reachability_graph = SiblingReachabilityGraph(sibling_reachability)
    ast.set_current_root(root)

    mcfic = MissingCaseFinderIntersectingConstants(
        ast, RestructuringOptions(True, True, 2, LoopBreakOptions.structural_variable), switch, reachability_graph
    )
    mcfic.insert(CaseNodeCandidate(missing_case, mcfic._get_const_eq_check_expression_of_disjunction(cond_2_symbol), cond_2_symbol))

    assert isinstance(ast.current_root, SeqNode) and len(ast.current_root.children) == 2
    assert isinstance(cond := ast.current_root.children[0], ConditionNode) and cond.true_branch_child


def test_insert_intersecting_cases_anywhere(task):
    """Test, node is not insertable."""
    condition_handler = ConditionHandler()
    # cond_1_symbol = condition_handler.add_condition(Condition(OperationType.equal, [var_c, const[1]]))
    cond_2_symbol = condition_handler.add_condition(Condition(OperationType.equal, [var_c, const[2]]))

    ast = AbstractSyntaxForest(condition_handler=condition_handler)
    root = ast.factory.create_seq_node()
    missing_case = ast.factory.create_condition_node(condition=cond_2_symbol)
    switch = ast.factory.create_switch_node(var_c)
    true_branch = ast.factory.create_true_node()
    case1 = ast.factory.create_case_node(var_c, const[1])
    case2 = ast.factory.create_case_node(var_c, const[2], break_case=True)
    code_nodes = [
        ast.factory.create_code_node([Assignment(var_b, BinaryOperation(OperationType.plus, [var_b, const[i + 1]]))]) for i in range(2)
    ]
    empty_code = ast.factory.create_code_node([])
    ast._add_nodes_from(code_nodes + [root, missing_case, switch, case1, case2, true_branch, empty_code])
    ast._add_edges_from(
        [
            (root, missing_case),
            (root, switch),
            (missing_case, true_branch),
            (true_branch, code_nodes[0]),
            (switch, case1),
            (switch, case2),
            (case1, empty_code),
            (case2, code_nodes[1]),
        ]
    )
    ast._code_node_reachability_graph.add_reachability(empty_code, code_nodes[1])
    root.sort_children()
    switch.sort_cases()
    sibling_reachability = ast.get_sibling_reachability_of_children_of(root)
    reachability_graph = SiblingReachabilityGraph(sibling_reachability)
    ast.set_current_root(root)

    mcfic = MissingCaseFinderIntersectingConstants(
        ast, RestructuringOptions(True, True, 2, LoopBreakOptions.structural_variable), switch, reachability_graph
    )
    mcfic.insert(CaseNodeCandidate(missing_case, mcfic._get_const_eq_check_expression_of_disjunction(cond_2_symbol), cond_2_symbol))

    assert isinstance(ast.current_root, SeqNode) and len(ast.current_root.children) == 1
    assert isinstance(switch := ast.current_root.children[0], SwitchNode) and switch.cases == (case2, case1)


def test_switch_extractor_sequence(task):
    """Test, switch gets extracted from sequence nodes with Reaching Condition."""
    condition_handler = ConditionHandler()
    # cond_1_symbol = condition_handler.add_condition(Condition(OperationType.equal, [var_c, const[1]]))
    cond_2_symbol = condition_handler.add_condition(Condition(OperationType.not_equal, [var_c, const[1]]))

    ast = AbstractSyntaxForest(condition_handler=condition_handler)
    root = ast.factory.create_seq_node(reaching_condition=cond_2_symbol)
    code_node = ast.factory.create_code_node(
        [Assignment(ListOperation([]), Call(ImportedFunctionSymbol("scanf", 0x42), [Constant(0x804B01F), var_c]))]
    )
    switch = ast.factory.create_switch_node(var_c)
    case1 = ast.factory.create_case_node(var_c, const[2], break_case=True)
    case2 = ast.factory.create_case_node(var_c, const[3], break_case=True)
    case_content = [
        ast.factory.create_code_node([Assignment(var_b, BinaryOperation(OperationType.plus, [var_b, const[i + 1]]))]) for i in range(2)
    ]
    ast._add_nodes_from(case_content + [root, code_node, switch, case1, case2])
    ast._add_edges_from(
        [
            (root, code_node),
            (root, switch),
            (switch, case1),
            (switch, case2),
            (case1, case_content[0]),
            (case2, case_content[1]),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        [(code_node, case_content[0]), (code_node, case_content[1]), (case_content[0], case_content[1])]
    )
    root.sort_children()
    switch.sort_cases()
    ast.set_current_root(root)

    SwitchExtractor.extract(ast, RestructuringOptions(True, True, 2, LoopBreakOptions.structural_variable))
    assert isinstance(ast.current_root, SeqNode) and ast.current_root.reaching_condition.is_true and len(ast.current_root.children) == 2
    assert ast.current_root.children[0].reaching_condition == cond_2_symbol
    assert isinstance(switch := ast.current_root.children[1], SwitchNode) and switch.cases == (case1, case2)


def test_switch_extractor_sequence_no_extraction(task):
    """Test, switch gets extracted from sequence nodes with Reaching Condition."""
    condition_handler = ConditionHandler()
    # cond_1_symbol = condition_handler.add_condition(Condition(OperationType.equal, [var_c, const[1]]))
    cond_1_symbol = condition_handler.add_condition(Condition(OperationType.not_equal, [var_b, const[1]]))
    cond_2_symbol = condition_handler.add_condition(Condition(OperationType.not_equal, [var_c, const[1]]))

    ast = AbstractSyntaxForest(condition_handler=condition_handler)
    root = ast.factory.create_condition_node(cond_2_symbol)
    true_node = ast.factory.create_true_node()
    seq_node = ast.factory.create_seq_node(reaching_condition=cond_1_symbol)
    code_node = ast.factory.create_code_node(
        [Assignment(ListOperation([]), Call(ImportedFunctionSymbol("scanf", 0x42), [Constant(0x804B01F), var_c]))]
    )
    switch = ast.factory.create_switch_node(var_c)
    case1 = ast.factory.create_case_node(var_c, const[2], break_case=True)
    case2 = ast.factory.create_case_node(var_c, const[3], break_case=True)
    case_content = [
        ast.factory.create_code_node([Assignment(var_b, BinaryOperation(OperationType.plus, [var_b, const[i + 1]]))]) for i in range(2)
    ]
    ast._add_nodes_from(case_content + [root, true_node, seq_node, code_node, switch, case1, case2])
    ast._add_edges_from(
        [
            (root, true_node),
            (true_node, seq_node),
            (seq_node, code_node),
            (seq_node, switch),
            (switch, case1),
            (switch, case2),
            (case1, case_content[0]),
            (case2, case_content[1]),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        [(code_node, case_content[0]), (code_node, case_content[1]), (case_content[0], case_content[1])]
    )
    seq_node.sort_children()
    switch.sort_cases()
    ast.set_current_root(root)

    SwitchExtractor.extract(ast, RestructuringOptions(True, True, 2, LoopBreakOptions.structural_variable))
    assert isinstance(cond := ast.current_root, ConditionNode) and cond.false_branch is None
    assert (
        isinstance(seq_node := cond.true_branch_child, SeqNode)
        and seq_node.reaching_condition == cond_1_symbol
        and len(seq_node.children) == 2
    )
    assert isinstance(seq_node.children[0], CodeNode)
    assert isinstance(switch := seq_node.children[1], SwitchNode) and switch.cases == (case1, case2)
