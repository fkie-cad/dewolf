from typing import Union

from decompiler.pipeline.dataflowanalysis.common_subexpression_elimination import CommonSubexpressionElimination
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, Expression, FunctionSymbol, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Relation, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer, Type, UnknownType
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

expr1 = BinaryOperation(OperationType.plus, [Variable("x", ssa_label=1), Constant(1)])
expr2 = BinaryOperation(OperationType.minus, [expr1, BinaryOperation(OperationType.multiply, [Variable("y", ssa_label=2), Constant(2)])])


def function_symbol(name: str, value: int = 0x42) -> FunctionSymbol:
    return FunctionSymbol(name, value)


def imp_function_symbol(name: str, value: int = 0x42, c_type: Type = UnknownType()) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value, c_type)


def _generate_options(threshold: int = 4, intra: bool = True, str_threshold: int = 2, min_str_length: int = 8) -> Options:
    options = Options()
    options.set("common-subexpression-elimination.threshold", threshold)
    options.set("common-subexpression-elimination.intra", intra)
    options.set("common-subexpression-elimination.string_threshold", str_threshold)
    options.set("common-subexpression-elimination.min_string_length", min_str_length)
    return options


def _run_cse(cfg: ControlFlowGraph, options: Options = _generate_options()):
    """Run common subexpression elimination on the given control flow graph."""
    CommonSubexpressionElimination().run(DecompilerTask("test", cfg, options=options))


def test_no_cse_for_calls_1():
    """Checks that we do not do subexpression elimination for functions."""
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a"), Call(function_symbol("foo"), [expr1.copy()])),
                Assignment(Variable("b"), Call(function_symbol("foo"), [expr1.copy()])),
                Return([BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")])]),
            ],
        )
    )
    _run_cse(cfg, _generate_options(threshold=2))
    assert len(node.instructions) == 4
    replacement = Variable("c0", ssa_label=0)
    assert node.instructions == [
        Assignment(replacement.copy(), expr1.copy()),
        Assignment(Variable("a"), Call(function_symbol("foo"), [replacement.copy()])),
        Assignment(Variable("b"), Call(function_symbol("foo"), [replacement.copy()])),
        Return([BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")])]),
    ]


def test_no_cse_for_calls_2():
    """Checks that we do not do subexpression elimination for functions."""
    expr3 = BinaryOperation(OperationType.plus, [Call(function_symbol("foo"), [expr1.copy()]), Constant(1)])
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a"), expr3.copy()),
                Assignment(Variable("b"), expr3.copy()),
                Return([BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")])]),
            ],
        )
    )
    _run_cse(cfg, _generate_options(threshold=2))
    assert len(node.instructions) == 4
    replacement = Variable("c0", ssa_label=0)
    expr4 = BinaryOperation(OperationType.plus, [Call(function_symbol("foo"), [replacement.copy()]), Constant(1)])
    assert node.instructions == [
        Assignment(replacement.copy(), expr1.copy()),
        Assignment(Variable("a"), expr4),
        Assignment(Variable("b"), expr4),
        Return([BinaryOperation(OperationType.plus, [Variable("a"), Variable("b")])]),
    ]


def test_no_cse_for_listoperation():
    """Checks that we do not treat ListOperations as valid subexpression, i.e. the RHS of phi-functions."""
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        nodes := [
            BasicBlock(0, [Branch(Condition(OperationType.equal, [expr1, Constant(1)]))]),
            BasicBlock(1, []),
            BasicBlock(2, []),
            BasicBlock(
                3,
                instructions=[
                    Phi(Variable("a", ssa_label=1), [Variable("x", ssa_label=0), Variable("y", ssa_label=0)]),
                    Phi(Variable("b", ssa_label=1), [Variable("x", ssa_label=0), Variable("y", ssa_label=0)]),
                    Return([BinaryOperation(OperationType.plus, [Variable("a", ssa_label=1), Variable("b", ssa_label=1)])]),
                ],
            ),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[1]),
            FalseCase(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[3]),
        ]
    )
    old_inst = [i.copy() for i in cfg.instructions]
    _run_cse(cfg, _generate_options(threshold=2))
    assert old_inst == list(cfg.instructions)


def test_intra_function():
    """Test if intra instruction references are counted according to the flag."""
    # Check first that nothing changes when we disable intra
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a"), Call(imp_function_symbol("foo"), [expr1, expr1, expr1])),
                Branch(Condition(OperationType.equal, [expr1, Constant(1)])),
            ],
        )
    )
    _run_cse(cfg, _generate_options(intra=False))
    assert len(node.instructions) == 2
    # Then, check if the example is correctly changed with we set the option to yes
    _run_cse(cfg)
    replacement = Variable("c0", ssa_label=0)
    assert node.instructions == [
        Assignment(replacement.copy(), expr1.copy()),
        Assignment(Variable("a"), Call(imp_function_symbol("foo"), [replacement.copy(), replacement.copy(), replacement.copy()])),
        Branch(Condition(OperationType.equal, [replacement.copy(), Constant(1)])),
    ]


def test_trivial_1():
    """Test common subexpression elimination in a single basic block."""
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a"), BinaryOperation(OperationType.plus, [expr1.copy(), Constant(1)])),
                Assignment(Variable("b"), BinaryOperation(OperationType.plus, [expr1.copy(), Constant(2)])),
                Assignment(Variable("c"), BinaryOperation(OperationType.plus, [expr1.copy(), Constant(3)])),
                Assignment(Variable("d"), BinaryOperation(OperationType.plus, [expr1.copy(), Constant(4)])),
            ],
        )
    )
    _run_cse(cfg)
    replacement = Variable("c0", ssa_label=0)
    assert node.instructions == [
        Assignment(replacement.copy(), expr1),
        Assignment(Variable("a"), BinaryOperation(OperationType.plus, [replacement.copy(), Constant(1)])),
        Assignment(Variable("b"), BinaryOperation(OperationType.plus, [replacement.copy(), Constant(2)])),
        Assignment(Variable("c"), BinaryOperation(OperationType.plus, [replacement.copy(), Constant(3)])),
        Assignment(Variable("d"), BinaryOperation(OperationType.plus, [replacement.copy(), Constant(4)])),
    ]


def test_trivial_2():
    """Test common subexpression elimination in a single basic block where expression exists."""
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a"), expr1.copy()),
                Assignment(Variable("b"), expr1.copy()),
                Assignment(Variable("c"), expr1.copy()),
            ],
        )
    )
    _run_cse(cfg)
    assert node.instructions == [
        Assignment(Variable("a"), expr1),
        Assignment(Variable("b"), Variable("a")),
        Assignment(Variable("c"), Variable("a")),
    ]


def test_eliminate_longest_common_subexpression_1():
    """CSE should always eliminate the subexpressions with the highest complexity,"""
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a"), BinaryOperation(OperationType.minus, [expr2.copy(), Constant(1)])),
                Assignment(Variable("b"), BinaryOperation(OperationType.minus, [expr2.copy(), Constant(2)])),
                Assignment(Variable("c"), BinaryOperation(OperationType.minus, [expr2.copy(), Constant(3)])),
                Assignment(Variable("d"), BinaryOperation(OperationType.minus, [expr2.copy(), Constant(4)])),
            ],
        )
    )
    _run_cse(cfg)
    replacement = Variable("c0", ssa_label=0)
    assert node.instructions == [
        Assignment(replacement.copy(), expr2.copy()),
        Assignment(Variable("a"), BinaryOperation(OperationType.minus, [replacement.copy(), Constant(1)])),
        Assignment(Variable("b"), BinaryOperation(OperationType.minus, [replacement.copy(), Constant(2)])),
        Assignment(Variable("c"), BinaryOperation(OperationType.minus, [replacement.copy(), Constant(3)])),
        Assignment(Variable("d"), BinaryOperation(OperationType.minus, [replacement.copy(), Constant(4)])),
    ]


def test_eliminate_longest_common_subexpression_2():
    """CSE should always eliminate the subexpressions with the highest complexity,"""
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a"), expr2.copy()),
                Assignment(Variable("b"), expr2.copy()),
                Assignment(Variable("c"), expr2.copy()),
                Assignment(Variable("d"), expr2.copy()),
            ],
        )
    )
    _run_cse(cfg)
    assert node.instructions == [
        Assignment(Variable("a"), expr2),
        Assignment(Variable("b"), Variable("a")),
        Assignment(Variable("c"), Variable("a")),
        Assignment(Variable("d"), Variable("a")),
    ]


def test_nested_subexpressions_to_be_eliminated_1():
    """
    Check that nested subexpressions are eliminated correctly.

    expr1 should break the threshold when expr2 is defined in its own instruction.
    """
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a"), BinaryOperation(OperationType.multiply, [expr1.copy(), Constant(2)])),
                Assignment(Variable("b"), BinaryOperation(OperationType.multiply, [expr1.copy(), Constant(3)])),
                Assignment(Variable("c"), BinaryOperation(OperationType.multiply, [expr1.copy(), Constant(4)])),
                Assignment(Variable("d"), BinaryOperation(OperationType.multiply, [expr2.copy(), Constant(2)])),
                Assignment(Variable("e"), BinaryOperation(OperationType.multiply, [expr2.copy(), Constant(3)])),
                Assignment(Variable("f"), BinaryOperation(OperationType.multiply, [expr2.copy(), Constant(4)])),
                Assignment(Variable("g"), BinaryOperation(OperationType.multiply, [expr2.copy(), Constant(5)])),
            ],
        )
    )
    _run_cse(cfg)
    c0, c1 = Variable("c0", ssa_label=0), Variable("c1", ssa_label=0)
    assert node.instructions == [
        Assignment(c1.copy(), expr1),
        Assignment(Variable("a"), BinaryOperation(OperationType.multiply, [c1.copy(), Constant(2)])),
        Assignment(Variable("b"), BinaryOperation(OperationType.multiply, [c1.copy(), Constant(3)])),
        Assignment(Variable("c"), BinaryOperation(OperationType.multiply, [c1.copy(), Constant(4)])),
        Assignment(
            c0.copy(),
            BinaryOperation(
                OperationType.minus,
                [c1.copy(), BinaryOperation(OperationType.multiply, [Variable("y", ssa_label=2), Constant(2)])],
            ),
        ),
        Assignment(Variable("d"), BinaryOperation(OperationType.multiply, [c0.copy(), Constant(2)])),
        Assignment(Variable("e"), BinaryOperation(OperationType.multiply, [c0.copy(), Constant(3)])),
        Assignment(Variable("f"), BinaryOperation(OperationType.multiply, [c0.copy(), Constant(4)])),
        Assignment(Variable("g"), BinaryOperation(OperationType.multiply, [c0.copy(), Constant(5)])),
    ]


def test_nested_subexpressions_to_be_eliminated_2():
    """
    Check that nested subexpressions are eliminated correctly.

    expr1 should break the threshold when expr2 is defined in its own instruction.
    """
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a"), expr1.copy()),
                Assignment(Variable("b"), expr1.copy()),
                Assignment(Variable("c"), expr1.copy()),
                Assignment(Variable("d"), expr2.copy()),
                Assignment(Variable("e"), expr2.copy()),
                Assignment(Variable("f"), expr2.copy()),
                Assignment(Variable("g"), expr2.copy()),
            ],
        )
    )
    _run_cse(cfg)
    expr2.substitute(expr1, Variable("a"))
    assert node.instructions == [
        Assignment(Variable("a"), expr1),
        Assignment(Variable("b"), Variable("a")),
        Assignment(Variable("c"), Variable("a")),
        Assignment(Variable("d"), expr2),
        Assignment(Variable("e"), Variable("d")),
        Assignment(Variable("f"), Variable("d")),
        Assignment(Variable("g"), Variable("d")),
    ]


def test_finds_correct_dominator():
    """
                                    +-------------------------+
                                    |           0.            |
                                    |      if(a#0 > 0x0)      | -+
                                    +-------------------------+  |
                                      |                          |
                                      |                          |
                                      v                          |
                                    +-------------------------+  |
                                    |           1.            |  |
                                    |      a#1 = -(a#0)       |  |
                                    +-------------------------+  |
                                      |                          |
                                      |                          |
                                      v                          |
    +-------------------------+     +-------------------------+  |
    |                         |     |           2.            |  |
    |           4.            |     |    a#2 = ϕ(a#0,a#1)     |  |
    | printf("%s", x#1 + 0x1) |     | b#3 = ϕ(b#1,x#1 + 0x1)  |  |
    |                         | <-- |     if(a#2 == b#3)      | <+
    +-------------------------+     +-------------------------+
      |                               |
      |                               |
      |                               v
      |                             +-------------------------+
      |                             |           3.            |
      |                             | printf("%s", x#1 + 0x1) |
      |                             +-------------------------+
      |                               |
      |                               |
      |                               v
      |                             +-------------------------+
      |                             |           5.            |
      |                             |     bar(x#1 + 0x1)      |
      +---------------------------> |    return x#1 + 0x1     |
                                    +-------------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            head := BasicBlock(
                0,
                instructions=[Branch(Condition(OperationType.greater, [Variable("a", ssa_label=0), Constant(0, Integer.int32_t())]))],
            ),
            branch_body := BasicBlock(
                1, instructions=[Assignment(Variable("a", ssa_label=1), UnaryOperation(OperationType.negate, [Variable("a", ssa_label=0)]))]
            ),
            phi_block := BasicBlock(
                2,
                instructions=[
                    Phi(Variable("a", ssa_label=2), [Variable("a", ssa_label=0), Variable("a", ssa_label=1)]),
                    Phi(Variable("b", ssa_label=3), [Variable("b", ssa_label=1), expr1.copy()]),
                    Branch(Condition(OperationType.equal, [Variable("a", ssa_label=2), Variable("b", ssa_label=3)])),
                ],
            ),
            print_branch := BasicBlock(
                3, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("%s"), expr1.copy()]))]
            ),
            foo_branch := BasicBlock(
                4, instructions=[Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("%s"), expr1.copy()]))]
            ),
            return_block := BasicBlock(
                5, instructions=[Assignment(ListOperation([]), Call(function_symbol("bar"), [expr1.copy()])), Return([expr1.copy()])]
            ),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(head, branch_body),
            FalseCase(head, phi_block),
            UnconditionalEdge(branch_body, phi_block),
            TrueCase(phi_block, print_branch),
            FalseCase(phi_block, foo_branch),
            UnconditionalEdge(foo_branch, return_block),
            UnconditionalEdge(print_branch, return_block),
        ]
    )
    _run_cse(cfg)
    assert head.instructions == [
        Assignment(Variable("c0", ssa_label=0), expr1.copy()),
        Branch(Condition(OperationType.greater, [Variable("a", ssa_label=0), Constant(0, Integer.int32_t())])),
    ]


def test_dereference_is_not_propagated():
    """
    Check that expressions containing dereference operations are nor propagated.

    +-----------------------+
    |          0.           |
    |  foo((*(x#0)) + 0xc)  |
    |  foo((*(x#0)) + 0xc)  |
    |  foo((*(x#0)) + 0xc)  |
    | return (*(x#0)) + 0xc |
    +-----------------------+
    """
    cfg = ControlFlowGraph()
    expression = BinaryOperation(
        OperationType.plus, [UnaryOperation(OperationType.dereference, [Variable("x", ssa_label=0)]), Constant(12)]
    )
    original_instructions = [
        Assignment(ListOperation([]), Call(function_symbol("foo"), [expression.copy()])),
        Assignment(ListOperation([]), Call(function_symbol("foo"), [expression.copy()])),
        Assignment(ListOperation([]), Call(function_symbol("foo"), [expression.copy()])),
        Return([expression.copy()]),
    ]
    cfg.add_node(BasicBlock(0, instructions=[inst.copy() for inst in original_instructions]))
    _run_cse(cfg)
    assert list(cfg.instructions) == original_instructions


def test_branch_condition_not_replaced():
    """Check that branch conditions are not replaced"""
    cfg = ControlFlowGraph()
    condition = Condition(OperationType.less, [Variable("x", ssa_label=0), Constant(12)])
    original_instructions = [
        Assignment(Variable("x", ssa_label=0), Call(function_symbol("foo"), [])),
        Branch(condition.copy()),
        Assignment(Variable("u", ssa_label=1), Call(function_symbol("bar"), [])),
        Branch(condition.copy()),
        Assignment(Variable("v", ssa_label=1), Call(function_symbol("bar"), [])),
        Branch(condition.copy()),
        Return([Variable("u", ssa_label=1)]),
        Return([Variable("v", ssa_label=1)]),
    ]
    nodes = [
        BasicBlock(0, instructions=[original_instructions[0].copy(), original_instructions[1].copy()]),
        BasicBlock(1, instructions=[original_instructions[2].copy()]),
        BasicBlock(2, instructions=[original_instructions[3].copy()]),
        BasicBlock(3, instructions=[original_instructions[4].copy()]),
        BasicBlock(4, instructions=[original_instructions[5].copy()]),
        BasicBlock(5, instructions=[original_instructions[6].copy()]),
        BasicBlock(6, instructions=[original_instructions[7].copy()]),
    ]
    cfg.add_nodes_from(nodes)
    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[1]),
            FalseCase(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[2]),
            TrueCase(nodes[2], nodes[3]),
            FalseCase(nodes[2], nodes[4]),
            UnconditionalEdge(nodes[3], nodes[4]),
            TrueCase(nodes[4], nodes[5]),
            FalseCase(nodes[4], nodes[6]),
        ]
    )
    _run_cse(cfg, _generate_options(threshold=3))
    assert list(cfg.instructions) == original_instructions


def test_branch_sub_condition_replaced():
    """Check that branch conditions are not replaced"""
    cfg = ControlFlowGraph()
    subexpression = BinaryOperation(OperationType.multiply, [Variable("x", ssa_label=0), Constant(2)])
    condition = Condition(OperationType.less, [subexpression, Constant(12)])
    original_instructions = [
        Assignment(Variable("x", ssa_label=0), Call(function_symbol("foo"), [])),
        Branch(condition.copy()),
        Assignment(Variable("u", ssa_label=1), Call(function_symbol("bar"), [])),
        Branch(condition.copy()),
        Assignment(Variable("v", ssa_label=1), Call(function_symbol("bar"), [])),
        Branch(condition.copy()),
        Return([Variable("u", ssa_label=1)]),
        Return([Variable("v", ssa_label=1)]),
    ]
    nodes = [
        BasicBlock(0, instructions=[original_instructions[0].copy(), original_instructions[1].copy()]),
        BasicBlock(1, instructions=[original_instructions[2].copy()]),
        BasicBlock(2, instructions=[original_instructions[3].copy()]),
        BasicBlock(3, instructions=[original_instructions[4].copy()]),
        BasicBlock(4, instructions=[original_instructions[5].copy()]),
        BasicBlock(5, instructions=[original_instructions[6].copy()]),
        BasicBlock(6, instructions=[original_instructions[7].copy()]),
    ]
    cfg.add_nodes_from(nodes)
    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[1]),
            FalseCase(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[2]),
            TrueCase(nodes[2], nodes[3]),
            FalseCase(nodes[2], nodes[4]),
            UnconditionalEdge(nodes[3], nodes[4]),
            TrueCase(nodes[4], nodes[5]),
            FalseCase(nodes[4], nodes[6]),
        ]
    )
    _run_cse(cfg, _generate_options(threshold=3))
    replacement = Variable("c0", ssa_label=0)
    new_branch = Branch(Condition(OperationType.less, [replacement, Constant(12)]))
    assert (
        nodes[0].instructions == [original_instructions[0], Assignment(replacement, subexpression), new_branch]
        and nodes[1].instructions == [original_instructions[2]]
        and nodes[2].instructions == [new_branch]
        and nodes[3].instructions == [original_instructions[4]]
        and nodes[4].instructions == [new_branch]
        and nodes[5].instructions == [original_instructions[6]]
        and nodes[6].instructions == [original_instructions[7]]
    )


def test_domination_of_replacement():
    """
    only one defined subexpression dominates a usage.
      +-----------------------------------------------------------------+
      |                                                                 |
      |                               +------------------------------+  |
      |                               |              0.              |  |
      |                               +------------------------------+  |
      |                                 |                               |
      |                                 |                               |
      |                                 v                               v
    +---------------------------+     +-------------------------------------+
    |            3.             |     |                 1.                  |
    |   printf("value is: %d    |     | var_10#2 = ϕ(0xa,var_10#3,var_10#4) |
    |       ", var_10#2)        |     |         if(var_10#2 > 0xf)          |
    | var_10#4 = var_10#2 + 0x1 | <-- |                                     |
    +---------------------------+     +-------------------------------------+
                                        |                               ^
                                        |                               |
                                        v                               |
    +---------------------------+     +------------------------------+  |
    |                           |     |              2.              |  |
    |            5.             |     |    printf("value of a: %d    |  |
    |        return 0x0         |     |         ", var_10#2)         |  |
    |                           |     |  var_10#3 = var_10#2 + 0x1   |  |
    |                           | <-- | if((var_10#2 + 0x1) <= 0x13) |  |
    +---------------------------+     +------------------------------+  |
                                        |                               |
                                        |                               |
                                        v                               |
                                      +------------------------------+  |
                                      |              4.              | -+
                                      +------------------------------+
    """
    cfg = ControlFlowGraph()
    var = [Variable("var_10", Integer(32, True), i, False, None) for i in range(5)]
    sub_expr = BinaryOperation(OperationType.plus, [var[2], Constant(1, Integer(32, True))], Integer(32, True))
    instrs = [
        Phi(var[2], [Constant(10, Integer(32, True)), var[3], var[4]]),
        create_branch(OperationType.greater, var[2], Constant(15, Integer(32, True))),
        printf_call("value of a: %d\n", var[2], 2),
        Assignment(var[3], sub_expr.copy()),
        create_branch(OperationType.less_or_equal, sub_expr.copy(), Constant(19, Integer(32, True))),
        printf_call("value is: %d\n", var[2], 3),
        Assignment(var[4], sub_expr.copy()),
        Return(ListOperation([Constant(0, Integer(32, True))])),
    ]

    cfg.add_nodes_from(
        nodes := [
            BasicBlock(0, []),
            BasicBlock(1, [i.copy() for i in instrs[0:2]]),
            BasicBlock(2, [i.copy() for i in instrs[2:5]]),
            BasicBlock(3, [i.copy() for i in instrs[5:7]]),
            BasicBlock(4, []),
            BasicBlock(5, [i.copy() for i in instrs[7:]]),
        ]
    )
    instrs[0]._origin_block = {nodes[0]: Constant(10, Integer(32, True)), nodes[3]: var[4], nodes[4]: var[3]}
    nodes[1].instructions[0]._origin_block = {nodes[0]: Constant(10, Integer(32, True)), nodes[3]: var[4], nodes[4]: var[3]}

    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            TrueCase(nodes[1], nodes[2]),
            FalseCase(nodes[1], nodes[3]),
            TrueCase(nodes[2], nodes[4]),
            FalseCase(nodes[2], nodes[5]),
            UnconditionalEdge(nodes[3], nodes[1]),
            UnconditionalEdge(nodes[4], nodes[1]),
        ]
    )

    _run_cse(cfg)
    assert (
        nodes[0].instructions == []
        and nodes[1].instructions == instrs[0:2]
        and nodes[2].instructions == instrs[2:4] + [create_branch(OperationType.less_or_equal, var[3], Constant(19, Integer(32, True)))]
        and nodes[3].instructions == instrs[5:7]
        and nodes[4].instructions == []
        and nodes[5].instructions == instrs[7:]
    )


def create_branch(operation_type: OperationType, op1: Expression, op2: Expression):
    return Branch(Condition(operation_type, [op1, op2], CustomType("bool", 1)))


def printf_call(string: Union[str, int], var: Expression, memory: int, signed=False) -> Assignment:
    return Assignment(
        ListOperation([]),
        Call(
            imp_function_symbol("printf"),
            [Constant(string, Pointer(Integer(8, signed), 32)), var],
            Pointer(CustomType("void", 0), 32),
            memory,
        ),
    )


def test_no_definition_of_phi_function():
    """The dictionary _defining_variable_of that maps expression to their definition should not contain Phi-function definitions.
                 +--------------------------------------------------+
                 |                        0.                        |
                 |             __x86.get_pc_thunk.bx()              |
                 |  __printf_chk(0x1, "Enter week number (1-7): ")  |
                 |              var_28#1 = &(var_10#0)              |
                 | ecx_1#2,edx_1#2 = __isoc99_scanf("%d", var_28#1) |
                 |               if(var_10#0 != 0x1)                | -+
                 +--------------------------------------------------+  |
                   |                                                   |
                   |                                                   |
                   v                                                   |
                 +--------------------------------------------------+  |
                 |                        1.                        |  |
              +- |               if(var_10#0 != 0x2)                |  |
              |  +--------------------------------------------------+  |
              |    |                                                   |
              |    |                                                   |
              |    v                                                   |
              |  +--------------------------------------------------+  |
              |  |                        2.                        |  |
              |  |               if(var_10#0 != 0x3)                | -+-------------+
              |  +--------------------------------------------------+  |             |
              |    |                                                   |             |
              |    |                                                   |             |
              |    v                                                   |             |
              |  +--------------------------------------------------+  |             |
              |  |                        4.                        |  |             |
         +----+- | __printf_chk(0x1, eax_1#10, var_24#9, var_20#9)  |  |             |
         |    |  +--------------------------------------------------+  |             |
         |    |    |                                                   |             |
         |    |    |                                                   |             |
         |    |    v                                                   |             |
         |    |  +--------------------------------------------------+  |             |
         |    |  |                        5.                        |  |             |
         |    |  |                    return 0x0                    | -+-------------+------------+
         |    |  +--------------------------------------------------+  |             |            |
         |    |    |                                                   |             |            |
         |    |    |                                                   |             |            |
         |    |    v                                                   |             |            |
         |    |  +--------------------------------------------------+  |             |            |
         |    |  |                        6.                        |  |             |            |
    +----+----+- |               if(var_10#0 != 0x4)                |  |             |            |
    |    |    |  +--------------------------------------------------+  |             |            |
    |    |    |    |                                                   |             |            |
    |    |    |    |                                                   |             |            |
    |    |    |    v                                                   |             |            |
    |    |    |  +--------------------------------------------------+  |             |            |
    |    |    |  |                        7.                        |  |             |            |
    |    |    |  |               if(var_10#0 != 0x5)                | -+-------------+------------+------------+
    |    |    |  +--------------------------------------------------+  |             |            |            |
    |    |    |    |                                                   |             |            |            |
    |    |    |    |                                                   |             |            |            |
    |    |    |    v                                                   |             |            |            |
    |    |    |  +--------------------------------------------------+  |             |            |            |
    |    |    |  |                        8.                        |  |             |            |            |
    |    |    |  +--------------------------------------------------+  |             |            |            |
    |    |    |    |                                                   |             |            |            |
    |    |    |    |                                                   |             |            |            |
    |    |    |    v                                                   v             v            v            v
    |    |    |  +-------------------------------------------------------------------------------------------------------+
    |    |    +> |                                                                                                       |
    |    |       |                                                  3.                                                   |
    |    |       |          var_24#9 = ϕ(var_10#0,edx_1#2,ecx_1#2,var_10#0,var_10#0,var_10#0,var_10#0,var_10#0)          |
    |    +-----> |          var_20#9 = ϕ(var_10#0,edx_1#2,ecx_1#2,var_10#0,var_10#0,var_10#0,var_10#0,var_10#0)          |
    |            | eax_1#10 = ϕ("Invalid Input!","Sunday","Saturday","Friday","Thursday","Wednesday","Tuesday","Monday") |
    |            |                                                                                                       |
    +----------> |                                                                                                       |
                 +-------------------------------------------------------------------------------------------------------+

    """
    cfg = ControlFlowGraph()
    var_eax = Variable("eax_1", Pointer(Integer(8, True), 32), 10, False, None)
    var_ecx = Variable("ecx_1", Integer(32, True), 2, False, None)
    var_edx = Variable("edx_1", Integer(32, True), 2, False, None)
    var_10 = Variable("var_10", Integer(32, True), 0, False, None)
    var_20 = Variable("var_20", Integer(32, True), 9, False, None)
    var_24 = Variable("var_24", Integer(32, True), 9, False, None)
    var_28 = Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    void_pointer = Pointer(CustomType("void", 0), 32)

    def constant_8(string: str) -> Constant:
        return Constant(string, Pointer(Integer(8, False), 32))

    def constant_32(integer: int) -> Constant:
        return Constant(integer, Integer(32, True))

    instructions = [  # BasicBlock 0: 0-4
        Assignment(ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], void_pointer, 1)),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("__printf_chk"), [constant_32(1), constant_8("Enter week number (1-7): ")], void_pointer, 2),
        ),
        Assignment(var_28, UnaryOperation(OperationType.address, [var_10], Pointer(Integer(32, True), 32), None, False)),
        Assignment(
            ListOperation([var_ecx, var_edx]),
            Call(imp_function_symbol("__isoc99_scanf"), [constant_8("%d"), var_28], void_pointer, 3),
        ),
        Branch(Condition(OperationType.not_equal, [var_10, constant_32(1)], CustomType("bool", 1))),
        # vertex 1: 5
        Branch(Condition(OperationType.not_equal, [var_10, constant_32(2)], CustomType("bool", 1))),
        # vertex 3: 6
        Branch(Condition(OperationType.not_equal, [var_10, constant_32(3)], CustomType("bool", 1))),
        # vertex 5: 7-9
        Phi(var_24, [var_10, var_edx, var_ecx, var_10, var_10, var_10, var_10, var_10]),
        Phi(var_20, [var_10, var_edx, var_ecx, var_10, var_10, var_10, var_10, var_10]),
        Phi(
            var_eax,
            [
                constant_8("Invalid Input!"),
                constant_8("Sunday"),
                constant_8("Saturday"),
                constant_8("Friday"),
                constant_8("Thursday"),
                constant_8("Wednesday"),
                constant_8("Tuesday"),
                constant_8("Monday"),
            ],
        ),
        Assignment(
            ListOperation([]),
            Call(
                imp_function_symbol("__printf_chk"),
                [
                    constant_32(1),
                    var_eax,
                    var_24,
                    var_20,
                ],
                void_pointer,
                4,
            ),
        ),
        Return(ListOperation([constant_32(0)])),
        # BasicBlock 6
        Branch(Condition(OperationType.not_equal, [var_10, constant_32(4)], CustomType("bool", 1))),
        # BasicBlock 8
        Branch(Condition(OperationType.not_equal, [var_10, constant_32(5)], CustomType("bool", 1))),
        # BasicBlock 10
        Branch(Condition(OperationType.not_equal, [var_10, constant_32(6)], CustomType("bool", 1))),
        # BasicBlock 12
        Branch(Condition(OperationType.not_equal, [var_10, constant_32(7)], CustomType("bool", 1))),
    ]

    cfg.add_nodes_from(
        nodes := [
            BasicBlock(0, [i.copy() for i in instructions[:5]]),
            BasicBlock(1, [instructions[5].copy()]),
            BasicBlock(2, [instructions[6].copy()]),
            BasicBlock(3, [i.copy() for i in instructions[7:10]]),
            BasicBlock(4, [instructions[10].copy()]),
            BasicBlock(5, [instructions[11].copy()]),
            BasicBlock(6, [instructions[12].copy()]),
            BasicBlock(7, [instructions[13].copy()]),
            BasicBlock(8, []),
        ]
    )
    instructions[5]._origin_block = {
        nodes[0]: var_10,
        nodes[1]: var_10,
        nodes[2]: var_10,
        nodes[4]: var_10,
        nodes[5]: var_10,
        nodes[6]: var_ecx,
        nodes[8]: var_10,
        nodes[7]: var_edx,
    }
    nodes[3].instructions[0]._origin_block = {
        nodes[0]: var_10,
        nodes[1]: var_10,
        nodes[2]: var_10,
        nodes[4]: var_10,
        nodes[5]: var_10,
        nodes[6]: var_ecx,
        nodes[8]: var_10,
        nodes[7]: var_edx,
    }
    instructions[6]._origin_block = {
        nodes[0]: var_10,
        nodes[1]: var_10,
        nodes[2]: var_10,
        nodes[4]: var_10,
        nodes[5]: var_10,
        nodes[6]: var_ecx,
        nodes[8]: var_10,
        nodes[7]: var_edx,
    }
    nodes[3].instructions[1]._origin_block = {
        nodes[0]: var_10,
        nodes[1]: var_10,
        nodes[2]: var_10,
        nodes[4]: var_10,
        nodes[5]: var_10,
        nodes[6]: var_ecx,
        nodes[8]: var_10,
        nodes[7]: var_edx,
    }
    instructions[7]._origin_block = {
        nodes[0]: constant_8("Monday"),
        nodes[1]: constant_8("Tuesday"),
        nodes[2]: constant_8("Wednesday"),
        nodes[4]: constant_8("Thursday"),
        nodes[5]: constant_8("Friday"),
        nodes[6]: constant_8("Saturday"),
        nodes[8]: constant_8("Invalid Input!"),
        nodes[7]: constant_8("Sunday"),
    }
    nodes[3].instructions[2]._origin_block = {
        nodes[0]: constant_8("Monday"),
        nodes[1]: constant_8("Tuesday"),
        nodes[2]: constant_8("Wednesday"),
        nodes[4]: constant_8("Thursday"),
        nodes[5]: constant_8("Friday"),
        nodes[6]: constant_8("Saturday"),
        nodes[8]: constant_8("Invalid Input!"),
        nodes[7]: constant_8("Sunday"),
    }

    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[1]),
            FalseCase(nodes[0], nodes[3]),
            TrueCase(nodes[1], nodes[2]),
            FalseCase(nodes[1], nodes[3]),
            TrueCase(nodes[2], nodes[4]),
            FalseCase(nodes[2], nodes[3]),
            TrueCase(nodes[4], nodes[5]),
            FalseCase(nodes[4], nodes[3]),
            TrueCase(nodes[5], nodes[6]),
            FalseCase(nodes[5], nodes[3]),
            TrueCase(nodes[6], nodes[7]),
            FalseCase(nodes[6], nodes[3]),
            TrueCase(nodes[7], nodes[8]),
            FalseCase(nodes[7], nodes[3]),
            UnconditionalEdge(nodes[8], nodes[3]),
        ]
    )

    _run_cse(cfg)

    assert nodes[0].instructions == instructions[0:5]
    assert nodes[1].instructions == [instructions[5]]
    assert nodes[2].instructions == [instructions[6]]
    assert nodes[3].instructions == instructions[7:10]
    assert nodes[4].instructions == [instructions[10]]
    assert nodes[5].instructions == [instructions[11]]
    assert nodes[6].instructions == [instructions[12]]
    assert nodes[7].instructions == [instructions[13]]
    assert nodes[8].instructions == []


def test_do_not_propagate_aliased_over_relation():
    """
    test_memory test1
    +-----------------------------+  +-----------------------------+
    |             0.              |  |             0.              |
    |       eax#1 = rand()        |  |       eax#1 = rand()        |
    |   var_18#2 = eax#1 + 0x5    |  |   var_18#2 = eax#1 + 0x5    |
    |   var_10#1 = &(var_18#2)    |  |   var_10#1 = &(var_18#2)    |
    |      eax_3#4 = rand()       |  |      eax_3#4 = rand()       |
    |   var_18#3 = eax#1 + 0x5    |  |     var_18#3 = var_18#2     |
    | *(var_10#1) = eax_3#4 + 0xa |  | *(var_10#1) = eax_3#4 + 0xa |
    |    var_18#4 -> var_18#3     |  |    var_18#4 -> var_18#3     |
    |     printf("POINTER %d      |  |     printf("POINTER %d      |
    |       ", *(var_10#1))       |  |       ", *(var_10#1))       |
    |     return eax#1 + 0x5      |  |     return eax#1 + 0x5      |
    +-----------------------------+  +-----------------------------+
    """
    cfg = ControlFlowGraph()
    eax_1 = Variable("eax", Integer(32, True), 1, False, None)
    eax_3_4 = Variable("eax_3", Integer(32, True), 4, False, None)
    var_18_2 = Variable("var_18", Integer(32, True), 2, True, None)
    var_18_3 = Variable("var_18", Integer(32, True), 3, True, None)
    var_18_4 = Variable("var_18", Integer(32, True), 4, True, None)
    var_10_1 = Variable("var_10", Pointer(Integer(32, True), 32), 1, False, None)
    instructions = [
        Assignment(ListOperation([eax_1]), Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 1)),
        Assignment(var_18_2, BinaryOperation(OperationType.plus, [eax_1, Constant(5, Integer(32, True))], Integer(32, True))),
        Assignment(var_10_1, UnaryOperation(OperationType.address, [var_18_2], Pointer(Integer(32, True), 32), None, False)),
        Assignment(ListOperation([eax_3_4]), Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 3)),
        Assignment(var_18_3, BinaryOperation(OperationType.plus, [eax_1, Constant(5, Integer(32, True))], Integer(32, True))),
        Assignment(
            UnaryOperation(OperationType.dereference, [var_10_1], Pointer(Integer(32, True), 32), 4, False),
            BinaryOperation(OperationType.plus, [eax_3_4, Constant(10, Integer(32, True))], Pointer(Integer(32, True), 32)),
        ),
        Relation(var_18_4, var_18_3),
        Assignment(
            ListOperation([]),
            Call(
                imp_function_symbol("printf"),
                [
                    Constant(134520844, Pointer(Integer(8, True), 32)),
                    UnaryOperation(OperationType.dereference, [var_10_1], Integer(32, True), None, False),
                ],
                Pointer(CustomType("void", 0), 32),
                5,
            ),
        ),
        Return(ListOperation([BinaryOperation(OperationType.plus, [eax_1, Constant(5, Integer(32, True))], Integer(32, True))])),
    ]

    cfg.add_node(BasicBlock(0, instructions[:]))
    old_inst = [inst.copy() for inst in instructions]
    _run_cse(cfg)
    assert list(cfg.instructions) == old_inst[:4] + [Assignment(var_18_3, var_18_2)] + old_inst[5:]


def test_propagate_over_relation_if_not_connected():
    """
    test_memory test1 modified.
    +-----------------------------+  +-----------------------------+
    |             0.              |  |             0.              |
    |       eax#1 = rand()        |  |       eax#1 = rand()        |
    |   var_15#2 = eax#1 + 0x5    |  |   var_15#2 = eax#1 + 0x5    |
    |   var_10#1 = &(var_18#2)    |  |   var_10#1 = &(var_18#2)    |
    |      eax_3#4 = rand()       |  |      eax_3#4 = rand()       |
    |   var_18#3 = eax#1 + 0x5    |  |     var_18#3 = var_15#2     |
    | *(var_10#1) = eax_3#4 + 0xa |  | *(var_10#1) = eax_3#4 + 0xa |
    |    var_18#4 -> var_18#3     |  |    var_18#4 -> var_18#3     |
    |     printf("POINTER %d      |  |     printf("POINTER %d      |
    |       ", *(var_10#1))       |  |       ", *(var_10#1))       |
    |     return eax#1 + 0x5      |  |     return var_15#2         |
    +-----------------------------+  +-----------------------------+
    """
    cfg = ControlFlowGraph()
    eax_1 = Variable("eax", Integer(32, True), 1, False, None)
    eax_3_4 = Variable("eax_3", Integer(32, True), 4, False, None)
    var_15_2 = Variable("var_15", Integer(32, True), 2, True, None)
    var_18_2 = Variable("var_18", Integer(32, True), 2, True, None)
    var_18_3 = Variable("var_18", Integer(32, True), 3, True, None)
    var_18_4 = Variable("var_18", Integer(32, True), 4, True, None)
    var_10_1 = Variable("var_10", Pointer(Integer(32, True), 32), 1, False, None)
    instructions = [
        Assignment(ListOperation([eax_1]), Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 1)),
        Assignment(var_15_2, BinaryOperation(OperationType.plus, [eax_1, Constant(5, Integer(32, True))], Integer(32, True))),
        Assignment(var_10_1, UnaryOperation(OperationType.address, [var_18_2], Pointer(Integer(32, True), 32), None, False)),
        Assignment(ListOperation([eax_3_4]), Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 3)),
        Assignment(var_18_3, BinaryOperation(OperationType.plus, [eax_1, Constant(5, Integer(32, True))], Integer(32, True))),
        Assignment(
            UnaryOperation(OperationType.dereference, [var_10_1], Pointer(Integer(32, True), 32), 4, False),
            BinaryOperation(OperationType.plus, [eax_3_4, Constant(10, Integer(32, True))], Pointer(Integer(32, True), 32)),
        ),
        Relation(var_18_4, var_18_3),
        Assignment(
            ListOperation([]),
            Call(
                imp_function_symbol("printf"),
                [
                    Constant(134520844, Pointer(Integer(8, True), 32)),
                    UnaryOperation(OperationType.dereference, [var_10_1], Integer(32, True), None, False),
                ],
                Pointer(CustomType("void", 0), 32),
                5,
            ),
        ),
        Return(ListOperation([BinaryOperation(OperationType.plus, [eax_1, Constant(5, Integer(32, True))], Integer(32, True))])),
    ]

    cfg.add_node(BasicBlock(0, instructions[:]))
    old_inst = [inst.copy() for inst in instructions]
    _run_cse(cfg)
    assert list(cfg.instructions) == old_inst[:4] + [Assignment(var_18_3, var_15_2)] + old_inst[5:8] + [Return(ListOperation([var_15_2]))]


def test_no_propagation_over_aliased_on_path():
    """
    test memory test19
    +----+     +-----------------------------------------+                                             +----+     +-----------------------------------------+
    |    |     |                   0.                    |                                             |    |     |                   0.                    |
    |    |     |             eax#1 = rand()              |                                             |    |     |             eax#1 = rand()              |
    |    |     |         var_18#2 = eax#1 + 0x1          |                                             |    |     |         var_18#2 = eax#1 + 0x1          |
    |    |     |         var_14#1 = &(var_18#2)          |                                             |    |     |         var_14#1 = &(var_18#2)          |
    | 1. |     | printf("first block x %d", eax#1 + 0x1) |                                             | 1. |     |   printf("first block x %d", var_18#2)  |
    |    |     |         var_18#3 = eax#1 + 0x1          |                                             |    |     |         var_18#3 = var_18#2             |
    |    |     |        __isoc99_scanf(var_14#1)         |                                             |    |     |        __isoc99_scanf(var_14#1)         |
    |    |     |          var_18#4 -> var_18#3           |                                             |    |     |          var_18#4 -> var_18#3           |
    |    | <-- |           if(var_1c#0 <= 0xa)           |                                             |    | <-- |           if(var_1c#0 <= 0xa)           |
    +----+     +-----------------------------------------+                                             +----+     +-----------------------------------------+
      |          |                                                                                       |          |
      |          |                                                                                       |          |
      |          v                                                                                       |          v
      |        +-----------------------------------------+     +------------------------------------+    |        +-----------------------------------------+     +------------------------------------+
      |        |                   2.                    |     |                                    |    |        |                   2.                    |     |                                    |
      |        |    printf("first if x %d", var_18#4)    |     |                                    |    |        |    printf("first if x %d", var_18#4)    |     |                                    |
      |        |        var_28_2#3 = &(var_1c#0)         |     |                 5.                 |    |        |        var_28_2#3 = &(var_1c#0)         |     |                 5.                 |
      |        |  __isoc99_scanf(0x804a018, var_28_2#3)  |     | printf("second if x %d", var_18#4) |    |        |  __isoc99_scanf(0x804a018, var_28_2#3)  |     | printf("second if x %d", var_18#4) |
      |        |          var_1c#6 -> var_1c#0           |     |                                    |    |        |          var_1c#6 -> var_1c#0           |     |                                    |
      |        |           if(var_1c#6 > 0x9)            | --> |                                    |    |        |           if(var_1c#6 > 0x9)            | --> |                                    |
      |        +-----------------------------------------+     +------------------------------------+    |        +-----------------------------------------+     +------------------------------------+
      |          |                                               |                                       |          |                                               |
      |          |                                               |                                       |          |                                               |
      |          v                                               |                                       |          v                                               |
      |        +-----------------------------------------+       |                                       |        +-----------------------------------------+       |
      |        |                   4.                    |       |                                       |        |                   4.                    |       |
      |        +-----------------------------------------+       |                                       |        +-----------------------------------------+       |
      |          |                                               |                                       |          |                                               |
      |          |                                               |                                       |          |                                               |
      |          v                                               |                                       |          v                                               |
      |        +-----------------------------------------+       |                                       |        +-----------------------------------------+       |
      |        |                   3.                    |       |                                       |        |                   3.                    |       |
      |        |       printf("ptr %d", var_18#4)        |       |                                       |        |       printf("ptr %d", var_18#4)        |       |
      +------> |           return eax#1 + 0x1            | <-----+                                       +------> |            return eax#1 + 0x1           | <-----+
               +-----------------------------------------+                                                        +-----------------------------------------+
    """
    cfg = ControlFlowGraph()
    eax_1 = Variable("eax", Integer(32, True), 1, False, None)
    var_18_2 = Variable("var_18", Integer(32, True), 2, True, None)
    var_14_1 = Variable("var_14", Pointer(Integer(32, True), 32), 1, False, None)
    var_18_3 = Variable("var_18", Integer(32, True), 3, True, None)
    var_18_4 = Variable("var_18", Integer(32, True), 4, True, None)
    var_1c_0 = Variable("var_1c", Integer(32, True), 0, True, None)
    var_28_2_3 = Variable("var_28_2", Pointer(Integer(32, True), 32), 3, False, None)
    var_1c_6 = Variable("var_1c", Integer(32, True), 6, True, None)
    instructions = [
        # vertex 0
        Assignment(ListOperation([eax_1]), Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 1)),
        Assignment(var_18_2, BinaryOperation(OperationType.plus, [eax_1, Constant(1, Integer(32, True))], Integer(32, True))),
        Assignment(var_14_1, UnaryOperation(OperationType.address, [var_18_2], Pointer(Integer(32, True), 32), None, False)),
        printf_call(
            134520859,
            BinaryOperation(OperationType.plus, [eax_1, Constant(1, Integer(32, True))], Integer(32, True)),
            3,
            signed=True,
        ),
        Assignment(var_18_3, BinaryOperation(OperationType.plus, [eax_1, Constant(1, Integer(32, True))], Integer(32, True))),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("__isoc99_scanf"), [var_14_1], Pointer(CustomType("void", 0), 32), 4),
        ),
        Relation(var_18_4, var_18_3),
        Branch(Condition(OperationType.less_or_equal, [var_1c_0, Constant(10, Integer(32, True))], CustomType("bool", 1))),
        # BasicBlock 2
        printf_call(134520876, var_18_4, 5, signed=True),
        Assignment(
            var_28_2_3,
            UnaryOperation(OperationType.address, [var_1c_0], Pointer(Integer(32, True), 32), None, False),
        ),
        Assignment(
            ListOperation([]),
            Call(
                imp_function_symbol("__isoc99_scanf"),
                [Constant(134520856, Integer(32, True)), var_28_2_3],
                Pointer(CustomType("void", 0), 32),
                6,
            ),
        ),
        Relation(var_1c_6, var_1c_0),
        Branch(Condition(OperationType.greater, [var_1c_6, Constant(9, Integer(32, True))], CustomType("bool", 1))),
        # BasicBlock 3
        printf_call(134520905, var_18_4, 9, signed=True),
        Return(ListOperation([BinaryOperation(OperationType.plus, [eax_1, Constant(1, Integer(32, True))], Integer(32, True))])),
        # BasicBlock 5
        printf_call(134520890, var_18_4, 7, signed=True),
    ]

    cfg.add_nodes_from(
        vertices := [
            BasicBlock(0, [i.copy() for i in instructions[:8]]),
            BasicBlock(1, []),
            BasicBlock(2, [i.copy() for i in instructions[8:13]]),
            BasicBlock(3, [i.copy() for i in instructions[13:15]]),
            BasicBlock(4, []),
            BasicBlock(5, [i.copy() for i in instructions[15:]]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            TrueCase(vertices[2], vertices[4]),
            FalseCase(vertices[2], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[3]),
            UnconditionalEdge(vertices[5], vertices[3]),
        ]
    )
    _run_cse(cfg)
    assert (
        vertices[0].instructions
        == instructions[0:3] + [printf_call(134520859, var_18_2, 3, signed=True), Assignment(var_18_3, var_18_2)] + instructions[5:8]
    )
    assert vertices[1].instructions == []
    assert vertices[2].instructions == instructions[8:13]
    assert vertices[3].instructions == instructions[13:15]
    assert vertices[4].instructions == []
    assert vertices[5].instructions == instructions[15:]


def test_complex_string_elimination_1():
    """Checks if complex string constants are eliminated."""

    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(
                    ListOperation([Variable("rax", Integer(32, True), 1)]),
                    Call(imp_function_symbol("strlen"), [Constant("abcdefghijklmnop", Pointer(Integer(8), 32))]),
                ),
                Assignment(
                    ListOperation([]),
                    Call(
                        function_symbol("print_str_with_length"),
                        [Constant("abcdefghijklmnop", Pointer(Integer(8), 32)), Variable("rax", Integer(32, True), 1)],
                    ),
                ),
                Return(ListOperation([Constant(0, Integer(64, True))])),
            ],
        )
    )

    _run_cse(cfg, _generate_options(str_threshold=2, min_str_length=10))

    assert node.instructions == [
        Assignment(Variable("c0", Pointer(Integer(8, False), 32), 0), Constant("abcdefghijklmnop", Pointer(Integer(8), 32))),
        Assignment(
            ListOperation([Variable("rax", Integer(32, True), 1)]),
            Call(
                imp_function_symbol("strlen"),
                [Variable("c0", Pointer(Integer(8, False), 32), 0)],
            ),
        ),
        Assignment(
            ListOperation([]),
            Call(
                function_symbol("print_str_with_length"),
                [Variable("c0", Pointer(Integer(8, False), 32), 0), Variable("rax", Integer(32, True), 1)],
            ),
        ),
        Return(ListOperation([Constant(0, Integer(64, True))])),
    ]


def test_complex_string_elimination_2():
    """Do not replace string with variable if threshold is too low."""

    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(
                    ListOperation([Variable("rax", Integer(32, True), 1)]),
                    Call(imp_function_symbol("strlen"), [Constant("abcdefghijklmnop", Pointer(Integer(8), 32))]),
                ),
                Assignment(
                    ListOperation([]),
                    Call(
                        function_symbol("print_str_with_length"),
                        [Constant("abcdefghijklmnop", Pointer(Integer(8), 32)), Variable("rax", Integer(32, True), 1)],
                    ),
                ),
                Return(ListOperation([Constant(0, Integer(64, True))])),
            ],
        )
    )

    _run_cse(cfg, _generate_options(str_threshold=3, min_str_length=10))

    assert node.instructions == [
        Assignment(
            ListOperation([Variable("rax", Integer(32, True), 1)]),
            Call(imp_function_symbol("strlen"), [Constant("abcdefghijklmnop", Pointer(Integer(8), 32))]),
        ),
        Assignment(
            ListOperation([]),
            Call(
                function_symbol("print_str_with_length"),
                [Constant("abcdefghijklmnop", Pointer(Integer(8), 32)), Variable("rax", Integer(32, True), 1)],
            ),
        ),
        Return(ListOperation([Constant(0, Integer(64, True))])),
    ]


def test_complex_string_elimination_inter():
    """Inter: do not find duplicates in same instruction."""

    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(
                    ListOperation([Variable("rax", Integer(32, True), 1)]),
                    Call(
                        imp_function_symbol("strlen"),
                        [Constant("abcdefghijklmnop", Pointer(Integer(8), 32)), Constant("abcdefghijklmnop", Pointer(Integer(8), 32))],
                    ),
                ),
            ],
        )
    )

    _run_cse(cfg, _generate_options(str_threshold=2, min_str_length=10, intra=False))

    assert node.instructions == [
        Assignment(
            ListOperation([Variable("rax", Integer(32, True), 1)]),
            Call(
                imp_function_symbol("strlen"),
                [Constant("abcdefghijklmnop", Pointer(Integer(8), 32)), Constant("abcdefghijklmnop", Pointer(Integer(8), 32))],
            ),
        ),
    ]


def test_complex_string_elimination_intra():
    """Inter: do not find duplicates in same instruction."""

    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(
                    ListOperation([Variable("rax", Integer(32, True), 1)]),
                    Call(
                        imp_function_symbol("strlen"),
                        [Constant("abcdefghijklmnop", Pointer(Integer(8), 32)), Constant("abcdefghijklmnop", Pointer(Integer(8), 32))],
                    ),
                ),
            ],
        )
    )

    _run_cse(cfg, _generate_options(str_threshold=2, min_str_length=10, intra=True))

    assert node.instructions == [
        Assignment(Variable("c0", Pointer(Integer(8, False), 32), 0), Constant("abcdefghijklmnop", Pointer(Integer(8), 32))),
        Assignment(
            ListOperation([Variable("rax", Integer(32, True), 1)]),
            Call(
                imp_function_symbol("strlen"),
                [Variable("c0", Pointer(Integer(8, False), 32), 0), Variable("c0", Pointer(Integer(8, False), 32), 0)],
            ),
        ),
    ]


def test_common_subexpression_elimination_correct_place():
    """Check that the instruction is inserted at the correct position"""
    expr3 = BinaryOperation(OperationType.plus, [Variable("y", ssa_label=1), Constant(1)])
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("a", ssa_label=4), BinaryOperation(OperationType.plus, [Variable("b", ssa_label=2), expr2.copy()])),
                Assignment(Variable("c", ssa_label=1), BinaryOperation(OperationType.minus, [Variable("a", ssa_label=4), expr3.copy()])),
                Assignment(Variable("d", ssa_label=4), BinaryOperation(OperationType.plus, [Variable("e", ssa_label=2), expr2.copy()])),
                Assignment(Variable("f", ssa_label=1), BinaryOperation(OperationType.minus, [Variable("g", ssa_label=4), expr3.copy()])),
            ],
        )
    )
    _run_cse(cfg, _generate_options(threshold=2))
    assert len(node.instructions) == 6
    replacement0 = Variable("c0", ssa_label=0)
    replacement1 = Variable("c1", ssa_label=0)
    assert node.instructions == [
        Assignment(replacement0.copy(), expr2.copy()),
        Assignment(Variable("a", ssa_label=4), BinaryOperation(OperationType.plus, [Variable("b", ssa_label=2), replacement0])),
        Assignment(replacement1.copy(), expr3.copy()),
        Assignment(Variable("c", ssa_label=1), BinaryOperation(OperationType.minus, [Variable("a", ssa_label=4), replacement1])),
        Assignment(Variable("d", ssa_label=4), BinaryOperation(OperationType.plus, [Variable("e", ssa_label=2), replacement0])),
        Assignment(Variable("f", ssa_label=1), BinaryOperation(OperationType.minus, [Variable("g", ssa_label=4), replacement1])),
    ]
