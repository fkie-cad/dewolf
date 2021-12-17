import pytest
from dewolf.pipeline.commons.reaching_definitions import ReachingDefinitions
from dewolf.structures.graphs.cfg import BasicBlock, ControlFlowGraph, UnconditionalEdge
from dewolf.structures.pseudo.expressions import Constant, FunctionSymbol, ImportedFunctionSymbol, Variable
from dewolf.structures.pseudo.instructions import Assignment, Branch, Return
from dewolf.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation


def test_single_basic_block_graph(one_basic_block_cfg, a, b, c, d, func):
    """
    Test shows:
    - if there are two definitions of a variable, only the second one reaches the end of the block
    - if the variable is given to the function by reference,
    it still does not change the reaching definitions (limitation of the standard algorithm)
    """
    cfg = one_basic_block_cfg

    rd = ReachingDefinitions(cfg)
    nodes = [n for n in cfg.nodes]
    n0 = nodes[0]

    d0 = Assignment(a, b)
    d1 = Assignment(a, d)
    d3 = Assignment(c, a)

    assert rd.reach_in_block(n0) == set()
    assert rd.reach_out_block(n0) == {d1, d3}

    assert rd.reach_in_stmt(n0, 0) == set()
    assert rd.reach_out_stmt(n0, 0) == {d0}
    assert rd.reach_in_stmt(n0, 1) == {d0}
    assert rd.reach_out_stmt(n0, 1) == {d1}
    assert rd.reach_in_stmt(n0, 2) == {d1}
    assert rd.reach_out_stmt(n0, 2) == {d1}
    assert rd.reach_in_stmt(n0, 3) == {d1}
    assert rd.reach_out_stmt(n0, 3) == {d1, d3}


@pytest.fixture
def one_basic_block_cfg(a, b, c, d, func):
    d0 = Assignment(a, b)
    d1 = Assignment(a, d)
    d2 = Assignment(ListOperation([]), Call(func, [UnaryOperation(OperationType.address, [a])]))
    d3 = Assignment(c, a)

    n0 = BasicBlock(0, [d0, d1, d2, d3])

    cfg = ControlFlowGraph()
    cfg.add_node(n0)
    return cfg


def test_loop_cfg(loop_cfg, a, b):
    """Test shows that reaching definitions are correctly calculated when a variable is redefined in loop"""
    rd = ReachingDefinitions(loop_cfg)
    n0, n1, n2, n3 = (n for n in loop_cfg.nodes)

    s0 = Assignment(a, Constant(0))
    s3 = Assignment(a, BinaryOperation(OperationType.plus, [a, Constant(1)]))

    assert rd.reach_in_block(n0) == set()
    assert rd.reach_out_block(n0) == {s0}
    assert rd.reach_in_block(n1) == {s0, s3}
    assert rd.reach_out_block(n1) == {s0, s3}
    assert rd.reach_in_block(n2) == {s0, s3}
    assert rd.reach_out_block(n2) == {s3}
    assert rd.reach_in_block(n3) == {s0, s3}
    assert rd.reach_out_block(n3) == {s0, s3}

    assert rd.reach_in_stmt(n0, 0) == set()
    assert rd.reach_out_stmt(n0, 0) == {s0}
    assert rd.reach_in_stmt(n1, 0) == {s0, s3}
    assert rd.reach_out_stmt(n1, 0) == {s0, s3}
    assert rd.reach_in_stmt(n2, 0) == {s0, s3}
    assert rd.reach_out_stmt(n2, 0) == {s0, s3}
    assert rd.reach_in_stmt(n2, 1) == {s0, s3}
    assert rd.reach_out_stmt(n2, 1) == {s3}
    assert rd.reach_in_stmt(n3, 0) == {s0, s3}
    assert rd.reach_out_stmt(n3, 0) == {s0, s3}


@pytest.fixture
def loop_cfg(a, b):
    s0 = Assignment(a, Constant(0))
    s1 = Branch(Condition(OperationType.less_or_equal, [a, b]))
    s2 = [Assignment(ListOperation([]), Call(ImportedFunctionSymbol("print", 0x42), [a]))]
    s3 = Assignment(a, BinaryOperation(OperationType.plus, [a, Constant(1)]))
    s4 = Return([Constant(0)])
    n0 = BasicBlock(0, [s0])
    n1 = BasicBlock(1, [s1])
    n2 = BasicBlock(2, s2 + [s3])
    n3 = BasicBlock(3, [s4])

    cfg = ControlFlowGraph()
    cfg.add_edges_from([UnconditionalEdge(n0, n1), UnconditionalEdge(n1, n2), UnconditionalEdge(n2, n1), UnconditionalEdge(n1, n3)])
    return cfg


def test_condition_cfg(condition_cfg, a, b, c, func):
    """
    |   1.    |     |     0.     |
    | b = 0x6 |     |  b = 0x7   |
    |  a = b  |     |   a = b    |
    |         | <-- | if(a <= b) |
    +---------+     +------------+
      |               |
      |               |
      |               v
      |             +------------+     +-------------+
      |             |     2.     |     |     4.      |
      |             | if(a <= c) |     | c = func(b) |
      |             |            | --> |    a = c    |
      |             +------------+     +-------------+
      |               |                  |
      |               |                  |
      |               v                  |
      |             +------------+       |
      |             |     3.     |       |
      |             |  b = 0x8   |       |
      |             |   a = b    |       |
      |             +------------+       |
      |               |                  |
      |               |                  |
      |               v                  |
      |             +------------+       |
      |             |     5.     |       |
      |             |  print(a)  | <-----+
      |             +------------+
      |               |
      |               |
      |               v
      |             +------------+
      |             |     6.     |
      +-----------> |  return c  |
                    +------------+


    """
    s0 = Assignment(b, Constant(7))
    s1 = Assignment(a, b)
    s4 = Assignment(b, Constant(8))
    s5 = Assignment(a, b)

    s6 = Assignment(ListOperation([c]), Call(func, [b]))
    s7 = Assignment(a, c)
    s10 = Assignment(b, Constant(6))
    s11 = Assignment(a, b)

    rd = ReachingDefinitions(condition_cfg)
    n0, n1, n2, n3, n4, n5, n6 = (n for n in condition_cfg.nodes)
    assert rd.reach_in_block(n0) == set()
    assert rd.reach_out_block(n0) == {s0, s1}
    assert rd.reach_in_block(n1) == {s0, s1}
    assert rd.reach_out_block(n1) == {s10, s11}
    assert rd.reach_in_block(n2) == {s0, s1}
    assert rd.reach_out_block(n2) == {s0, s1}
    assert rd.reach_in_block(n3) == {s0, s1}
    assert rd.reach_out_block(n3) == {s4, s5}
    assert rd.reach_out_block(n3) == {s4, s1}
    assert rd.reach_in_block(n4) == {s0, s1}
    assert rd.reach_out_block(n4) == {s6, s7, s0}
    assert rd.reach_in_block(n5) == {s0, s1, s4, s6, s7}
    assert rd.reach_out_block(n5) == {s0, s1, s4, s6, s7}
    assert rd.reach_in_block(n6) == {s0, s1, s4, s6, s7, s10}
    assert rd.reach_in_block(n6) == {s0, s11, s4, s6, s7, s10}
    assert rd.reach_out_block(n6) == {s0, s1, s4, s6, s7, s10}

    assert rd.reach_in_stmt(n0, 0) == set()
    assert rd.reach_out_stmt(n0, 0) == {s0}
    assert rd.reach_in_stmt(n0, 1) == {s0}
    assert rd.reach_out_stmt(n0, 1) == {s0, s1}
    assert rd.reach_in_stmt(n1, 0) == {s0, s1}
    assert rd.reach_out_stmt(n1, 0) == {s1, s10}
    assert rd.reach_in_stmt(n1, 1) == {s1, s10}
    assert rd.reach_out_stmt(n1, 1) == {s1, s10} == {s11, s10}
    assert rd.reach_in_stmt(n2, 0) == {s0, s1}
    assert rd.reach_out_stmt(n2, 0) == {s0, s1}
    assert rd.reach_in_stmt(n3, 0) == {s0, s1}
    assert rd.reach_out_stmt(n3, 0) == {s1, s4}
    assert rd.reach_out_stmt(n3, 1) == {s1, s4} == {s4, s5}
    assert rd.reach_in_stmt(n4, 0) == {s0, s1}
    assert rd.reach_out_stmt(n4, 0) == {s0, s1, s6}
    assert rd.reach_in_stmt(n4, 1) == {s0, s1, s6}
    assert rd.reach_out_stmt(n4, 1) == {s0, s6, s7}
    assert rd.reach_in_stmt(n5, 0) == {s0, s1, s4, s6, s7}
    assert rd.reach_out_stmt(n5, 0) == {s0, s1, s4, s6, s7}
    assert rd.reach_in_stmt(n6, 0) == {s0, s1, s4, s6, s7, s10}
    assert rd.reach_out_stmt(n6, 0) == {s0, s1, s4, s6, s7, s10}


@pytest.fixture
def condition_cfg(a, b, c, func):
    s0 = Assignment(b, Constant(7))
    s1 = Assignment(a, b)
    s2 = Branch(Condition(OperationType.less_or_equal, [a, b]))
    n0 = BasicBlock(0, [s0, s1, s2])
    s3 = Branch(Condition(OperationType.less_or_equal, [a, c]))
    n1 = BasicBlock(1, [s3])
    s4 = Assignment(b, Constant(8))
    s5 = Assignment(a, b)
    n2 = BasicBlock(2, [s4, s5])
    s6 = Assignment(ListOperation([c]), Call(func, [b]))
    s7 = Assignment(a, c)
    n3 = BasicBlock(3, [s6, s7])
    s8 = Assignment(ListOperation([]), Call(ImportedFunctionSymbol("print", 0x42), [a]))
    n4 = BasicBlock(4, [s8])
    s9 = Return([c])
    n6 = BasicBlock(6, [s9])
    s10 = Assignment(b, Constant(6))
    s11 = Assignment(a, b)
    n5 = BasicBlock(5, [s10, s11])
    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n5),
            UnconditionalEdge(n0, n1),
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n1, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n4),
            UnconditionalEdge(n4, n6),
            UnconditionalEdge(n5, n6),
        ]
    )
    return cfg


def test_repeating_definitions_are_correctly_distinguished(basic_block_with_repeating_stmts):
    """
    We want to distinguish between reaching definitions computed for statements 1 and 3 although these two look alike.
    0: b = 0
    1: a = b
    2: b = 1
    3: a = b
    """
    s0 = Assignment(Variable("b"), Constant(0))
    s1 = Assignment(Variable("a"), Variable("b"))
    s2 = Assignment(Variable("b"), Constant(1))
    rd = ReachingDefinitions(basic_block_with_repeating_stmts)
    nodes = [n for n in basic_block_with_repeating_stmts.nodes]
    n0 = nodes[0]
    assert rd.reach_in_stmt(n0, 1) == {s0}
    assert rd.reach_in_stmt(n0, 3) == {s2, s1}


@pytest.fixture
def basic_block_with_repeating_stmts(a, b):
    s0 = Assignment(b, Constant(0))
    s1 = Assignment(a, b)
    s2 = Assignment(b, Constant(1))
    s3 = Assignment(a, b)
    n0 = BasicBlock(0, [s0, s1, s2, s3])
    cfg = ControlFlowGraph()
    cfg.add_node(n0)
    return cfg


def test_that_shows_reaching_definitions_cannot_deal_with_pointers(basic_block_with_pointers, a, b, c, d):
    """Show that for code
    a = 1;
    printf("%d\n",a);
    b = &a;
    c = b;
    d = c;
    *d = 2;
    printf("%d\n",a);
    return 0;

    reaching definitions mistakenly state that a = 1 reaches the end of the block (and corresponding
    print statements)
    """
    s0 = Assignment(a, Constant(0))
    s2 = Assignment(b, UnaryOperation(OperationType.address, [a]))
    s3 = Assignment(c, b)
    s4 = Assignment(d, c)

    rd = ReachingDefinitions(basic_block_with_pointers)
    n0 = [n for n in basic_block_with_pointers.nodes][0]
    assert rd.reach_in_block(n0) == set()
    assert rd.reach_out_block(n0) == {s0, s2, s3, s4}

    # a = 1 reaches first print
    assert rd.reach_in_stmt(n0, 1) == {s0}
    # a = 1 reaches second print
    assert rd.reach_in_stmt(n0, 6) == {s0, s2, s3, s4}


@pytest.fixture
def basic_block_with_pointers(a, b, c, d):
    s0 = Assignment(a, Constant(0))
    s1 = Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0x42), [a]))
    s2 = Assignment(b, UnaryOperation(OperationType.address, [a]))
    s3 = Assignment(c, b)
    s4 = Assignment(d, c)
    s5 = Assignment(UnaryOperation(OperationType.dereference, [d]), Constant(2))
    s6 = Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0x42), [a]))
    s7 = Return([Constant(0)])
    n0 = BasicBlock(0, [s0, s1, s2, s3, s4, s5, s6, s7])
    cfg = ControlFlowGraph()
    cfg.add_node(n0)
    return cfg


@pytest.fixture
def a():
    return Variable("a")


@pytest.fixture
def b():
    return Variable("b")


@pytest.fixture
def c():
    return Variable("c")


@pytest.fixture
def d():
    return Variable("d")


@pytest.fixture
def func():
    return FunctionSymbol("func", 0x42)
