"""Pytest for the Interference Graph."""
from typing import List, Tuple

import pytest
from dewolf.structures.graphs.cfg import BasicBlock, ControlFlowGraph, UnconditionalEdge
from dewolf.structures.interferencegraph import InterferenceGraph
from dewolf.structures.pseudo.expressions import Constant, FunctionSymbol, ImportedFunctionSymbol, Variable
from dewolf.structures.pseudo.instructions import Assignment, Branch, Phi, Return
from dewolf.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from dewolf.structures.pseudo.typing import Integer
from dewolf.util.insertion_ordered_set import InsertionOrderedSet

v_1 = Variable("v", Integer.int32_t(), 1)
v_2 = Variable("v", Integer.int32_t(), 2)
v_3 = Variable("v", Integer.int32_t(), 3)
w_1 = Variable("w", Integer.int32_t(), 1)
x_1 = Variable("x", Integer.int32_t(), 1)
x_3 = Variable("x", Integer.int32_t(), 3)


def function_symbol(name: str, value: int = 0x42) -> FunctionSymbol:
    return FunctionSymbol(name, value)


def imp_function_symbol(name: str, value: int = 0x42) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value)


def construct_graph(numb: int) -> InterferenceGraph:
    interference_graph = InterferenceGraph()
    interference_graph.add_edges_from([(v_1, v_2), (v_3, w_1), (v_2, x_1)])

    if numb == 2:
        interference_graph.add_edges_from([(v_2, v_3), (x_1, x_3)])
    return interference_graph


def test_interfere():
    interference_graph = construct_graph(1)
    assert interference_graph.are_interfering(v_3, w_1)
    assert not interference_graph.are_interfering(v_3, v_1)


def test_interference_graph_of_group_first_graph_a():
    interference_graph = construct_graph(1)
    sub_graph = interference_graph.get_subgraph_of(InsertionOrderedSet([x_1, x_3]))

    assert InsertionOrderedSet(sub_graph.nodes) == InsertionOrderedSet([x_1])
    assert set(sub_graph.edges) == set()


def test_interference_graph_of_group_first_graph_b():
    interference_graph = construct_graph(1)
    sub_graph = interference_graph.get_subgraph_of(InsertionOrderedSet([v_1, v_2, v_3]))

    assert InsertionOrderedSet(sub_graph.nodes) == InsertionOrderedSet([v_1, v_2, v_3])
    assert sub_graph.are_interfering(v_1, v_2) and not sub_graph.are_interfering(v_1, v_3) and not sub_graph.are_interfering(v_2, v_3)


def test_interference_graph_of_group_first_graph_c():
    interference_graph = construct_graph(1)
    sub_graph = interference_graph.get_subgraph_of(InsertionOrderedSet([v_1, v_2, x_1]))

    assert InsertionOrderedSet(sub_graph.nodes) == InsertionOrderedSet([v_1, v_2, x_1])
    assert sub_graph.are_interfering(v_1, v_2) and sub_graph.are_interfering(v_2, x_1) and not sub_graph.are_interfering(v_1, x_1)


def test_interference_graph_of_group_second_graph_a():
    interference_graph = construct_graph(2)
    sub_graph = interference_graph.get_subgraph_of(InsertionOrderedSet([v_1, v_2, v_3]))

    assert InsertionOrderedSet(sub_graph.nodes) == InsertionOrderedSet([v_1, v_2, v_3])
    assert sub_graph.are_interfering(v_1, v_2) and not sub_graph.are_interfering(v_1, v_3) and sub_graph.are_interfering(v_2, v_3)


def test_interference_graph_of_group_second_graph_b():
    interference_graph = construct_graph(2)
    sub_graph = interference_graph.get_subgraph_of(InsertionOrderedSet([x_1, x_3]))

    assert InsertionOrderedSet(sub_graph.nodes) == InsertionOrderedSet([x_1, x_3])
    assert sub_graph.are_interfering(x_1, x_3)


@pytest.fixture()
def variable_x():
    return [Variable("x", Integer.int32_t(), i) for i in range(20)]


@pytest.fixture()
def variable_u():
    return [Variable("u", Integer.int32_t(), i) for i in range(20)]


@pytest.fixture()
def variable_v():
    return [Variable("v", Integer.int32_t(), i) for i in range(20)]


@pytest.fixture()
def aliased_variable_x():
    return [Variable("x", Integer.int32_t(), index, is_aliased=True) for index in range(20)]


@pytest.fixture()
def aliased_variable_y():
    return [Variable("y", Integer.int32_t(), index, is_aliased=True) for index in range(20)]


@pytest.fixture()
def aliased_variable_z():
    return [Variable("z", Integer.int32_t(), index, is_aliased=True) for index in range(20)]


@pytest.fixture()
def construct_graph_test_loop_1(variable_x, variable_u, variable_v, aliased_variable_y) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """Compare with test1 of test_loop
                       +------------------------+
                       |   printf(0x804b00c)    |
                       |      x#1 = &(y#1)      |
                       | scanf(0x804b01f, x#1)  |
                       |       y#2 = y#1        |
                       |       u#1 = y#2        |
                       |       x#2 = u#1        |
                       | printf(0x804b024, x#2) |
                       |       y#3 = y#2        |
                       |       v#1 = 0x1        |
                       +------------------------+
                         |
                         |
                         v
    +------------+     +------------------------+
    |            |     |    x#3 = ϕ(x#2,x#4)    |
    |            |     |    v#2 = ϕ(v#1,v#3)    |
    | u#4 = 0x0  |     |    u#2 = ϕ(u#1,u#3)    |
    | return 0x0 |     |    y#4 = ϕ(y#3,y#5)    |
    |            |     |       u#3 = y#4        |
    |            | <-- |     if(v#2 <= u#3)     | <+
    +------------+     +------------------------+  |
                         |                         |
                         |                         |
                         v                         |
                       +------------------------+  |
                       |       x#4 = v#2        |  |
                       | printf(0x804b045, x#4) |  |
                       |       y#5 = y#4        |  |
                       |   v#3 = (v#2 + 0x1)    | -+
                       +------------------------+
    """
    instructions = [
        # node 0: 0 - 8
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        Assignment(variable_x[1], UnaryOperation(OperationType.address, [aliased_variable_y[1]], Integer.int32_t())),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), variable_x[1]])),
        Assignment(aliased_variable_y[2], aliased_variable_y[1]),
        Assignment(variable_u[1], aliased_variable_y[2]),
        Assignment(variable_x[2], variable_u[1]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B024), variable_x[2]])),
        Assignment(aliased_variable_y[3], aliased_variable_y[2]),
        Assignment(variable_v[1], Constant(0x1)),
        # node 1: 9 - 14
        Phi(variable_x[3], [variable_x[2], variable_x[4]]),
        Phi(variable_v[2], [variable_v[1], variable_v[3]]),
        Phi(variable_u[2], [variable_u[1], variable_u[3]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[5]]),
        Assignment(variable_u[3], aliased_variable_y[4]),
        Branch(Condition(OperationType.less_or_equal, [variable_v[2], variable_u[3]], "bool")),
        # node 2: 15 - 18
        Assignment(variable_x[4], variable_v[2]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B045), variable_x[4]])),
        Assignment(aliased_variable_y[5], aliased_variable_y[4]),
        Assignment(variable_v[3], BinaryOperation(OperationType.plus, [variable_v[2], Constant(0x1)])),
        # node 3: 19 - 20
        Assignment(variable_u[4], Constant(0x0)),
        Return([Constant(0x0)]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(10)]
    # Add instructions:
    nodes[0].instructions = instructions[0:9]
    nodes[1].instructions = instructions[9:15]
    nodes[2].instructions = instructions[15:19]
    nodes[3].instructions = instructions[19:]

    instructions[9]._origin_block = {nodes[0]: variable_x[2], nodes[2]: variable_x[4]}
    instructions[10]._origin_block = {nodes[0]: variable_v[1], nodes[2]: variable_v[3]}
    instructions[11]._origin_block = {nodes[0]: variable_u[1], nodes[2]: variable_u[3]}
    instructions[12]._origin_block = {nodes[0]: aliased_variable_y[3], nodes[2]: aliased_variable_y[5]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[1], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[1]),
        ]
    )
    return nodes, cfg


def test_interference_graph_of_test_loop_test1_without_dead_code(
    construct_graph_test_loop_1, variable_x, variable_u, variable_v, aliased_variable_y
):
    """
                       +------------------------+
                       |   printf(0x804b00c)    |
                       |      x#1 = &(y#1)      |
                       | scanf(0x804b01f, x#1)  |
                       |       y#2 = y#1        |
                       |       u#1 = y#2        |
                       |       x#2 = u#1        |
                       | printf(0x804b024, x#2) |
                       |       y#3 = y#2        |
                       |       v#1 = 0x1        |
                       +------------------------+
                         |
                         |
                         v
    +------------+     +------------------------+
    |            |     |    v#2 = ϕ(v#1,v#3)    |
    | return 0x0 |     |    y#4 = ϕ(y#3,y#5)    |
    |            |     |       u#3 = y#4        |
    |            | <-- |     if(v#2 <= u#3)     | <+
    +------------+     +------------------------+  |
                         |                         |
                         |                         |
                         v                         |
                       +------------------------+  |
                       |       x#4 = v#2        |  |
                       | printf(0x804b045, x#4) |  |
                       |       y#5 = y#4        |  |
                       |   v#3 = (v#2 + 0x1)    | -+
                       +------------------------+

    """
    nodes, cfg = construct_graph_test_loop_1

    nodes[1].remove_instruction(Phi(variable_x[3], [variable_x[2], variable_x[4]]))
    nodes[1].remove_instruction(Phi(variable_u[2], [variable_u[1], variable_u[3]]))
    nodes[3].remove_instruction(Assignment(variable_u[4], Constant(0x0)))

    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == set(variable_x[1:3] + [variable_x[4]]) | {variable_u[1], variable_u[3]} | set(
        variable_v[1:4]
    ) | set(aliased_variable_y[1:6])

    assert (
        set(interference_graph.neighbors(variable_x[1])) == {aliased_variable_y[1]}
        and set(interference_graph.neighbors(variable_x[2])) == {aliased_variable_y[2]}
        and set(interference_graph.neighbors(variable_x[4])) == {aliased_variable_y[4], variable_v[2]}
        and set(interference_graph.neighbors(variable_u[1])) == {aliased_variable_y[2]}
        and set(interference_graph.neighbors(variable_u[3])) == {aliased_variable_y[4], variable_v[2]}
        and set(interference_graph.neighbors(variable_v[1])) == {aliased_variable_y[3]}
        and set(interference_graph.neighbors(variable_v[2])) == {aliased_variable_y[4], variable_x[4], variable_u[3], aliased_variable_y[5]}
        and set(interference_graph.neighbors(variable_v[3])) == {aliased_variable_y[5]}
        and set(interference_graph.neighbors(aliased_variable_y[1])) == {variable_x[1]}
        and set(interference_graph.neighbors(aliased_variable_y[2])) == {variable_x[2], variable_u[1]}
        and set(interference_graph.neighbors(aliased_variable_y[3])) == {variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_y[4])) == {variable_x[4], variable_u[3], variable_v[2]}
        and set(interference_graph.neighbors(aliased_variable_y[5])) == {variable_v[2], variable_v[3]}
    )


def test_interference_graph_of_test_loop_test1_with_dead_code(
    construct_graph_test_loop_1, variable_x, variable_u, variable_v, aliased_variable_y
):
    nodes, cfg = construct_graph_test_loop_1

    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == (
        set(variable_x[1:5]) | set(variable_u[1:5]) | set(variable_v[1:4]) | set(aliased_variable_y[1:6])
    )

    assert (
        set(interference_graph.neighbors(variable_x[1])) == {aliased_variable_y[1]}
        and set(interference_graph.neighbors(variable_x[2])) == {aliased_variable_y[2], aliased_variable_y[3], variable_u[1], variable_v[1]}
        and set(interference_graph.neighbors(variable_x[4]))
        == {aliased_variable_y[4], variable_v[2], variable_u[3], variable_v[3], aliased_variable_y[5]}
        and set(interference_graph.neighbors(variable_u[1])) == {aliased_variable_y[2], aliased_variable_y[3], variable_x[2], variable_v[1]}
        and set(interference_graph.neighbors(variable_u[3]))
        == {aliased_variable_y[4], variable_v[2], variable_v[3], variable_x[4], aliased_variable_y[5]}
        and set(interference_graph.neighbors(variable_v[1])) == {aliased_variable_y[3], variable_u[1], variable_x[2]}
        and set(interference_graph.neighbors(variable_v[2]))
        == {aliased_variable_y[4], variable_x[4], variable_u[3], aliased_variable_y[5], variable_x[3], variable_u[2]}
        and set(interference_graph.neighbors(variable_v[3])) == {aliased_variable_y[5], variable_u[3], variable_x[4]}
        and set(interference_graph.neighbors(aliased_variable_y[1])) == {variable_x[1]}
        and set(interference_graph.neighbors(aliased_variable_y[2])) == {variable_x[2], variable_u[1]}
        and set(interference_graph.neighbors(aliased_variable_y[3])) == {variable_v[1], variable_u[1], variable_x[2]}
        and set(interference_graph.neighbors(aliased_variable_y[4]))
        == {variable_x[4], variable_u[3], variable_v[2], variable_x[3], variable_u[2]}
        and set(interference_graph.neighbors(aliased_variable_y[5])) == {variable_v[2], variable_v[3], variable_u[3], variable_x[4]}
        and set(interference_graph.neighbors(variable_u[2])) == {variable_v[2], variable_x[3], aliased_variable_y[4]}
        and set(interference_graph.neighbors(variable_x[3])) == {variable_v[2], variable_u[2], aliased_variable_y[4]}
    )


@pytest.fixture()
def construct_graph_one_basicblock(variable_x, variable_v, variable_u) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """A graph with only one basic block
    +---------------------------+
    | x#1 = (x#0 * (u#0 + v#0)) |
    |      print(x#1, v#0)      |
    |     v#1 = (v#0 + x#1)     |
    | u#1 = binomial(v#1, 0x3)  |
    |        return u#1         |
    +---------------------------+
    """
    node = BasicBlock(0)

    node.instructions = [
        Assignment(
            variable_x[1],
            BinaryOperation(OperationType.multiply, [variable_x[0], BinaryOperation(OperationType.plus, [variable_u[0], variable_v[0]])]),
        ),
        Assignment(ListOperation([]), Call(imp_function_symbol("print"), [variable_x[1], variable_v[0]])),
        Assignment(variable_v[1], BinaryOperation(OperationType.plus, [variable_v[0], variable_x[1]])),
        Assignment(variable_u[1], Call(function_symbol("binomial"), [variable_v[1], Constant(3)])),
        Return([variable_u[1]]),
    ]

    cfg = ControlFlowGraph()
    cfg.add_node(node)
    return [node], cfg


def test_interference_graph_of_one_basicblock_a(construct_graph_one_basicblock, variable_x, variable_v, variable_u):
    nodes, cfg = construct_graph_one_basicblock

    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == set(variable_x[:2]) | set(variable_v[:2]) | set(variable_u[:2])

    assert (
        set(interference_graph.neighbors(variable_x[0])) == {variable_u[0], variable_v[0]}
        and set(interference_graph.neighbors(variable_x[1])) == {variable_v[0]}
        and set(interference_graph.neighbors(variable_v[0])) == {variable_u[0], variable_x[0], variable_x[1]}
        and set(interference_graph.neighbors(variable_v[1])) == set()
        and set(interference_graph.neighbors(variable_u[0])) == {variable_x[0], variable_v[0]}
        and set(interference_graph.neighbors(variable_u[1])) == set()
    )


def test_interference_graph_of_one_basicblock_b(construct_graph_one_basicblock, variable_x, variable_v, variable_u):
    """
    +---------------------------+
    | x#1 = (x#0 * (u#0 + v#0)) |
    |      print(x#1, v#0)      |
    |     v#1 = (v#0 + x#1)     |
    | u#1 = binomial(v#1, 0x3)  |
    |      return u#1,v#1       |
    +---------------------------+
    """
    nodes, cfg = construct_graph_one_basicblock

    # nodes[0].replace_instruction(
    #     Return([variable_u[1]]), [Return([BinaryOperation(OperationType.multiply, [variable_u[1], variable_v[1]])])]
    # )
    nodes[0].replace_instruction(Return([variable_u[1]]), [Return([variable_u[1], variable_v[1]])])

    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == set(variable_x[:2]) | set(variable_v[:2]) | set(variable_u[:2])

    assert (
        set(interference_graph.neighbors(variable_x[0])) == {variable_u[0], variable_v[0]}
        and set(interference_graph.neighbors(variable_x[1])) == {variable_v[0]}
        and set(interference_graph.neighbors(variable_v[0])) == {variable_u[0], variable_x[0], variable_x[1]}
        and set(interference_graph.neighbors(variable_v[1])) == {variable_u[1]}
        and set(interference_graph.neighbors(variable_u[0])) == {variable_x[0], variable_v[0]}
        and set(interference_graph.neighbors(variable_u[1])) == {variable_v[1]}
    )


@pytest.fixture()
def construct_graph_if_else(variable_u, variable_v, aliased_variable_y, aliased_variable_z) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """Graph with an if-else-statement.
    +-------------------+     +-------------------------+
    |                   |     |    printf(0x804b00c)    |
    |                   |     |      u#1 = &(y#1)       |
    | u#3 = (u#1 / 0x2) |     |  scanf(0x804b01f, u#1)  |
    |                   |     |      v#1 = &(z#2)       |
    |                   |     |  scanf(0x804b024, v#1)  |
    |                   | <-- |      if(u#1 < v#1)      |
    +-------------------+     +-------------------------+
      |                         |
      |                         |
      |                         v
      |                       +-------------------------+
      |                       |    u#2 = (0x2 * u#1)    |
      |                       |    v#2 = (v#1 - 0x5)    |
      |                       +-------------------------+
      |                         |
      |                         |
      |                         v
      |                       +-------------------------+
      |                       |    u#4 = ϕ(u#2,u#3)     |
      |                       |    v#3 = ϕ(v#2,v#1)     |
      |                       | v#4 = compare(u#4, v#3) |
      +---------------------> |       return v#4        |
                              +-------------------------+
    """
    instructions = [
        # node 0: 0-5
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        Assignment(variable_u[1], UnaryOperation(OperationType.address, [aliased_variable_y[1]], Integer.int32_t())),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), variable_u[1]])),
        Assignment(variable_v[1], UnaryOperation(OperationType.address, [aliased_variable_z[2]], Integer.int32_t())),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B024), variable_v[1]])),
        Branch(Condition(OperationType.less, [variable_u[1], variable_v[1]])),
        # node 1: 6 - 7
        Assignment(variable_u[2], BinaryOperation(OperationType.multiply, [Constant(2), variable_u[1]])),
        Assignment(variable_v[2], BinaryOperation(OperationType.minus, [variable_v[1], Constant(5)])),
        # node 2: 8
        Assignment(variable_u[3], BinaryOperation(OperationType.divide, [variable_u[1], Constant(2)])),
        # node 3: 9 -12
        Phi(variable_u[4], [variable_u[2], variable_u[3]]),
        Phi(variable_v[3], [variable_v[2], variable_v[1]]),
        Assignment(variable_v[4], Call(function_symbol("compare"), [variable_u[4], variable_v[3]])),
        Return([variable_v[4]]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(4)]
    # Add instructions:
    nodes[0].instructions = instructions[0:6]
    nodes[1].instructions = instructions[6:8]
    nodes[2].instructions = [instructions[8]]
    nodes[3].instructions = instructions[9:]

    instructions[9]._origin_block = {nodes[1]: variable_u[2], nodes[2]: variable_u[3]}
    instructions[10]._origin_block = {nodes[1]: variable_v[2], nodes[2]: variable_v[1]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[3]),
        ]
    )
    return nodes, cfg


def test_interference_graph_if_else(construct_graph_if_else, variable_u, variable_v, aliased_variable_y, aliased_variable_z):
    nodes, cfg = construct_graph_if_else

    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == set(variable_u[1:5]) | set(variable_v[1:5]) | {
        aliased_variable_y[1],
        aliased_variable_z[2],
    }

    assert (
        set(interference_graph.neighbors(variable_u[1])) == {variable_v[1], aliased_variable_z[2]}
        and set(interference_graph.neighbors(variable_u[2])) == {variable_v[1], variable_v[2]}
        and set(interference_graph.neighbors(variable_u[3])) == {variable_v[1]}
        and set(interference_graph.neighbors(variable_u[4])) == {variable_v[3]}
        and set(interference_graph.neighbors(variable_v[1])) == {variable_u[1], variable_u[2], variable_u[3]}
        and set(interference_graph.neighbors(variable_v[2])) == {variable_u[2]}
        and set(interference_graph.neighbors(variable_v[3])) == {variable_u[4]}
        and set(interference_graph.neighbors(variable_v[4])) == set()
        and set(interference_graph.neighbors(aliased_variable_y[1])) == {aliased_variable_z[2]}
        and set(interference_graph.neighbors(aliased_variable_z[2])) == {aliased_variable_y[1], variable_u[1]}
    )


@pytest.fixture()
def construct_graph_loop(variable_u, variable_v, aliased_variable_y) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """Graph with a loop-statement.
                                   +--------------------------+
                                   |    printf(0x804a00c)     |
                                   | scanf(0x804a025, &(y#1)) |
                                   |  printf(0x804a028, y#1)  |
                                   +--------------------------+
                                     |
                                     |
                                     v
    +------------------------+     +------------------------------------+
    | printf(0x804a049, u#3) |     |          u#3 = ϕ(y#1,y#4)          |
    |       return 0x0       |     |       y#4 = ϕ(y#1,y#7,v#11)        |
    |                        | <-- |           if(y#4 <= 0x0)           |
    +------------------------+     +------------------------------------+
                                     |                           ^    ^
                                     |                           |    |
                                     v                           |    |
                                   +--------------------------+  |    |
                                   |  printf(0x804a045, y#4)  |  |    |
                                   |    y#7 = (y#4 - 0x2)     |  |    |
                                   |    v#9 = is_odd(y#7)     |  |    |
                                   | if((v#9 & 0xff) == 0x0)  | -+    |
                                   +--------------------------+       |
                                     |                                |
                                     |                                |
                                     v                                |
                                   +--------------------------+       |
                                   |    v#11 = (y#7 - 0x1)    | ------+
                                   +--------------------------+
    """
    instructions = [
        # node 0: 0 - 2
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A00C)])),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_y[1]])]),
        ),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A028), aliased_variable_y[1]])),
        # node 1: 3 - 5
        Phi(variable_u[3], [aliased_variable_y[1], aliased_variable_y[4]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[1], aliased_variable_y[7], variable_v[11]]),
        Branch(Condition(OperationType.less_or_equal, [aliased_variable_y[4], Constant(0x0)])),
        # node 2: 6 - 7
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A049), variable_u[3]])),
        Return([Constant(0x0)]),
        # node 3: 8 - 11
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A045), aliased_variable_y[4]])),
        Assignment(aliased_variable_y[7], BinaryOperation(OperationType.minus, [aliased_variable_y[4], Constant(0x2)])),
        Assignment(variable_v[9], Call(function_symbol("is_odd"), [aliased_variable_y[7]])),
        Branch(
            Condition(OperationType.equal, [BinaryOperation(OperationType.bitwise_and, [variable_v[9], Constant(0xFF)]), Constant(0x0)])
        ),
        # node 4: 12
        Assignment(variable_v[11], BinaryOperation(OperationType.minus, [aliased_variable_y[7], Constant(0x1)])),
    ]
    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(5)]
    # Add instructions:
    nodes[0].instructions = instructions[0:3]
    nodes[1].instructions = instructions[3:6]
    nodes[2].instructions = instructions[6:8]
    nodes[3].instructions = instructions[8:12]
    nodes[4].instructions = [instructions[12]]

    instructions[3]._origin_block = {nodes[0]: aliased_variable_y[1], nodes[3]: aliased_variable_y[4], nodes[4]: aliased_variable_y[4]}
    instructions[4]._origin_block = {nodes[0]: aliased_variable_y[1], nodes[3]: aliased_variable_y[7], nodes[4]: variable_v[11]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[1], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[3], nodes[1]),
            UnconditionalEdge(nodes[3], nodes[4]),
            UnconditionalEdge(nodes[4], nodes[1]),
        ]
    )
    return nodes, cfg


def test_interference_graph_graph_loop(construct_graph_loop, variable_v, variable_u, aliased_variable_y):
    nodes, cfg = construct_graph_loop

    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == {
        variable_v[9],
        variable_v[11],
        variable_u[3],
        aliased_variable_y[1],
        aliased_variable_y[4],
        aliased_variable_y[7],
    }

    assert (
        set(interference_graph.neighbors(variable_v[9])) == {aliased_variable_y[4], aliased_variable_y[7]}
        and set(interference_graph.neighbors(variable_v[11])) == {aliased_variable_y[4]}
        and set(interference_graph.neighbors(variable_u[3])) == {aliased_variable_y[4]}
        and set(interference_graph.neighbors(aliased_variable_y[1])) == set()
        and set(interference_graph.neighbors(aliased_variable_y[4]))
        == {variable_u[3], variable_v[9], variable_v[11], aliased_variable_y[7]}
        and set(interference_graph.neighbors(aliased_variable_y[7])) == {variable_v[9], aliased_variable_y[4]}
    )


def test_contract_independend_set(construct_graph_loop, variable_v, variable_u, aliased_variable_y):
    """Contract an independent set in the interference graph"""
    nodes, cfg = construct_graph_loop

    interference_graph = InterferenceGraph(cfg)
    interference_graph.contract_independent_set([aliased_variable_y[1], aliased_variable_y[4]])

    assert set(interference_graph.nodes) == {
        variable_v[9],
        variable_v[11],
        variable_u[3],
        aliased_variable_y[1],
        aliased_variable_y[7],
    }

    assert (
        set(interference_graph.neighbors(variable_v[9])) == {aliased_variable_y[1], aliased_variable_y[7]}
        and set(interference_graph.neighbors(variable_v[11])) == {aliased_variable_y[1]}
        and set(interference_graph.neighbors(variable_u[3])) == {aliased_variable_y[1]}
        and set(interference_graph.neighbors(aliased_variable_y[1]))
        == {variable_u[3], variable_v[9], variable_v[11], aliased_variable_y[7]}
        and set(interference_graph.neighbors(aliased_variable_y[7])) == {variable_v[9], aliased_variable_y[1]}
    )


def test_contract_non_independend_set(construct_graph_loop, aliased_variable_y):
    """Try to contract an set that is not an independent set in the interference graph, which fails."""
    nodes, cfg = construct_graph_loop

    interference_graph = InterferenceGraph(cfg)
    with pytest.raises(ValueError):
        interference_graph.contract_independent_set([aliased_variable_y[1], aliased_variable_y[4], aliased_variable_y[7]])


@pytest.fixture()
def construct_graph_circular_dependency_phi(
    variable_x, variable_v, variable_u, aliased_variable_y, aliased_variable_z
) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """Graph where we have a circular dependency on the phi-functions.
                                   +-----------------------+
                                   |   printf(0x804b00c)   |
                                   |     x#1 = &(y#1)      |
                                   | scanf(0x804b01f, x#1) |
                                   |       y#2 = y#1       |
                                   |   printf(0x804bb0c)   |
                                   |     v#1 = &(z#3)      |
                                   | scanf(0x804bb1f, v#1) |
                                   +-----------------------+
                                     |
                                     |
                                     v
    +------------------------+     +-----------------------+
    |                        |     |   x#2 = ϕ(x#1,v#2)    |
    | printf(0x804bb0c, x#2) |     |   v#2 = ϕ(v#1,x#2)    |
    |                        |     |   u#2 = ϕ(0x1,u#1)    |
    |                        | <-- |    if(u#2 <= 0x14)    | <+
    +------------------------+     +-----------------------+  |
                                     |                        |
                                     |                        |
                                     v                        |
                                   +-----------------------+  |
                                   |   u#1 = (u#2 + 0x1)   | -+
                                   +-----------------------+
    """
    instructions = [
        # node 0: 0 - 6
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        Assignment(variable_x[1], UnaryOperation(OperationType.address, [aliased_variable_y[1]], Integer.int32_t())),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), variable_x[1]])),
        Assignment(aliased_variable_y[2], aliased_variable_y[1]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804BB0C)])),
        Assignment(variable_v[1], UnaryOperation(OperationType.address, [aliased_variable_z[3]], Integer.int32_t())),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804BB1F), variable_v[1]])),
        # node 1: 7 - 10
        Phi(variable_x[2], [variable_x[1], variable_v[2]]),
        Phi(variable_v[2], [variable_v[1], variable_x[2]]),
        Phi(variable_u[2], [Constant(1), variable_u[1]]),
        Branch(Condition(OperationType.less_or_equal, [variable_u[2], Constant(20)])),
        # node 2: 11
        Assignment(variable_u[1], BinaryOperation(OperationType.plus, [variable_u[2], Constant(1)])),
        # node 3: 12
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804BB0C), variable_x[2]])),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(4)]
    # Add instructions:
    nodes[0].instructions = instructions[0:7]
    nodes[1].instructions = instructions[7:11]
    nodes[2].instructions = [instructions[11]]
    nodes[3].instructions = [instructions[12]]

    instructions[7]._origin_block = {nodes[0]: variable_x[1], nodes[2]: variable_v[2]}
    instructions[8]._origin_block = {nodes[0]: variable_v[1], nodes[2]: variable_x[2]}
    instructions[9]._origin_block = {nodes[0]: Constant(1), nodes[2]: variable_u[1]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[1], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[1]),
        ]
    )
    return nodes, cfg


def test_interference_graph_circular_dependency_phi_functions(
    construct_graph_circular_dependency_phi, variable_x, variable_v, variable_u, aliased_variable_y, aliased_variable_z
):
    nodes, cfg = construct_graph_circular_dependency_phi

    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == set(variable_x[1:3]) | set(variable_v[1:3]) | set(variable_u[1:3]) | set(
        aliased_variable_y[1:3]
    ) | {aliased_variable_z[3]}

    assert (
        set(interference_graph.neighbors(variable_x[1]))
        == {aliased_variable_y[1], aliased_variable_y[2], aliased_variable_z[3], variable_v[1]}
        and set(interference_graph.neighbors(variable_x[2])) == {variable_v[2], variable_u[2], variable_u[1]}
        and set(interference_graph.neighbors(variable_v[1])) == {variable_x[1]}
        and set(interference_graph.neighbors(variable_v[2])) == {variable_x[2], variable_u[2], variable_u[1]}
        and set(interference_graph.neighbors(variable_u[1])) == {variable_x[2], variable_v[2]}
        and set(interference_graph.neighbors(variable_u[2])) == {variable_v[2], variable_x[2]}
        and set(interference_graph.neighbors(aliased_variable_y[1])) == {variable_x[1], aliased_variable_z[3]}
        and set(interference_graph.neighbors(aliased_variable_y[2])) == {variable_x[1], aliased_variable_z[3]}
        and set(interference_graph.neighbors(aliased_variable_z[3])) == {variable_x[1], aliased_variable_y[1], aliased_variable_y[2]}
    )


@pytest.fixture()
def construct_graph_multiple_entry_loop(variable_v, aliased_variable_y, aliased_variable_z) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """Graph with a loop that has two entries.
       +---------------------------+
       |     printf(0x804b00c)     |
       |   scanf(0x804b01f, y#1)   |
       |     printf(0x804bb0c)     |
       |   scanf(0x804bb1f, z#1)   |
       |  v#1 = compute(y#1, z#1)  |
       |       if(y#1 > z#1)       | -+
       +---------------------------+  |
         |                            |
         |                            |
         v                            |
       +---------------------------+  |
       |     y#2 = ϕ(y#1,y#4)      |  |
       |     z#2 = ϕ(z#1,z#4)      |  |
    +> |     y#3 = (y#2 / 0x2)     |  |
    |  +---------------------------+  |
    |    |                            |
    |    |                            |
    |    v                            |
    |  +---------------------------+  |
    |  |     y#4 = ϕ(y#1,y#3)      |  |
    |  |     z#3 = ϕ(z#1,z#2)      |  |
    |  |     z#4 = (z#3 - 0x2)     |  |
    |  | v#4 = (v#1 + (y#4 - z#4)) | <+
    |  +---------------------------+
    |    |
    |    |
    |    v
    |  +---------------------------+
    +- |       if(y#4 < z#4)       |
       +---------------------------+
         |
         |
         v
       +---------------------------+
       |  v#5 = compute(y#4, z#4)  |
       |   printf(v#1, v#4, v#5)   |
       |  v#5 = compute(v#1, v#4)  |
       |        printf(v#5)        |
       +---------------------------+
    """
    instructions = [
        # node 0: 0 - 5
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), aliased_variable_y[1]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804BB0C)])),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804BB1F), aliased_variable_z[1]])),
        Assignment(variable_v[1], Call(function_symbol("compute"), [aliased_variable_y[1], aliased_variable_z[1]])),
        Branch(Condition(OperationType.greater, [aliased_variable_y[1], aliased_variable_z[1]])),
        # node 1: 6 - 8
        Phi(aliased_variable_y[2], [aliased_variable_y[1], aliased_variable_y[4]]),
        Phi(aliased_variable_z[2], [aliased_variable_z[1], aliased_variable_z[4]]),
        Assignment(aliased_variable_y[3], BinaryOperation(OperationType.divide, [aliased_variable_y[2], Constant(2)])),
        # node 2: 9 - 12
        Phi(aliased_variable_y[4], [aliased_variable_y[1], aliased_variable_y[3]]),
        Phi(aliased_variable_z[3], [aliased_variable_z[1], aliased_variable_z[2]]),
        Assignment(aliased_variable_z[4], BinaryOperation(OperationType.minus, [aliased_variable_z[3], Constant(2)])),
        Assignment(
            variable_v[4],
            BinaryOperation(
                OperationType.plus,
                [variable_v[1], BinaryOperation(OperationType.minus, [aliased_variable_y[4], aliased_variable_z[4]])],
            ),
        ),
        # node 3: 13
        Branch(Condition(OperationType.less, [aliased_variable_y[4], aliased_variable_z[4]])),
        # node 4: 14 - 17
        Assignment(variable_v[5], Call(function_symbol("compute"), [aliased_variable_y[4], aliased_variable_z[4]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable_v[1], variable_v[4], variable_v[5]])),
        Assignment(variable_v[5], Call(function_symbol("compute"), [variable_v[1], variable_v[4]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable_v[5]])),
    ]
    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(5)]
    # Add instructions:
    nodes[0].instructions = instructions[0:6]
    nodes[1].instructions = instructions[6:9]
    nodes[2].instructions = instructions[9:13]
    nodes[3].instructions = [instructions[13]]
    nodes[4].instructions = instructions[14:]

    instructions[6]._origin_block = {nodes[0]: aliased_variable_y[1], nodes[3]: aliased_variable_y[4]}
    instructions[7]._origin_block = {nodes[0]: aliased_variable_z[1], nodes[3]: aliased_variable_z[4]}

    instructions[9]._origin_block = {nodes[0]: aliased_variable_y[1], nodes[1]: aliased_variable_y[3]}
    instructions[10]._origin_block = {nodes[0]: aliased_variable_z[1], nodes[1]: aliased_variable_z[2]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[1], nodes[2]),
            UnconditionalEdge(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[2], nodes[3]),
            UnconditionalEdge(nodes[3], nodes[1]),
            UnconditionalEdge(nodes[3], nodes[4]),
        ]
    )
    return nodes, cfg


def test_interference_graph_multiple_entry_loop_a(construct_graph_multiple_entry_loop, variable_v, aliased_variable_y, aliased_variable_z):
    """Multiple Entry, y & z are used the whole time.
       +---------------------------+
       |     printf(0x804b00c)     |
       |   scanf(0x804b01f, y#1)   |
       |     printf(0x804bb0c)     |
       |   scanf(0x804bb1f, z#1)   |
       |  v#1 = compute(y#1, z#1)  |
       |       if(y#1 > z#1)       | -+
       +---------------------------+  |
         |                            |
         |                            |
         v                            |
       +---------------------------+  |
       |     y#2 = ϕ(y#1,y#4)      |  |
       |     z#2 = ϕ(z#1,z#4)      |  |
    +> |     y#3 = (y#2 / 0x2)     |  |
    |  +---------------------------+  |
    |    |                            |
    |    |                            |
    |    v                            |
    |  +---------------------------+  |
    |  |     y#4 = ϕ(y#1,y#3)      |  |
    |  |     z#3 = ϕ(z#1,z#2)      |  |
    |  |     z#4 = (z#3 - 0x2)     |  |
    |  | v#4 = (v#1 + (y#4 - z#4)) | <+
    |  +---------------------------+
    |    |
    |    |
    |    v
    |  +---------------------------+
    +- |       if(y#4 < z#4)       |
       +---------------------------+
         |
         |
         v
       +---------------------------+
       |  v#5 = compute(y#4, z#4)  |
       |   printf(v#1, v#4, v#5)   |
       +---------------------------+
    """
    nodes, cfg = construct_graph_multiple_entry_loop

    del nodes[4].instructions[3]
    del nodes[4].instructions[2]
    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == set(aliased_variable_y[1:5]) | set(aliased_variable_z[1:5]) | {
        variable_v[1],
        variable_v[4],
        variable_v[5],
    }

    assert (
        set(interference_graph.neighbors(aliased_variable_y[1])) == {aliased_variable_z[1], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_y[2])) == {aliased_variable_z[2], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_y[3])) == {aliased_variable_z[2], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_y[4]))
        == {aliased_variable_z[3], aliased_variable_z[4], variable_v[1], variable_v[4]}
        and set(interference_graph.neighbors(aliased_variable_z[1])) == {aliased_variable_y[1], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_z[2])) == {aliased_variable_y[2], aliased_variable_y[3], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_z[3])) == {aliased_variable_y[4], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_z[4])) == {aliased_variable_y[4], variable_v[1], variable_v[4]}
        and set(interference_graph.neighbors(variable_v[1])) == set(interference_graph.nodes) - {variable_v[1]}
        and set(interference_graph.neighbors(variable_v[4])) == {aliased_variable_y[4], aliased_variable_z[4], variable_v[1], variable_v[5]}
        and set(interference_graph.neighbors(variable_v[5])) == {variable_v[1], variable_v[4]}
    )


def test_interference_graph_multiple_entry_loop_b(construct_graph_multiple_entry_loop, variable_v, aliased_variable_y, aliased_variable_z):
    """Multiple Entry, no Phi functions for v and y & z are not used in the last basic block.
       +---------------------------+
       |     printf(0x804b00c)     |
       |   scanf(0x804b01f, y#1)   |
       |     printf(0x804bb0c)     |
       |   scanf(0x804bb1f, z#1)   |
       |  v#1 = compute(y#1, z#1)  |
       |       if(y#1 > z#1)       | -+
       +---------------------------+  |
         |                            |
         |                            |
         v                            |
       +---------------------------+  |
       |     y#2 = ϕ(y#1,y#4)      |  |
       |     z#2 = ϕ(z#1,z#4)      |  |
    +> |     y#3 = (y#2 / 0x2)     |  |
    |  +---------------------------+  |
    |    |                            |
    |    |                            |
    |    v                            |
    |  +---------------------------+  |
    |  |     y#4 = ϕ(y#1,y#3)      |  |
    |  |     z#3 = ϕ(z#1,z#2)      |  |
    |  |     z#4 = (z#3 - 0x2)     |  |
    |  | v#4 = (v#1 + (y#4 - z#4)) | <+
    |  +---------------------------+
    |    |
    |    |
    |    v
    |  +---------------------------+
    +- |       if(y#4 < z#4)       |
       +---------------------------+
         |
         |
         v
       +---------------------------+
       |  v#5 = compute(v#1, v#4)  |
       |        printf(v#5)        |
       +---------------------------+
    """
    nodes, cfg = construct_graph_multiple_entry_loop

    del nodes[4].instructions[1]
    del nodes[4].instructions[0]
    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == set(aliased_variable_y[1:5]) | set(aliased_variable_z[1:5]) | {
        variable_v[1],
        variable_v[4],
        variable_v[5],
    }

    assert (
        set(interference_graph.neighbors(aliased_variable_y[1])) == {aliased_variable_z[1], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_y[2])) == {aliased_variable_z[2], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_y[3])) == {aliased_variable_z[2], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_y[4]))
        == {aliased_variable_z[3], aliased_variable_z[4], variable_v[1], variable_v[4]}
        and set(interference_graph.neighbors(aliased_variable_z[1])) == {aliased_variable_y[1], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_z[2])) == {aliased_variable_y[2], aliased_variable_y[3], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_z[3])) == {aliased_variable_y[4], variable_v[1]}
        and set(interference_graph.neighbors(aliased_variable_z[4])) == {aliased_variable_y[4], variable_v[1], variable_v[4]}
        and set(interference_graph.neighbors(variable_v[1])) == set(interference_graph.nodes) - {variable_v[1], variable_v[5]}
        and set(interference_graph.neighbors(variable_v[4])) == {aliased_variable_y[4], aliased_variable_z[4], variable_v[1]}
        and set(interference_graph.neighbors(variable_v[5])) == set()
    )


@pytest.fixture()
def construct_graph_dead_code(
    variable_u, variable_v, aliased_variable_x, aliased_variable_y, aliased_variable_z
) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """Graph with dead code that interferes with other variables and is not the RHS of a Phi function.
                           +------------------------------------------+
                           |            printf(0x804a048)             |
                           | scanf(0x804a05e, &(x#1), &(y#1), &(z#1)) |
                           |                x#2 = x#1                 |
                           |              if(x#2 <= y#1)              | -+
                           +------------------------------------------+  |
                             |                                           |
                             |                                           |
                             v                                           |
                           +------------------------------------------+  |
                           |                u#1 = z#1                 |  |
                        +- |              if(x#2 > u#1)               |  |
                        |  +------------------------------------------+  |
                        |    |                                           |
                        |    |                                           |
                        |    v                                           |
    +-----------+       |  +------------------------------------------+  |
    |           |       |  |             u#2 = ϕ(y#1,u#1)             |  |
    | u#5 = u#3 |       |  |       v#3,v#4 = compute(x#2, u#2)        |  |
    |           | <-----+- |                u#3 = y#1                 | <+
    +-----------+       |  +------------------------------------------+
      |                 |    |
      |                 |    |
      |                 |    v
      |                 |  +------------------------------------------+
      |                 |  |                u#4 = z#1                 |
      |                 |  +------------------------------------------+
      |                 |    |
      |                 |    |
      |                 |    v
      |                 |  +------------------------------------------+
      |                 |  |             u#6 = ϕ(u#4,u#5)             |
      +-----------------+> |             u#7 = ϕ(u#4,z#1)             |
                        |  +------------------------------------------+
                        |    |
                        |    |
                        |    v
                        |  +------------------------------------------+
                        |  |             u#8 = ϕ(x#2,u#6)             |
                        |  |             u#9 = ϕ(y#1,u#3)             |
                        |  |            u#10 = ϕ(u#1,u#7)             |
                        |  |  printf(0x804a068, x#2, u#9, u#10, u#8)  |
                        +> |                return 0x0                |
                           +------------------------------------------+
    """
    instructions = [
        # node 0: 0 - 3
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A048)])),
        Assignment(
            ListOperation([]),
            Call(
                ImportedFunctionSymbol("scanf", 0),
                [
                    Constant(0x804A05E),
                    UnaryOperation(OperationType.address, [aliased_variable_x[1]]),
                    UnaryOperation(OperationType.address, [aliased_variable_y[1]]),
                    UnaryOperation(OperationType.address, [aliased_variable_z[1]]),
                ],
            ),
        ),
        Assignment(aliased_variable_x[2], aliased_variable_x[1]),
        Branch(Condition(OperationType.less_or_equal, [aliased_variable_x[2], aliased_variable_y[1]])),
        # node 1: 4 - 5
        Assignment(variable_u[1], aliased_variable_z[1]),
        Branch(Condition(OperationType.greater, [aliased_variable_x[2], variable_u[1]])),
        # # node 2: 6 - 9
        Phi(variable_u[2], [aliased_variable_y[1], variable_u[1]]),
        Assignment(ListOperation([variable_v[3], variable_v[4]]), Call(function_symbol("compute"), [aliased_variable_x[2], variable_u[2]])),
        Assignment(variable_u[3], aliased_variable_y[1]),
        Branch(Condition(OperationType.greater_or_equal, [aliased_variable_z[1], variable_u[3]])),
        # # node 3: 10
        Assignment(variable_u[4], aliased_variable_z[1]),
        # # node 4: 11
        Assignment(variable_u[5], variable_u[3]),
        # node 5: 12 - 13
        Phi(variable_u[6], [variable_u[4], variable_u[5]]),
        Phi(variable_u[7], [variable_u[4], aliased_variable_z[1]]),
        # # node 6: 14 - 18
        Phi(variable_u[8], [aliased_variable_x[2], variable_u[6]]),
        Phi(variable_u[9], [aliased_variable_y[1], variable_u[3]]),
        Phi(variable_u[10], [variable_u[1], variable_u[7]]),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("printf"), [Constant(0x804A068), aliased_variable_x[2], variable_u[9], variable_u[10], variable_u[8]]),
        ),
        Return([Constant(0x0)]),
    ]
    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(7)]
    # Add instructions:
    nodes[0].instructions = instructions[0:4]
    nodes[1].instructions = instructions[4:6]
    nodes[2].instructions = instructions[6:9]
    nodes[3].instructions = [instructions[10]]
    nodes[4].instructions = [instructions[11]]
    nodes[5].instructions = instructions[12:14]
    nodes[6].instructions = instructions[14:]

    instructions[6]._origin_block = {nodes[0]: aliased_variable_y[1], nodes[1]: variable_u[1]}

    instructions[12]._origin_block = {nodes[3]: variable_u[4], nodes[4]: variable_u[5]}
    instructions[13]._origin_block = {nodes[3]: variable_u[4], nodes[4]: aliased_variable_z[1]}

    instructions[14]._origin_block = {nodes[1]: aliased_variable_x[2], nodes[5]: variable_u[6]}
    instructions[15]._origin_block = {nodes[1]: aliased_variable_y[1], nodes[5]: variable_u[3]}
    instructions[16]._origin_block = {nodes[1]: variable_u[1], nodes[5]: variable_u[7]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[6]),
            UnconditionalEdge(nodes[2], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[4]),
            UnconditionalEdge(nodes[3], nodes[5]),
            UnconditionalEdge(nodes[4], nodes[5]),
            UnconditionalEdge(nodes[5], nodes[6]),
        ]
    )
    return nodes, cfg


def test_interference_graph_dead_code(
    construct_graph_dead_code, variable_u, variable_v, aliased_variable_x, aliased_variable_y, aliased_variable_z
):
    nodes, cfg = construct_graph_dead_code

    interference_graph = InterferenceGraph(cfg)

    assert set(interference_graph.nodes) == set(aliased_variable_x[1:3]) | set(variable_u[1:11]) | {
        aliased_variable_y[1],
        aliased_variable_z[1],
        variable_v[3],
        variable_v[4],
    }

    assert (
        set(interference_graph.neighbors(aliased_variable_x[1])) == {aliased_variable_y[1], aliased_variable_z[1]}
        and set(interference_graph.neighbors(aliased_variable_x[2]))
        == set(interference_graph.nodes) - {aliased_variable_x[1], aliased_variable_x[2]}
        and set(interference_graph.neighbors(aliased_variable_y[1]))
        == set(interference_graph.nodes) - set(variable_u[3:11]) - {aliased_variable_y[1]}
        and set(interference_graph.neighbors(aliased_variable_z[1]))
        == set(interference_graph.nodes) - set(variable_u[6:11]) - {variable_u[4], aliased_variable_z[1]}
        and set(interference_graph.neighbors(variable_u[1])) == {aliased_variable_x[2], aliased_variable_y[1], aliased_variable_z[1]}
        and set(interference_graph.neighbors(variable_u[2])) == {aliased_variable_x[2], aliased_variable_y[1], aliased_variable_z[1]}
        and set(interference_graph.neighbors(variable_u[3]))
        == {aliased_variable_x[2], aliased_variable_z[1], variable_u[4], variable_u[5], variable_u[6], variable_u[7]}
        and set(interference_graph.neighbors(variable_u[4])) == {aliased_variable_x[2], variable_u[3]}
        and set(interference_graph.neighbors(variable_u[5])) == {variable_u[3], aliased_variable_x[2], aliased_variable_z[1]}
        and set(interference_graph.neighbors(variable_u[6])) == {variable_u[3], variable_u[7], aliased_variable_x[2]}
        and set(interference_graph.neighbors(variable_u[7])) == {variable_u[3], variable_u[6], aliased_variable_x[2]}
        and set(interference_graph.neighbors(variable_u[8])) == {variable_u[9], variable_u[10], aliased_variable_x[2]}
        and set(interference_graph.neighbors(variable_u[9])) == {variable_u[8], variable_u[10], aliased_variable_x[2]}
        and set(interference_graph.neighbors(variable_u[10])) == {variable_u[8], variable_u[9], aliased_variable_x[2]}
    )


def test_phi_function_in_head1():
    """
    +--------------------+
    |        0.          | ---+
    | u#1 = ϕ(v#0, u#2)  |    |
    | v#1 = ϕ(v#0, u#1)  |    |
    | u#2 = v#1 + 10     | <--+
    +--------------------+
    """
    u1 = Variable("u", Integer.int32_t(), 1)
    u2 = Variable("u", Integer.int32_t(), 2)
    v0 = Variable("v", Integer.int32_t(), 0)
    v1 = Variable("v", Integer.int32_t(), 1)
    node = BasicBlock(0, [Phi(u1, [v0, u2]), Phi(v1, [v0, u1]), Assignment(u2, BinaryOperation(OperationType.plus, [v1, Constant(10)]))])
    node.instructions[0]._origin_block = {None: v0, node: u2}
    node.instructions[1]._origin_block = {None: v0, node: u1}

    cfg = ControlFlowGraph()
    cfg.add_node(node)
    cfg.add_edges_from([UnconditionalEdge(node, node)])

    interference_graph = InterferenceGraph(cfg)

    assert interference_graph.number_of_nodes() == 4 and interference_graph.number_of_edges() == 2
    assert set(interference_graph.neighbors(u1)) == {v1, u2}


def test_phi_function_in_head2():
    """
    +--------------------+
    |        0.          | ---+
    | u#1 = ϕ(v#0, u#2)  |    |
    | v#1 = ϕ(v#0, u#1)  |    |
    | u#2 = u#1 + v#1    | <--+
    +--------------------+
    """
    u1 = Variable("u", Integer.int32_t(), 1)
    u2 = Variable("u", Integer.int32_t(), 2)
    v0 = Variable("v", Integer.int32_t(), 0)
    v1 = Variable("v", Integer.int32_t(), 1)
    node = BasicBlock(0, [Phi(u1, [v0, u2]), Phi(v1, [v0, u1]), Assignment(u2, BinaryOperation(OperationType.plus, [u1, v1]))])
    node.instructions[0]._origin_block = {None: v0, node: u2}
    node.instructions[0]._origin_block = {None: v0, node: u1}
    cfg = ControlFlowGraph()
    cfg.add_node(node)
    cfg.add_edges_from([UnconditionalEdge(node, node)])

    interference_graph = InterferenceGraph(cfg)

    assert interference_graph.number_of_nodes() == 4 and interference_graph.number_of_edges() == 2
    assert set(interference_graph.neighbors(u1)) == {v1, u2}


def test_phi_function_in_head3():
    """
    +--------------------+
    |        0.          | ---+
    | u#1 = ϕ(v#0, u#2)  |    |
    | v#1 = ϕ(v#0, u#1)  |    |
    | u#2 = v#0 + v#1    | <--+
    +--------------------+
    """
    u1 = Variable("u", Integer.int32_t(), 1)
    u2 = Variable("u", Integer.int32_t(), 2)
    v0 = Variable("v", Integer.int32_t(), 0)
    v1 = Variable("v", Integer.int32_t(), 1)
    node = BasicBlock(0, [Phi(u1, [v0, u2]), Phi(v1, [v0, u1]), Assignment(u2, BinaryOperation(OperationType.plus, [v0, v1]))])
    node.instructions[0]._origin_block = {None: v0, node: u2}
    node.instructions[1]._origin_block = {None: v0, node: u1}
    cfg = ControlFlowGraph()
    cfg.add_node(node)
    cfg.add_edges_from([UnconditionalEdge(node, node)])

    interference_graph = InterferenceGraph(cfg)

    assert interference_graph.number_of_nodes() == 4 and interference_graph.number_of_edges() == 5
    assert set(interference_graph.neighbors(u1)) == {v1, u2, v0}
    assert set(interference_graph.neighbors(v0)) == {v1, u1, u2}


def test_phi_function_in_head4():
    """
    +--------------------+
    |        0.          | ---+
    | u#1 = ϕ(v#0, u#3)  |    |
    | u#2 = ϕ(v#1, u#1)  |    |
    | u#3 = u#1 + u#2    | <--+
    +--------------------+
    """
    u1 = Variable("u", Integer.int32_t(), 1)
    u2 = Variable("u", Integer.int32_t(), 2)
    u3 = Variable("u", Integer.int32_t(), 3)
    v0 = Variable("v", Integer.int32_t(), 0)
    v1 = Variable("v", Integer.int32_t(), 1)
    node = BasicBlock(0, [Phi(u1, [v0, u3]), Phi(u2, [v1, u1]), Assignment(u3, BinaryOperation(OperationType.plus, [u1, u2]))])
    node.instructions[0]._origin_block = {None: v0, node: u3}
    node.instructions[1]._origin_block = {None: v1, node: u1}
    cfg = ControlFlowGraph()
    cfg.add_node(node)
    cfg.add_edges_from([UnconditionalEdge(node, node)])

    interference_graph = InterferenceGraph(cfg)

    assert interference_graph.number_of_nodes() == 5 and interference_graph.number_of_edges() == 3
    assert set(interference_graph.neighbors(v0)) == {v1}
    assert set(interference_graph.neighbors(u1)) == {u2, u3}
