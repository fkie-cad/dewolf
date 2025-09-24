"""Pytest for renaming SSA-variables to non-SSA-variables."""

import string

from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.variable_renaming import (
    ConditionalVariableRenamer,
    MinimalVariableRenamer,
    SimpleVariableRenamer,
    VariableRenamer,
)
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Expression, Float, GlobalVariable

from tests.pipeline.SSA.utils_out_of_ssa_tests import *


def imp_function_symbol(name: str, value: int = 0x42) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value)


# test for update instructions
def test_update_instructions_no_redundant(variable_x, variable_v, aliased_variable_y, variable):
    """Updates the instructions according to a renaming dictionary. No redundant assignments occur."""
    binary_operation = BinaryOperation(OperationType.plus, [aliased_variable_y[2], aliased_variable_y[3]])
    instructions = [
        # node 0:
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        Assignment(variable_x[3], variable_x[2]),
        Assignment(variable_v[2], variable_v[1]),
        Assignment(aliased_variable_y[4], binary_operation),
        # node 1:
        Assignment(aliased_variable_y[5], binary_operation),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable_x[3], variable_v[2]])),
        # node 2:
        Assignment(variable_v[2], variable_v[3]),
        Assignment(variable_x[4], variable_v[2]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B045), variable_x[4]])),
        Assignment(variable_x[3], variable_x[4]),
    ]

    new_instructions = [
        # node 0:
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        Assignment(variable[2], variable[1]),
        Assignment(variable[5], variable[4]),
        Assignment(variable[6], BinaryOperation(OperationType.plus, [variable[7], variable[8]])),
        # node 1:
        Assignment(variable[6], BinaryOperation(OperationType.plus, [variable[7], variable[8]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable[2], variable[5]])),
        # node 2:
        Assignment(variable[5], variable[4]),
        Assignment(variable[3], variable[5]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B045), variable[3]])),
        Assignment(variable[2], variable[3]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(10)]
    # Add instructions:
    nodes[0].instructions = instructions[0:4]
    nodes[1].instructions = instructions[4:6]
    nodes[2].instructions = instructions[6:]

    cfg = ControlFlowGraph()
    cfg.add_edges_from([UnconditionalEdge(nodes[0], nodes[1]), UnconditionalEdge(nodes[2], nodes[1])])
    variable_renamer = VariableRenamer(decompiler_task(cfg), InterferenceGraph(cfg))

    variable_renamer.renaming_map = {
        variable_x[2]: variable[1],
        variable_x[3]: variable[2],
        variable_x[4]: variable[3],
        variable_v[1]: variable[4],
        variable_v[2]: variable[5],
        variable_v[3]: variable[4],
        aliased_variable_y[4]: variable[6],
        aliased_variable_y[5]: variable[6],
        aliased_variable_y[2]: variable[7],
        aliased_variable_y[3]: variable[8],
    }

    variable_renamer.rename()

    assert nodes[0].instructions + nodes[1].instructions + nodes[2].instructions == new_instructions
    assert nodes[0].instructions[1].destination.ssa_name == variable_x[3] and nodes[0].instructions[1].value.ssa_name == variable_x[2]
    assert [operand.ssa_name for operand in binary_operation.operands] == [aliased_variable_y[2], aliased_variable_y[3]]


def test_update_instructions_with_redundant(variable_x, variable_v, aliased_variable_y, variable):
    """Updates the instructions according to a renaming dictionary. Some redundant assignments occur."""
    binary_operation = BinaryOperation(OperationType.plus, [aliased_variable_y[2], aliased_variable_y[3]])
    instructions = [
        # node 0:
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        Assignment(variable_x[3], variable_x[2]),
        Assignment(variable_v[2], variable_v[1]),
        Assignment(aliased_variable_y[4], binary_operation),
        # node 1:
        Assignment(aliased_variable_y[5], binary_operation),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable_x[3], variable_v[2]])),
        # node 2:
        Assignment(variable_v[2], variable_v[3]),
        Assignment(variable_x[4], variable_v[2]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B045), variable_x[4]])),
        Assignment(variable_x[3], variable_x[4]),
        Assignment(aliased_variable_y[4], aliased_variable_y[5]),
    ]

    new_instructions = [
        # node 0:
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        Assignment(variable[5], BinaryOperation(OperationType.plus, [variable[3], variable[4]])),
        # node 1:
        Assignment(variable[5], BinaryOperation(OperationType.plus, [variable[3], variable[4]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable[1], variable[2]])),
        # node 2:
        Assignment(variable[1], variable[2]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B045), variable[1]])),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(10)]
    # Add instructions:
    nodes[0].instructions = instructions[0:4]
    nodes[1].instructions = instructions[4:6]
    nodes[2].instructions = instructions[6:]

    cfg = ControlFlowGraph()
    cfg.add_edges_from([UnconditionalEdge(nodes[0], nodes[1]), UnconditionalEdge(nodes[2], nodes[1])])
    variable_renamer = VariableRenamer(decompiler_task(cfg), InterferenceGraph(cfg))

    variable_renamer.renaming_map = {
        variable_x[2]: variable[1],
        variable_x[3]: variable[1],
        variable_x[4]: variable[1],
        variable_v[1]: variable[2],
        variable_v[2]: variable[2],
        variable_v[3]: variable[2],
        aliased_variable_y[2]: variable[3],
        aliased_variable_y[3]: variable[4],
        aliased_variable_y[4]: variable[5],
        aliased_variable_y[5]: variable[5],
    }

    variable_renamer.rename()

    assert nodes[0].instructions + nodes[1].instructions + nodes[2].instructions == new_instructions


def test_update_instructions_relation_not_redundant(graph_with_relations_easy, variable):
    task, interference_graph = graph_with_relations_easy

    var_18 = [Variable("var_18", Integer(32, True), i, True, None) for i in range(4)]
    var_10_1 = Variable("var_10", Pointer(Integer(32, True), 32), 1, False, None)
    var_18_2_new = Variable("var_18_2", Integer(32, True))
    var_18_3_new = Variable("var_18_3", Integer(32, True))
    var_10_1_new = Variable("var_10_1", Pointer(Integer(32, True), 32), None, False)

    variable_renamer = VariableRenamer(task, interference_graph)
    variable_renamer.renaming_map = {
        var_10_1: var_10_1_new,
        var_18[2]: var_18_2_new,
        var_18[3]: var_18_3_new,
    }

    with pytest.raises(ValueError):
        variable_renamer.rename()


# test for renaming
@pytest.fixture()
def renaming_graph(graph_with_input_arguments_different_variable_types) -> Tuple[DecompilerTask, InterferenceGraph]:
    """The base control flow graph for the renaming tests."""
    _, cfg = graph_with_input_arguments_different_variable_types
    task = decompiler_task(cfg, None, [Variable("arg1", Integer.int32_t()), Variable("arg2", Integer.int32_t())])
    interference_graph = InterferenceGraph(cfg)

    return task, interference_graph


def test_simple_renaming_with_arguments(
    renaming_graph,
    arg1,
    arg2,
    variable_v,
    variable_v_new,
    variable_u,
    variable_u_new,
    variable_x,
    variable_x_new,
    variable_y,
    variable_y_new,
):
    """Simple variable renaming when we have some input arguments."""
    task, interference_graph = renaming_graph
    simple_variable_renamer = SimpleVariableRenamer(task, interference_graph)

    arg1_new = [Variable("arg1", Integer.int32_t())] + [Variable(f"arg1_{i}", Integer.int32_t()) for i in range(1, 6)]
    arg2_new = [Variable("arg2", Integer.int32_t())] + [Variable(f"arg2_{i}", Integer.int32_t()) for i in range(1, 6)]

    assert simple_variable_renamer.renaming_map == {
        arg1[0]: arg1_new[0],
        arg2[0]: arg2_new[0],
        arg2[2]: arg2_new[2],
        arg2[3]: arg2_new[3],
        arg2[4]: arg2_new[4],
        variable_v[1]: variable_v_new[1],
        variable_u[2]: variable_u_new[2],
        variable_x[2]: variable_x_new[2],
        variable_v[2]: variable_v_new[2],
        variable_u[5]: variable_u_new[5],
        variable_y[1]: variable_y_new[1],
    }


def test_minimal_renaming(renaming_graph, arg1, arg2, variable_v, variable_u, variable_x, variable_y, variable):
    """Minimal renaming with input arguments and different variable types."""
    task, interference_graph = renaming_graph
    PhiFunctionLifter(task.graph, interference_graph, init_phi_functions_of_block(task.graph)).lift()
    minimal_variable_renamer = MinimalVariableRenamer(task, interference_graph)

    arg1_new = Variable("arg1", Integer.int32_t())
    arg2_new = Variable("arg2", Integer.int32_t())
    variable[3] = Variable("var_3", Integer.int64_t())

    assert minimal_variable_renamer.renaming_map == {
        arg1[0]: arg1_new,
        arg2[0]: arg2_new,
        arg2[2]: arg2_new,
        arg2[3]: arg2_new,
        arg2[4]: arg2_new,
        variable_v[1]: arg1_new,
        variable_x[2]: variable[0],
        variable_u[2]: arg1_new,
        variable_v[2]: variable[1],
        variable_u[5]: variable[2],
        variable_y[1]: variable[3],
    }


def test_minimal_renaming_with_phi_functions(renaming_graph, arg1, arg2, variable_v, variable_u, variable_x, variable_y, variable):
    """Minimal renaming with Phi-functions."""
    task, interference_graph = renaming_graph
    minimal_variable_renamer = MinimalVariableRenamer(task, interference_graph)

    arg1_new = Variable("arg1", Integer.int32_t())
    arg2_new = Variable("arg2", Integer.int32_t())
    variable[3] = Variable("var_3", Integer.int64_t())

    assert minimal_variable_renamer.renaming_map == {
        arg1[0]: arg1_new,
        arg2[0]: arg2_new,
        arg2[2]: arg2_new,
        arg2[3]: arg2_new,
        arg2[4]: arg2_new,
        variable_v[1]: arg1_new,
        variable_u[2]: arg1_new,
        variable_x[2]: variable[0],
        variable_v[2]: variable[1],
        variable_u[5]: variable[2],
        variable_y[1]: variable[3],
    }


@pytest.fixture()
def graph_with_different_aliased_variables(
    arg1, aliased_variable_x, aliased_variable_y, variable_u, variable_z
) -> Tuple[DecompilerTask, InterferenceGraph]:
    """
    Graph with two aliased variables that could have the same name.
                            +--------------------------+
                            |            0.            |
                            |    printf(0x804a00c)     |
                            | scanf(0x804a025, &(y#1)) |
                            |     if(y#1 < arg1#0)     | -+
                            +--------------------------+  |
                              |                           |
                              |                           |
                              v                           |
                            +--------------------------+  |
                            |            1.            |  |
                            |        y#2 = y#1         |  |
                            |     u#1 = y#2 + 0x2      |  |
                            +--------------------------+  |
                              |                           |
                              |                           |
                              v                           |
    +-----------------+     +--------------------------+  |
    |                 |     |            2.            |  |
    |                 |     |  arg1#2 = ϕ(arg1#0,u#1)  |  |
    |       4.        |     |    printf(0x804a00c)     |  |
    | u#3 = x#2 - 0x4 |     |        x#2 = 0x2         |  |
    |                 |     | scanf(0x804a025, &(x#2)) |  |
    |                 | <-- |     if(arg1#2 > x#2)     | <+
    +-----------------+     +--------------------------+
      |                       |
      |                       |
      |                       v
      |                     +--------------------------+
      |                     |            3.            |
      |                     |    z#1 = arg1#2 * x#2    |
      |                     +--------------------------+
      |                       |
      |                       |
      |                       v
      |                     +--------------------------+
      |                     |            5.            |
      |                     |     u#4 = ϕ(z#1,u#3)     |
      +-------------------> |        return u#4        |
                            +--------------------------+
    """
    instructions = [
        # node 0
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A00C)])),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_y[1]])]),
        ),
        Branch(Condition(OperationType.less, [aliased_variable_y[1], arg1[0]])),
        # node 1
        Assignment(aliased_variable_y[2], aliased_variable_y[1]),
        Assignment(variable_u[1], BinaryOperation(OperationType.plus, [aliased_variable_y[2], Constant(2)])),
        # node 2
        Phi(arg1[2], [arg1[0], variable_u[1]]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A00C)])),
        Assignment(aliased_variable_x[2], Constant(2)),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_x[2]])]),
        ),
        Branch(Condition(OperationType.greater, [arg1[2], aliased_variable_x[2]])),
        # node 3
        Assignment(variable_z[1], BinaryOperation(OperationType.multiply, [arg1[2], aliased_variable_x[2]])),
        # node 4
        Assignment(variable_u[3], BinaryOperation(OperationType.minus, [aliased_variable_x[2], Constant(4)])),
        # node 5
        Phi(variable_u[4], [variable_z[1], variable_u[3]]),
        Return([variable_u[4]]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(8)]
    # Add instructions:
    nodes[0].instructions = instructions[0:3]
    nodes[1].instructions = instructions[3:5]
    nodes[2].instructions = instructions[5:10]
    nodes[3].instructions = [instructions[10]]
    nodes[4].instructions = [instructions[11]]
    nodes[5].instructions = instructions[12:]

    instructions[4]._origin_block = {nodes[0]: arg1[0], nodes[1]: variable_u[1]}
    instructions[10]._origin_block = {nodes[3]: variable_z[1], nodes[4]: variable_u[3]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            FalseCase(nodes[0], nodes[1]),
            TrueCase(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[2]),
            TrueCase(nodes[2], nodes[3]),
            FalseCase(nodes[2], nodes[4]),
            UnconditionalEdge(nodes[3], nodes[5]),
            UnconditionalEdge(nodes[4], nodes[5]),
        ]
    )

    task = decompiler_task(cfg, None, [Variable("arg1", Integer.int32_t())])
    interference_graph = InterferenceGraph(cfg)

    return task, interference_graph


def test_minimal_renaming_not_grouping_aliased_variables(
    graph_with_different_aliased_variables, variable, arg1, variable_u, aliased_variable_y, aliased_variable_x, variable_z
):
    """Minimal renaming where two aliased-variables could be grouped but are not grouped due to different names."""
    task, interference_graph = graph_with_different_aliased_variables
    minimal_variable_renamer = MinimalVariableRenamer(task, interference_graph)

    arg1_new = Variable("arg1", Integer.int32_t())
    variable[0].is_aliased = True
    variable[1].is_aliased = True
    variable[2]._type = Integer.int64_t()

    assert minimal_variable_renamer.renaming_map == {
        arg1[0]: arg1_new,
        arg1[2]: arg1_new,
        variable_u[1]: arg1_new,
        variable_u[4]: arg1_new,
        variable_u[3]: arg1_new,
        aliased_variable_y[1]: variable[0],
        aliased_variable_y[2]: variable[0],
        aliased_variable_x[2]: variable[1],
        variable_z[1]: variable[2],
    }


def test_minimal_renaming_function_arguments_same_color(variable_v, variable_u):
    """Two function argument should get the same name, which is impossible."""
    instructions = [
        Assignment(variable_v[1], BinaryOperation(OperationType.plus, [variable_v[0], variable_u[0]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable_v[1]])),
    ]
    node = BasicBlock(0, instructions)
    cfg = ControlFlowGraph()
    cfg.add_node(node)
    task = decompiler_task(cfg, None, [Variable("v", Integer.int32_t()), Variable("u", Integer.int32_t())])
    interference_graph = InterferenceGraph()
    interference_graph.add_nodes_from([variable_v[0], variable_v[1], variable_u[0]])

    minimal_variable_renamer = MinimalVariableRenamer(task, interference_graph)
    assert minimal_variable_renamer.renaming_map[variable_v[0]] != minimal_variable_renamer.renaming_map[variable_u[0]]


def test_minimal_renaming_problem_function_argument_name(variable_v):
    """A function argument has as name var_{int}, which should not happen"""
    new_variable = Variable("var_", Integer.int32_t(), 0)
    instructions = [
        Assignment(variable_v[1], BinaryOperation(OperationType.plus, [variable_v[0], new_variable])),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [variable_v[1]])),
    ]
    node = BasicBlock(0, instructions)
    cfg = ControlFlowGraph()
    cfg.add_node(node)
    task = decompiler_task(cfg, None, [Variable("v", Integer.int32_t()), Variable("var_", Integer.int32_t())])
    interference_graph = InterferenceGraph()
    interference_graph.add_nodes_from([variable_v[0], variable_v[1], new_variable])
    interference_graph.add_edge(variable_v[0], new_variable)

    with pytest.raises(NameError):
        MinimalVariableRenamer(task, interference_graph)


@pytest.fixture()
def graph_with_relations_easy() -> Tuple[DecompilerTask, InterferenceGraph]:
    """
    Basic test that we never remove relations
    +----------------------------+
    |             0.             |
    |   var_10#1 = &(var_18#2)   |
    |     *(var_10#1) = 0xa      |
    |   var_18#3 -> var_18#2     |
    |         return 0x0         |
    +----------------------------+
    """
    var_18 = [Variable("var_18", Integer(32, True), i, True, None) for i in range(5)]
    var_10_1 = Variable("var_10", Pointer(Integer(32, True), 32), 1, False, None)
    cfg = ControlFlowGraph()
    cfg.add_node(
        BasicBlock(
            0,
            [
                Assignment(var_10_1, UnaryOperation(OperationType.address, [var_18[2]], Pointer(Integer(32, True), 32), None, False)),
                Assignment(
                    UnaryOperation(OperationType.dereference, [var_10_1], Pointer(Integer(32, True), 32), 3, False),
                    Constant(10, Pointer(Integer(32, True), 32)),
                ),
                Relation(var_18[3], var_18[2]),
                Return(ListOperation([Constant(0, Integer(32, True))])),
            ],
        )
    )
    task = decompiler_task(cfg)
    interference_graph = InterferenceGraph(cfg)
    return task, interference_graph


def test_simple_renaming_basic_relation(graph_with_relations_easy):
    """Checks that simple renaming handles arelations."""
    task, interference_graph = graph_with_relations_easy
    simple_variable_renamer = SimpleVariableRenamer(task, interference_graph)

    var_18 = [Variable("var_18", Integer(32, True), i, True, None) for i in range(4)]
    var_10_1 = Variable("var_10", Pointer(Integer(32, True), 32), 1, False, None)
    var_18_2_new = Variable("var_18_2", Integer(32, True))
    var_18_3_new = Variable("var_18_3", Integer(32, True))
    var_10_1_new = Variable("var_10_1", Pointer(Integer(32, True), 32), None, False)

    assert simple_variable_renamer.renaming_map == {
        var_10_1: var_10_1_new,
        var_18[2]: var_18_2_new,
        var_18[3]: var_18_2_new,
    }


def test_minimal_renaming_basic_relation(graph_with_relations_easy, variable):
    """Checks that minimal renaming can handle relations."""
    task, interference_graph = graph_with_relations_easy
    minimal_variable_renamer = MinimalVariableRenamer(task, interference_graph)

    var_18 = [Variable("var_18", Integer(32, True), i, True, None) for i in range(4)]
    var_10_1 = Variable("var_10", Pointer(Integer(32, True), 32), 1, False, None)
    variable[0].is_aliased = True
    variable[1]._type = Pointer(Integer(32, True), 32)

    assert minimal_variable_renamer.renaming_map == {
        var_10_1: variable[1],
        var_18[2]: variable[0],
        var_18[3]: variable[0],
    }


def test_conditional_renaming_basic_relation(graph_with_relations_easy, variable):
    """Checks that conditional renaming can handle relations."""
    task, interference_graph = graph_with_relations_easy
    minimal_variable_renamer = MinimalVariableRenamer(task, interference_graph)

    var_18 = [Variable("var_18", Integer(32, True), i, True, None) for i in range(4)]
    var_10_1 = Variable("var_10", Pointer(Integer(32, True), 32), 1, False, None)
    variable[0].is_aliased = True
    variable[1]._type = Pointer(Integer(32, True), 32)

    assert minimal_variable_renamer.renaming_map == {
        var_10_1: variable[1],
        var_18[2]: variable[0],
        var_18[3]: variable[0],
    }


@pytest.fixture()
def graph_with_relation() -> Tuple[DecompilerTask, InterferenceGraph]:
    """
        Test loop test2

                                                                                                    +----------------------------------------------------------------------------+
                                                                                                    |                                     0.                                     |
                                                                                                    |      printf("Enter any number to find sum of first and last digit: ")      |
                                                                                                    |                           var_28#1 = &(var_1c#0)                           |
                                                                                                    |                    __isoc99_scanf(0x804b01f, var_28#1)                     |
                                                                                                    |                            var_1c#2 -> var_1c#0                            |
                                                                                                    | edx_3#4 = (((var_1c#2 * 0x66666667) >> 0x20) >> 0x2) - (var_1c#2 >> 0x1f)  |
                                                                                                    |                    eax_7#8 = (edx_3#4 << 0x2) + edx_3#4                    |
                                                                                                    |                            var_1c#3 = var_1c#2                             |
                                                                                                    +----------------------------------------------------------------------------+
                                                                                                      |
                                                                                                      |
                                                                                                      v
    +-----------------------------------------------------------------------------------------+     +----------------------------------------------------------------------------+
    |                                           3.                                            |     |                                     1.                                     |
    | printf("Sum of first and last digit = %d", (var_1c#2 - (eax_7#8 + eax_7#8)) + var_1c#3) |     |                             if(var_1c#3 > 0x9)                             |
    |                                       return 0x0                                        | <-- |                                                                            | <+
    +-----------------------------------------------------------------------------------------+     +----------------------------------------------------------------------------+  |
                                                                                                      |                                                                             |
                                                                                                      |                                                                             |
                                                                                                      v                                                                             |
                                                                                                    +----------------------------------------------------------------------------+  |
                                                                                                    |                                     2.                                     |  |
                                                                                                    | var_1c#4 = (((var_1c#3 * 0x66666667) >> 0x20) >> 0x2) - (var_1c#3 >> 0x1f) |  |
                                                                                                    |                            var_1c#3 = var_1c#4                             | -+
                                                                                                    +----------------------------------------------------------------------------+
    """
    cfg = ControlFlowGraph()
    var_28 = Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    var_1c = [Variable("var_1c", Integer(32, True), i, True, None) for i in range(5)]
    edx_3 = Variable("edx_3", Integer(32, True), 4, False, None)
    eax_7 = Variable("eax_7", Integer(32, True), 8, False, None)
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            ImportedFunctionSymbol("printf", 0),
                            [Constant(134525004, Pointer(Integer(8, True), 32))],
                            Pointer(CustomType("void", 0), 32),
                            1,
                        ),
                    ),
                    Assignment(
                        var_28,
                        UnaryOperation(
                            OperationType.address,
                            [var_1c[0]],
                            Pointer(Integer(32, True), 32),
                            None,
                            False,
                        ),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            ImportedFunctionSymbol("__isoc99_scanf", 0),
                            [Constant(134524959, Integer(32, True)), var_28],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Relation(var_1c[2], var_1c[0]),
                    Assignment(
                        edx_3,
                        BinaryOperation(
                            OperationType.minus,
                            [
                                BinaryOperation(
                                    OperationType.right_shift,
                                    [
                                        BinaryOperation(
                                            OperationType.right_shift,
                                            [
                                                BinaryOperation(
                                                    OperationType.multiply,
                                                    [
                                                        var_1c[2],
                                                        Constant(1717986919, Integer(32, True)),
                                                    ],
                                                    Integer(64, True),
                                                ),
                                                Constant(32, UnknownType()),
                                            ],
                                            Integer(64, True),
                                        ),
                                        Constant(2, Integer(32, True)),
                                    ],
                                    Integer(32, True),
                                ),
                                BinaryOperation(
                                    OperationType.right_shift,
                                    [var_1c[2], Constant(31, Integer(32, True))],
                                    Integer(32, True),
                                ),
                            ],
                            Integer(32, True),
                        ),
                    ),
                    Assignment(
                        eax_7,
                        BinaryOperation(
                            OperationType.plus,
                            [
                                BinaryOperation(
                                    OperationType.left_shift,
                                    [edx_3, Constant(2, Integer(32, True))],
                                    Integer(32, True),
                                ),
                                edx_3,
                            ],
                            Integer(32, True),
                        ),
                    ),
                    Assignment(var_1c[3], var_1c[2]),
                ],
            ),
            BasicBlock(
                1,
                [
                    Branch(
                        Condition(
                            OperationType.greater,
                            [var_1c[3], Constant(9, Integer(32, True))],
                            CustomType("bool", 1),
                        )
                    )
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        var_1c[4],
                        BinaryOperation(
                            OperationType.minus,
                            [
                                BinaryOperation(
                                    OperationType.right_shift,
                                    [
                                        BinaryOperation(
                                            OperationType.right_shift,
                                            [
                                                BinaryOperation(
                                                    OperationType.multiply,
                                                    [
                                                        var_1c[3],
                                                        Constant(1717986919, Integer(32, True)),
                                                    ],
                                                    Integer(64, True),
                                                ),
                                                Constant(32, UnknownType()),
                                            ],
                                            Integer(64, True),
                                        ),
                                        Constant(2, Integer(32, True)),
                                    ],
                                    Integer(32, True),
                                ),
                                BinaryOperation(
                                    OperationType.right_shift,
                                    [var_1c[3], Constant(31, Integer(32, True))],
                                    Integer(32, True),
                                ),
                            ],
                            Integer(32, True),
                        ),
                    ),
                    Assignment(var_1c[3], var_1c[4]),
                ],
            ),
            BasicBlock(
                3,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            ImportedFunctionSymbol("printf", 0),
                            [
                                Constant(134525060, Pointer(Integer(8, True), 32)),
                                BinaryOperation(
                                    OperationType.plus,
                                    [
                                        BinaryOperation(
                                            OperationType.minus,
                                            [
                                                var_1c[2],
                                                BinaryOperation(
                                                    OperationType.plus,
                                                    [
                                                        eax_7,
                                                        eax_7,
                                                    ],
                                                    Integer(32, True),
                                                ),
                                            ],
                                            Integer(32, True),
                                        ),
                                        var_1c[3],
                                    ],
                                    Integer(32, True),
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            5,
                        ),
                    ),
                    Return(ListOperation([Constant(0, Integer(32, True))])),
                ],
            ),
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
    task = decompiler_task(cfg)
    interference_graph = InterferenceGraph(cfg)
    return task, interference_graph


def test_simple_renaming_relation(graph_with_relation):
    """Test for relations with simple renaming"""
    task, interference_graph = graph_with_relation
    simple_variable_renamer = SimpleVariableRenamer(task, interference_graph)

    var_28 = Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    var_28_new = Variable("var_28_1", Pointer(Integer(32, True), 32))
    var_1c = [Variable("var_1c", Integer(32, True), i, True, None) for i in range(5)]
    var_1c_new = [Variable(f"var_1c_{i}", Integer(32, True)) for i in range(5)]
    edx_3 = Variable("edx_3", Integer(32, True), 4, False, None)
    edx_3_new = Variable("edx_3_4", Integer(32, True))
    eax_7 = Variable("eax_7", Integer(32, True), 8, False, None)
    eax_7_new = Variable("eax_7_8", Integer(32, True))

    assert simple_variable_renamer.renaming_map == {
        var_28: var_28_new,
        edx_3: edx_3_new,
        eax_7: eax_7_new,
        var_1c[0]: var_1c_new[0],
        var_1c[2]: var_1c_new[0],
        var_1c[3]: var_1c_new[3],
        var_1c[4]: var_1c_new[4],
    }


def test_minimal_renaming_relation(graph_with_relation, variable):
    """Test for relations with simple renaming"""
    task, interference_graph = graph_with_relation
    minimal_variable_renamer = MinimalVariableRenamer(task, interference_graph)

    var_28 = Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    var_1c = [Variable("var_1c", Integer(32, True), i, True, None) for i in range(5)]
    edx_3 = Variable("edx_3", Integer(32, True), 4, False, None)
    eax_7 = Variable("eax_7", Integer(32, True), 8, False, None)
    variable[0].is_aliased = True
    variable[1].is_aliased = True
    variable[3]._type = Pointer(Integer(32, True), 32)

    assert minimal_variable_renamer.renaming_map == {
        var_28: variable[3],
        edx_3: variable[2],
        eax_7: variable[2],
        var_1c[0]: variable[0],
        var_1c[2]: variable[0],
        var_1c[3]: variable[1],
        var_1c[4]: variable[1],
    }

#TODO fix this test
"""
def test_conditional_renaming_relation(graph_with_relation, variable):
"""
    #Test for relations with simple renaming
"""
    task, interference_graph = graph_with_relation
    conditional_variable_renamer = ConditionalVariableRenamer(task, interference_graph)

    var_28 = Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    var_1c = [Variable("var_1c", Integer(32, True), i, True, None) for i in range(5)]
    edx_3 = Variable("edx_3", Integer(32, True), 4, False, None)
    eax_7 = Variable("eax_7", Integer(32, True), 8, False, None)
    variable[0].is_aliased = True
    variable[1]._type = Pointer(Integer(32, True), 32)
    variable[2].is_aliased = True

    assert conditional_variable_renamer.renaming_map == {
        var_28: variable[1],
        edx_3: variable[3],
        eax_7: variable[3],
        var_1c[0]: variable[0],
        var_1c[2]: variable[0],
        var_1c[3]: variable[2],
        var_1c[4]: variable[2],
    }
"""

#TODO fix this test
"""
def test_conditional_renaming():
"""
    #Test that conditional renaming only combines related variables
"""
    orig_variables = [Variable(letter, Integer.int32_t()) for letter in string.ascii_lowercase]
    new_variables = [Variable(f"var_{index}", Integer.int32_t()) for index in range(10)]

    cfg = ControlFlowGraph()
    cfg.add_node(
        BasicBlock(
            0,
            [
                Assignment(orig_variables[0], Constant(0, Integer.int32_t())),
                Assignment(ListOperation([]), Call(FunctionSymbol("fun", 0), [orig_variables[0]])),
                Assignment(orig_variables[1], Constant(1, Integer.int32_t())),
                Assignment(ListOperation([]), Call(FunctionSymbol("fun", 0), [orig_variables[1]])),
                Assignment(orig_variables[2], orig_variables[1]),
                Assignment(ListOperation([]), Call(FunctionSymbol("fun", 0), [orig_variables[2]])),
                Assignment(orig_variables[3], Constant(3, Integer.int32_t())),
                Assignment(ListOperation([]), Call(FunctionSymbol("fun", 0), [orig_variables[3]])),
            ],
        )
    )

    task = decompiler_task(cfg, SSAOptions.conditional)
    interference_graph = InterferenceGraph(cfg)
    renamer = ConditionalVariableRenamer(task, interference_graph)

    assert renamer.renaming_map == {
        orig_variables[0]: new_variables[0],
        orig_variables[1]: new_variables[2],
        orig_variables[2]: new_variables[2],
        orig_variables[3]: new_variables[1],
    }
"""

#TODO fix this Test
"""def test_conditional_parallel_edges():
"""
    #Test that conditional renaming prioritizes paralles edges of single edges, whose sum of
    #weights is bigger than the weight of the single edge
"""

    def _v(name: str) -> Variable:
        return Variable(name, Float.float())

    def _c(value: float) -> Constant:
        return Constant(value, Float.float())

    def _op(exp: Expression) -> BinaryOperation:
        return BinaryOperation(OperationType.plus_float, [exp, _c(0)])

    cfg = ControlFlowGraph()
    cfg.add_node(
        b1 := BasicBlock(
            1,
            [
                Assignment(_v("b"), _op(BinaryOperation(OperationType.plus_float, [_v("a0"), GlobalVariable("g0", Float.float(), _c(0))]))),
                Assignment(_v("c"), _v("b")),
                Assignment(_v("a1"), BinaryOperation(OperationType.plus_float, [_op(_v("b")), _v("c")])),
                Assignment(_v("a0"), _v("a1")),  # lifted phi function
            ],
        )
    )
    cfg.add_node(
        b0 := BasicBlock(
            0,
            [
                # Phi(_v("a0"), [_c(0), _v("a1")], origin_block={b1: _v("a1")}),
                Branch(Condition(OperationType.less, [_v("a0"), _c(100)]))
            ],
        )
    )
    cfg.add_node(b2 := BasicBlock(2, [Return([])]))

    cfg.add_edge(TrueCase(b0, b1))
    cfg.add_edge(FalseCase(b0, b2))
    cfg.add_edge(UnconditionalEdge(b1, b0))

    task = decompiler_task(cfg, SSAOptions.conditional)
    interference_graph = InterferenceGraph(cfg)
    renamer = ConditionalVariableRenamer(task, interference_graph)

    assert frozenset(frozenset(c) for c in renamer._variable_classes_handler.variable_class.values()) == frozenset(
        {frozenset({GlobalVariable("g0", Float.float(), _c(0))}), frozenset({_v("c")}), frozenset({_v("a0"), _v("a1"), _v("b")})}
    )
"""