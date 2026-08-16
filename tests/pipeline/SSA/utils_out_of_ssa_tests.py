from typing import Dict, List, Optional, Tuple, Union

import pytest
from decompiler.pipeline.ssa.outofssatranslation import SSAOptions
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, IndirectBranch, Instruction, Phi, Relation, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer, UnknownType
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def function_symbol(name: str, value: int = 0) -> FunctionSymbol:
    return FunctionSymbol(name, value)


def imp_function_symbol(name: str, value: int = 0) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value)


@pytest.fixture()
def arg1():
    return [Variable("arg1", Integer.int32_t(), i) for i in range(10)]


@pytest.fixture()
def arg2():
    return [Variable("arg2", Integer.int32_t(), i) for i in range(10)]


@pytest.fixture()
def variable_x():
    return [Variable("x", Integer.int32_t(), i) for i in range(10)]


@pytest.fixture()
def variable_x_new():
    return [Variable(f"x_{i}", Integer.int32_t()) for i in range(10)]


@pytest.fixture()
def aliased_variable_x():
    return [Variable("x", Integer.int32_t(), i, is_aliased=True) for i in range(10)]


@pytest.fixture()
def aliased_variable_x_new():
    return [Variable(f"x_{index}", Integer.int32_t()) for index in range(10)]


@pytest.fixture()
def variable_u():
    return [Variable("u", Integer.int32_t(), i) for i in range(10)]


@pytest.fixture()
def variable_u_new():
    return [Variable(f"u_{i}", Integer.int32_t()) for i in range(10)]


@pytest.fixture()
def variable_v():
    return [Variable("v", Integer.int32_t(), i) for i in range(10)]


@pytest.fixture()
def variable_v_new():
    return [Variable(f"v_{i}", Integer.int32_t()) for i in range(10)]


@pytest.fixture()
def copy_variable_v():
    return [Variable(f"copy_v", Integer.int32_t(), i) for i in range(10)]


@pytest.fixture()
def variable_y():
    return [Variable("y", Integer.int64_t(), i) for i in range(10)]


@pytest.fixture()
def variable_y_new():
    return [Variable(f"y_{i}", Integer.int64_t()) for i in range(10)]


@pytest.fixture()
def aliased_variable_y():
    return [Variable("y", Integer.int32_t(), index, is_aliased=True) for index in range(10)]


@pytest.fixture()
def aliased_variable_y_new():
    return [Variable(f"y_{index}", Integer.int32_t()) for index in range(10)]


@pytest.fixture()
def variable_z():
    return [Variable("z", Integer.int64_t(), i) for i in range(10)]


@pytest.fixture()
def aliased_variable_z():
    return [Variable("z", Integer.int32_t(), index, is_aliased=True) for index in range(10)]


@pytest.fixture()
def aliased_variable_z_new():
    return [Variable(f"z_{index}", Integer.int32_t()) for index in range(10)]


@pytest.fixture()
def variable():
    return [Variable(f"var_{index}", Integer.int32_t()) for index in range(10)]


@pytest.fixture()
def copy_variable():
    return [Variable(f"copy_var_{index}", Integer.int32_t()) for index in range(10)]

@pytest.fixture()
def graph_aliased_name_problem(aliased_variable_z, aliased_variable_y, variable_u, variable_v, variable_x):
    instructions = [
        # node 0
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("Enter two numbers ")])),
        Assignment(aliased_variable_z[2], aliased_variable_z[0]),
        Assignment(variable_v[1], UnaryOperation(OperationType.address, [aliased_variable_z[2]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804A025), variable_v[1]])),
        Assignment(aliased_variable_y[3], aliased_variable_y[0]),
        Assignment(variable_u[2], UnaryOperation(OperationType.address, [aliased_variable_y[3]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804A025), variable_u[2]])),
        # node 1
        Phi(variable_x[2], [Constant(0x1), variable_x[3]]),
        Phi(aliased_variable_y[5], [aliased_variable_y[3], aliased_variable_y[6]]),
        Phi(aliased_variable_z[5], [aliased_variable_z[2], aliased_variable_z[5]]),
        Branch(Condition(OperationType.less_or_equal, [variable_x[2], aliased_variable_z[5]])),
        # node 2
        Assignment(
            aliased_variable_y[6],
            BinaryOperation(
                OperationType.multiply,
                [aliased_variable_y[5], variable_x[2]],
            ),
        ),
        Assignment(
            variable_x[3],
            BinaryOperation(
                OperationType.plus,
                [variable_x[2], Constant(0x1)],
            ),
        ),
        # node 3
        Return([Constant(0x0)]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(4)]
    # Add instructions:
    nodes[0].instructions = instructions[0:7]
    nodes[1].instructions = instructions[7:11]
    nodes[2].instructions = instructions[11:13]
    nodes[3].instructions = [instructions[13]]

    instructions[7]._origin_block = {nodes[0]: Constant(0x1), nodes[2]: variable_x[3]}
    instructions[8]._origin_block = {nodes[0]: aliased_variable_y[3], nodes[2]: aliased_variable_y[6]}
    instructions[9]._origin_block = {nodes[0]: aliased_variable_z[2], nodes[2]: aliased_variable_z[5]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            TrueCase(nodes[1], nodes[2]),
            FalseCase(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[1]),
        ]
    )
    return nodes, instructions, cfg

@pytest.fixture()
def graph_no_dependency(
    variable_x, variable_u, variable_v, aliased_variable_y, variable_x_new, variable_u_new, variable_v_new, aliased_variable_y_new
) -> Tuple[List[BasicBlock], List[Instruction], ControlFlowGraph]:
    """This Graph has a set of Phi-functions that have no dependency.
    +------------------------+
    |   printf(0x804b00c)    |
    +------------------------+
      |
      |
      v
    +------------------------+
    |    x#3 = ϕ(x#2,x#4)    |
    |    v#2 = ϕ(v#1,v#3)    |
    |    u#2 = ϕ(u#1,u#3)    |
    |    y#4 = ϕ(y#3,y#5)    |
    |       u#3 = y#4        |
    |     if(v#2 <= u#3)     |
    +------------------------+
      ^
      |
      |
    +------------------------+
    |       x#4 = v#2        |
    | printf(0x804b045, x#4) |
    +------------------------+
    """
    instructions = [
        # node 0: 0
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        # node 1: 1 - 6
        Phi(variable_x[3], [variable_x[2], variable_x[4]]),
        Phi(variable_v[2], [variable_v[1], variable_v[3]]),
        Phi(variable_u[2], [variable_u[1], variable_u[3]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[5]]),
        Assignment(variable_u[3], aliased_variable_y[4]),
        Branch(Condition(OperationType.less_or_equal, [variable_v[2], variable_u[3]], CustomType("bool", 1))),
        # node 2: 7 - 8
        Assignment(variable_x[4], variable_v[2]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B045), variable_x[4]])),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(10)]
    # Add instructions:
    nodes[0].instructions = [instructions[0]]
    nodes[1].instructions = instructions[1:7]
    nodes[2].instructions = instructions[7:9]

    instructions[1]._origin_block = {nodes[0]: variable_x[2], nodes[2]: variable_x[4]}
    instructions[2]._origin_block = {nodes[0]: variable_v[1], nodes[2]: variable_v[3]}
    instructions[3]._origin_block = {nodes[0]: variable_u[1], nodes[2]: variable_u[3]}
    instructions[4]._origin_block = {nodes[0]: aliased_variable_y[3], nodes[2]: aliased_variable_y[5]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from([UnconditionalEdge(nodes[0], nodes[1]), UnconditionalEdge(nodes[2], nodes[1])])

    new_instructions = [

        # node 0: 0
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        # node 1: 1 - 6
        Phi(variable_x_new[3], [variable_x_new[2], variable_x_new[4]]),
        Phi(variable_v_new[2], [variable_v_new[1], variable_v_new[3]]),
        Phi(variable_u_new[2], [variable_u_new[1], variable_u_new[3]]),
        Phi(aliased_variable_y_new[4], [aliased_variable_y_new[3], aliased_variable_y_new[5]]),
        Assignment(variable_u_new[3], aliased_variable_y_new[4]),
        Branch(Condition(OperationType.less_or_equal, [variable_v_new[2], variable_u_new[3]], CustomType("bool", 1))),
        # node 2: 7 - 8
        Assignment(variable_x_new[4], variable_v_new[2]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B045), variable_x_new[4]])),
    ]

    new_instructions[1]._origin_block = {nodes[0]: variable_x_new[2], nodes[2]: variable_x_new[4]}
    new_instructions[2]._origin_block = {nodes[0]: variable_v_new[1], nodes[2]: variable_v_new[3]}
    new_instructions[3]._origin_block = {nodes[0]: variable_u_new[1], nodes[2]: variable_u_new[3]}
    new_instructions[4]._origin_block = {nodes[0]: aliased_variable_y_new[3], nodes[2]: aliased_variable_y_new[5]}

    return nodes, new_instructions, cfg


@pytest.fixture()
def graph_dependency_but_not_circular(
    variable_v, variable_u, aliased_variable_y, variable_v_new, variable_u_new, aliased_variable_y_new
) -> Tuple[List[BasicBlock], List[Instruction], ControlFlowGraph]:
    """This Graph has a set of Phi-functions that have a dependency, but no circular dependency.
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
    |       return 0x0       |     |        y#4 = ϕ(y#1,y#7,v#4)        |
    |                        | <-- |           if(y#4 <= 0x0)           |
    +------------------------+     +------------------------------------+
                                     |                           ^    ^
                                     |                           |    |
                                     v                           |    |
                                   +--------------------------+  |    |
                                   |  printf(0x804a045, y#4)  |  |    |
                                   |    y#7 = (y#4 - 0x2)     |  |    |
                                   |    v#2 = is_odd(y#7)     |  |    |
                                   | if((v#2 & 0xff) == 0x0)  | -+    |
                                   +--------------------------+       |
                                     |                                |
                                     |                                |
                                     v                                |
                                   +--------------------------+       |
                                   |    v#4 = (y#7 - 0x1)     | ------+
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
        Phi(aliased_variable_y[4], [aliased_variable_y[1], aliased_variable_y[7], variable_v[4]]),
        Branch(Condition(OperationType.less_or_equal, [aliased_variable_y[4], Constant(0x0)])),
        # node 2: 6 - 7
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A049), variable_u[3]])),
        Return([Constant(0x0)]),
        # node 3: 8 - 11
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A045), aliased_variable_y[4]])),
        Assignment(aliased_variable_y[7], BinaryOperation(OperationType.minus, [aliased_variable_y[4], Constant(0x2)])),
        Assignment(variable_v[2], Call(function_symbol("is_odd"), [aliased_variable_y[7]])),
        Branch(
            Condition(OperationType.equal, [BinaryOperation(OperationType.bitwise_and, [variable_v[2], Constant(0xFF)]), Constant(0x0)])
        ),
        # node 4: 12
        Assignment(variable_v[4], BinaryOperation(OperationType.minus, [aliased_variable_y[7], Constant(0x1)])),
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
    instructions[4]._origin_block = {nodes[0]: aliased_variable_y[1], nodes[3]: aliased_variable_y[7], nodes[4]: variable_v[4]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            FalseCase(nodes[1], nodes[2]),
            TrueCase(nodes[1], nodes[3]),
            TrueCase(nodes[3], nodes[1]),
            FalseCase(nodes[3], nodes[4]),
            UnconditionalEdge(nodes[4], nodes[1]),
        ]
    )

    new_instructions = [
        # node 0: 0 - 2
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A00C)])),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_y_new[1]])]),
        ),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A028), aliased_variable_y_new[1]])),
        # node 1: 3 - 5
        Phi(variable_u_new[3], [aliased_variable_y_new[1], aliased_variable_y_new[4]]),
        Phi(aliased_variable_y_new[4], [aliased_variable_y_new[1], aliased_variable_y_new[7], variable_v_new[4]]),
        Branch(Condition(OperationType.less_or_equal, [aliased_variable_y_new[4], Constant(0x0)])),
        # node 2: 6 - 7
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A049), variable_u_new[3]])),
        Return([Constant(0x0)]),
        # node 3: 8 - 11
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A045), aliased_variable_y_new[4]])),
        Assignment(aliased_variable_y_new[7], BinaryOperation(OperationType.minus, [aliased_variable_y_new[4], Constant(0x2)])),
        Assignment(variable_v_new[2], Call(function_symbol("is_odd"), [aliased_variable_y_new[7]])),
        Branch(
            Condition(OperationType.equal, [BinaryOperation(OperationType.bitwise_and, [variable_v_new[2], Constant(0xFF)]), Constant(0x0)])
        ),
        # node 4: 12
        Assignment(variable_v_new[4], BinaryOperation(OperationType.minus, [aliased_variable_y_new[7], Constant(0x1)])),
    ]

    new_instructions[3]._origin_block = {
        nodes[0]: aliased_variable_y_new[1],
        nodes[3]: aliased_variable_y_new[4],
        nodes[4]: aliased_variable_y_new[4],
    }
    new_instructions[4]._origin_block = {
        nodes[0]: aliased_variable_y_new[1],
        nodes[3]: aliased_variable_y_new[7],
        nodes[4]: variable_v_new[4],
    }

    return nodes, new_instructions, cfg


@pytest.fixture()
def graph_circular_dependency(
    variable_x,
    variable_v,
    variable_u,
    aliased_variable_y,
    aliased_variable_z,
    variable_x_new,
    variable_v_new,
    variable_u_new,
    aliased_variable_y_new,
    aliased_variable_z_new,
) -> Tuple[List[BasicBlock], List[Instruction], ControlFlowGraph]:
    """This Graph has a set of Phi-functions that have a circular dependency.
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
            TrueCase(nodes[1], nodes[2]),
            FalseCase(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[1]),
        ]
    )

    new_instructions = [
        # node 0: 0 - 6
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
        Assignment(variable_x_new[1], UnaryOperation(OperationType.address, [aliased_variable_y_new[1]], Integer.int32_t())),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), variable_x_new[1]])),
        Assignment(aliased_variable_y_new[2], aliased_variable_y_new[1]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804BB0C)])),
        Assignment(variable_v_new[1], UnaryOperation(OperationType.address, [aliased_variable_z_new[3]], Integer.int32_t())),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804BB1F), variable_v_new[1]])),
        # node 1: 7 - 10
        Phi(variable_x_new[2], [variable_x_new[1], variable_v_new[2]]),
        Phi(variable_v_new[2], [variable_v_new[1], variable_x_new[2]]),
        Phi(variable_u_new[2], [Constant(1), variable_u_new[1]]),
        Branch(Condition(OperationType.less_or_equal, [variable_u_new[2], Constant(20)])),
        # node 2: 11
        Assignment(variable_u_new[1], BinaryOperation(OperationType.plus, [variable_u_new[2], Constant(1)])),
        # node 3: 12
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804BB0C), variable_x_new[2]])),
    ]

    new_instructions[7]._origin_block = {nodes[0]: variable_x_new[1], nodes[2]: variable_v_new[2]}
    new_instructions[8]._origin_block = {nodes[0]: variable_v_new[1], nodes[2]: variable_x_new[2]}
    new_instructions[9]._origin_block = {nodes[0]: Constant(1), nodes[2]: variable_u_new[1]}

    return nodes, new_instructions, cfg


@pytest.fixture()
def graph_with_input_arguments_different_variable_types(
    arg1, arg2, variable_v, variable_u, variable_x, variable_y
) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """This Graph has different variable types and a set of function arguments.
                       +----------------------------------+
                       |                0.                |
                       | if(arg2#0 < arg1#0)              | -+
                       +----------------------------------+  |
                         |                                   |
                         |                                   |
                         v                                   |
                       +----------------------------------+  |
                       |                1.                |  |
                       +----------------------------------+  |
                         |                                   |
                         |                                   |
                         v                                   |
                       +----------------------------------+  |
                       |                2.                |  |
                       | arg2#2 = ϕ(arg2#0,arg1#0)        |  |
                    +- | if(arg1#0 > (arg2#2 + arg2#2))   | <+
                    |  +----------------------------------+
                    |    |
                    |    |
                    |    v
                    |  +----------------------------------+
                    |  |                3.                |
                    |  | arg2#3 = arg1#0 - arg2#2         |
                    |  +----------------------------------+
                    |    |
                    |    |
                    |    v
                    |  +----------------------------------+
                    |  |                4.                |
                    |  | arg2#4 = ϕ(arg2#2,arg2#3)        |
                    +> | v#1 = (arg1#0 - arg2#4) + 0x1    |
                       +----------------------------------+
                         |
                         |
                         v
    +------------+     +----------------------------------+
    |            |     |                5.                |
    |     7.     |     | u#2 = ϕ(0x1,u#5)                 |
    | return x#2 |     | v#2 = ϕ(v#1,v#2)                 |
    |            |     | x#2 = ϕ(0x1,y#1)                 |
    |            | <-- | if(u#2 <= arg2#4)                | <+
    +------------+     +----------------------------------+  |
                         |                                   |
                         |                                   |
                         v                                   |
                       +----------------------------------+  |
                       |                6.                |  |
                       | v#2 = v#2 + 0x1                  |  |
                       | u#5 = u#2 + 0x1                  |  |
                       | y#1 = (((long) v#2) * x#2) / u#2 | -+
                       +----------------------------------+
    """
    instructions = [
        # node 0
        Branch(Condition(OperationType.less, [arg2[0], arg1[0]])),
        # node 2
        Phi(arg2[2], [arg2[0], arg1[0]]),
        Branch(Condition(OperationType.greater, [arg1[0], BinaryOperation(OperationType.plus, [arg2[2], arg2[2]])])),
        # node 3
        Assignment(arg2[3], BinaryOperation(OperationType.minus, [arg1[0], arg2[2]])),
        # node 4
        Phi(arg2[4], [arg2[2], arg2[3]]),
        Assignment(
            variable_v[1], BinaryOperation(OperationType.plus, [BinaryOperation(OperationType.minus, [arg1[0], arg2[4]]), Constant(0x1)])
        ),
        # node 5
        Phi(variable_u[2], [Constant(0x1), variable_u[5]]),
        Phi(variable_v[2], [variable_v[1], variable_v[2]]),
        Phi(variable_x[2], [Constant(0x1), variable_y[1]]),
        Branch(Condition(OperationType.less_or_equal, [variable_u[2], arg2[4]])),
        # node 6
        Assignment(variable_v[2], BinaryOperation(OperationType.plus, [variable_v[2], Constant(0x1)])),
        Assignment(variable_u[5], BinaryOperation(OperationType.plus, [variable_u[2], Constant(0x1)])),
        Assignment(
            variable_y[1],
            BinaryOperation(
                OperationType.divide,
                [
                    BinaryOperation(
                        OperationType.multiply,
                        [UnaryOperation(OperationType.cast, [variable_v[2]], vartype=Integer.int64_t()), variable_x[2]],
                    ),
                    variable_u[2],
                ],
            ),
        ),
        # node 7
        Return([variable_x[2]]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(8)]
    # Add instructions:
    nodes[0].instructions = [instructions[0]]
    nodes[1].instructions = []
    nodes[2].instructions = instructions[1:3]
    nodes[3].instructions = [instructions[3]]
    nodes[4].instructions = instructions[4:6]
    nodes[5].instructions = instructions[6:10]
    nodes[6].instructions = instructions[10:13]
    nodes[7].instructions = [instructions[13]]

    instructions[1]._origin_block = {nodes[1]: arg2[0], nodes[0]: arg1[0]}
    instructions[4]._origin_block = {nodes[2]: arg2[2], nodes[3]: arg2[3]}
    instructions[6]._origin_block = {nodes[4]: Constant(0x1), nodes[6]: variable_u[5]}
    instructions[7]._origin_block = {nodes[4]: variable_v[1], nodes[6]: variable_v[2]}
    instructions[8]._origin_block = {nodes[4]: Constant(0x1), nodes[6]: variable_y[1]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[1]),
            FalseCase(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[2]),
            FalseCase(nodes[2], nodes[3]),
            TrueCase(nodes[2], nodes[4]),
            UnconditionalEdge(nodes[3], nodes[4]),
            UnconditionalEdge(nodes[4], nodes[5]),
            TrueCase(nodes[5], nodes[6]),
            FalseCase(nodes[5], nodes[7]),
            UnconditionalEdge(nodes[6], nodes[5]),
        ]
    )

    return nodes, cfg


@pytest.fixture()
def graph_with_input_arguments_different_variable_types_2(
    arg1, arg2, variable_v, variable_u, variable_x, variable_y
) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """This Graph has different variable types and a set of function arguments.
                       +----------------------------------+
                       |                0.                |
                       | if(arg2#0 < arg1#0)              | -+
                       +----------------------------------+  |
                         |                                   |
                         |                                   |
                         v                                   |
                       +----------------------------------+  |
                       |                1.                |  |
                       +----------------------------------+  |
                         |                                   |
                         |                                   |
                         v                                   |
                       +----------------------------------+  |
                       |                2.                |  |
                       | arg2#2 = ϕ(arg2#0,arg1#0)        |  |
                    +- | if(arg1#0 > (arg2#2 + arg2#2))   | <+
                    |  +----------------------------------+
                    |    |
                    |    |
                    |    v
                    |  +----------------------------------+
                    |  |                3.                |
                    |  | arg2#3 = arg1#0 - arg2#2         |
                    |  +----------------------------------+
                    |    |
                    |    |
                    |    v
                    |  +----------------------------------+
                    |  |                4.                |
                    |  | arg2#4 = ϕ(arg2#2,arg2#3)        |
                    +> | v#1 = (arg1#0 - arg2#4) + 0x1    |
                       +----------------------------------+
                         |
                         |
                         v
    +------------+     +----------------------------------+
    |            |     |                5.                |
    |     7.     |     | u#2 = ϕ(0x1,u#5)                 |
    | return x#2 |     | v#2 = ϕ(v#1,v#2)                 |
    |            |     | x#2 = ϕ(0x1,y#1)                 |
    |            | <-- | if(u#2 <= arg2#4)                | <+
    +------------+     +----------------------------------+  |
                         |                                   |
                         |                                   |
                         v                                   |
                       +----------------------------------+  |
                       |                6.                |  |
                       | u#5 = u#2 + 0x1                  |  |
                       | y#1 = (((long) v#2) * x#2) / u#2 | -+
                       +----------------------------------+
    """
    instructions = [
        # node 0
        Branch(Condition(OperationType.less, [arg2[0], arg1[0]])),
        # node 2
        Phi(arg2[2], [arg2[0], arg1[0]]),
        Branch(Condition(OperationType.greater, [arg1[0], BinaryOperation(OperationType.plus, [arg2[2], arg2[2]])])),
        # node 3
        Assignment(arg2[3], BinaryOperation(OperationType.minus, [arg1[0], arg2[2]])),
        # node 4
        Phi(arg2[4], [arg2[2], arg2[3]]),
        Assignment(
            variable_v[1], BinaryOperation(OperationType.plus, [BinaryOperation(OperationType.minus, [arg1[0], arg2[4]]), Constant(0x1)])
        ),
        # node 5
        Phi(variable_u[2], [Constant(0x1), variable_u[5]]),
        Phi(variable_v[2], [variable_v[1], variable_v[2]]),
        Phi(variable_x[2], [Constant(0x1), variable_y[1]]),
        Branch(Condition(OperationType.less_or_equal, [variable_u[2], arg2[4]])),
        # node 6
        Assignment(variable_u[5], BinaryOperation(OperationType.plus, [variable_u[2], Constant(0x1)])),
        Assignment(
            variable_y[1],
            BinaryOperation(
                OperationType.divide,
                [
                    BinaryOperation(
                        OperationType.multiply,
                        [UnaryOperation(OperationType.cast, [variable_v[2]], vartype=Integer.int64_t()), variable_x[2]],
                    ),
                    variable_u[2],
                ],
            ),
        ),
        # node 7
        Return([variable_x[2]]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(8)]
    # Add instructions:
    nodes[0].instructions = [instructions[0]]
    nodes[1].instructions = []
    nodes[2].instructions = instructions[1:3]
    nodes[3].instructions = [instructions[3]]
    nodes[4].instructions = instructions[4:6]
    nodes[5].instructions = instructions[6:10]
    nodes[6].instructions = instructions[10:12]
    nodes[7].instructions = [instructions[12]]

    instructions[1]._origin_block = {nodes[1]: arg2[0], nodes[0]: arg1[0]}
    instructions[4]._origin_block = {nodes[2]: arg2[2], nodes[3]: arg2[3]}
    instructions[6]._origin_block = {nodes[4]: Constant(0x1), nodes[6]: variable_u[5]}
    instructions[7]._origin_block = {nodes[4]: variable_v[1], nodes[6]: variable_v[2]}
    instructions[8]._origin_block = {nodes[4]: Constant(0x1), nodes[6]: variable_y[1]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[1]),
            FalseCase(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[1], nodes[2]),
            FalseCase(nodes[2], nodes[3]),
            TrueCase(nodes[2], nodes[4]),
            UnconditionalEdge(nodes[3], nodes[4]),
            UnconditionalEdge(nodes[4], nodes[5]),
            TrueCase(nodes[5], nodes[6]),
            FalseCase(nodes[5], nodes[7]),
            UnconditionalEdge(nodes[6], nodes[5]),
        ]
    )

    return nodes, cfg


@pytest.fixture()
def graph_with_edge_condition(
    aliased_variable_y, aliased_variable_z, aliased_variable_x, variable_v
) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """This Graph has edges with conditions.
                            +--------------------------------+
                            |               0.               |
                            | printf("Enter your choice = ") |
                            | scanf(0x804a025, &(y#0))       |
                            | puts("Enter a number ")        |
                            | scanf(0x804a025, &(z#0))       |
                            | puts("Enter a second number ") |
                            | scanf(0x804a025, &(x#0))       |
                            | if(y#0 > 0x5)                  |
                            +--------------------------------+
                                            |
                                            |
                                            v
                                       +---------+
                +----------------------|   1.    |------------------------------+
                |               +------| jmp y#0 |---------------+              |
                |               |      +---------+               |              |
                |               |      |         |               |              |
                v               |+-----+         v               |              v
    +-------------------------+ ||  +-------------------------+  |  +-------------------------+
    |           3.            | ||  |           4.            |  |  |           6.            |
    | v#1 = (z#0 + 0x1) * x#0 | ||  | v#2 = (z#0 + 0x2) + x#0 |  |  | v#4 = (z#0 + 0x4) - x#0 |
    +-------------------------+ ||  +-------------------------+  |  +-------------------------+
                         |      ||                     |         |                           |
              +----------+------+|                     |         |                           |
              v          |       v                     |         v                           |
    +------------------+ | +-------------------------+ | +---------------------------------+ |
    |        2.        | | |           5.            | | |               7.                | |
    | puts("default!") | | | v#3 = x#0 - (z#0 + 0x3) | | | v#5 = 0x2 * ((z#0 + 0x4) + x#0) | |
    +------------------+ | +-------------------------+ | +---------------------------------+ |
              |          |                   |     |       |                                 |
              |          |                   v     v       v                                 |
              |          |          +----------------------------------+                     |
              |          +--------->|                8.                |<--------------------+
              +-------------------->| v#6 = ϕ(0x0,v#1,v#2,v#3,v#4,v#5) |
                                    | printf("a = %d ", v#6)           |
                                    | return                           |
                                    +----------------------------------+
    """
    instructions = [
        # node 0
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("Enter your choice = ")])),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_y[0]])]),
        ),
        Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("Enter a number ")])),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_z[0]])]),
        ),
        Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("Enter a second number ")])),
        Assignment(
            ListOperation([]),
            Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_x[0]])]),
        ),
        Branch(Condition(OperationType.greater, [aliased_variable_y[0], Constant(0x5)])),
        # node 1
        IndirectBranch(aliased_variable_y[0]),
        # node 2
        Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("default !")])),
        # node 3
        Assignment(
            variable_v[1],
            BinaryOperation(
                OperationType.multiply,
                [BinaryOperation(OperationType.plus, [aliased_variable_z[0], Constant(0x1)]), aliased_variable_x[0]],
            ),
        ),
        # node 4
        Assignment(
            variable_v[2],
            BinaryOperation(
                OperationType.plus,
                [BinaryOperation(OperationType.plus, [aliased_variable_z[0], Constant(0x2)]), aliased_variable_x[0]],
            ),
        ),
        # node 5
        Assignment(
            variable_v[3],
            BinaryOperation(
                OperationType.minus,
                [aliased_variable_x[0], BinaryOperation(OperationType.plus, [aliased_variable_z[0], Constant(0x3)])],
            ),
        ),
        # node 6
        Assignment(
            variable_v[4],
            BinaryOperation(
                OperationType.minus,
                [BinaryOperation(OperationType.plus, [aliased_variable_z[0], Constant(0x4)]), aliased_variable_x[0]],
            ),
        ),
        #  7
        Assignment(
            variable_v[5],
            BinaryOperation(
                OperationType.multiply,
                [
                    Constant(2),
                    BinaryOperation(
                        OperationType.plus,
                        [BinaryOperation(OperationType.plus, [aliased_variable_z[0], Constant(0x4)]), aliased_variable_x[0]],
                    ),
                ],
            ),
        ),
        # node 8
        Phi(variable_v[6], [Constant(0x0), variable_v[1], variable_v[2], variable_v[3], variable_v[4], variable_v[5]]),
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a = %d "), variable_v[6]])),
        Return(Constant(0x0)),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(9)]
    # Add instructions:
    nodes[0].instructions = instructions[0:7]
    nodes[1].instructions = [instructions[7]]
    nodes[2].instructions = [instructions[8]]
    nodes[3].instructions = [instructions[9]]
    nodes[4].instructions = [instructions[10]]
    nodes[5].instructions = [instructions[11]]
    nodes[6].instructions = [instructions[12]]
    nodes[7].instructions = [instructions[13]]
    nodes[8].instructions = instructions[14:]

    instructions[14]._origin_block = {
        nodes[2]: Constant(0x0),
        nodes[3]: variable_v[1],
        nodes[4]: variable_v[2],
        nodes[5]: variable_v[3],
        nodes[6]: variable_v[4],
        nodes[7]: variable_v[5],
    }

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[3]),
            FalseCase(nodes[0], nodes[1]),
            SwitchCase(nodes[1], nodes[2], [Constant(0)]),
            SwitchCase(nodes[1], nodes[3], [Constant(1)]),
            SwitchCase(nodes[1], nodes[4], [Constant(2)]),
            SwitchCase(nodes[1], nodes[5], [Constant(3)]),
            SwitchCase(nodes[1], nodes[6], [Constant(4)]),
            SwitchCase(nodes[1], nodes[7], [Constant(5)]),
            UnconditionalEdge(nodes[2], nodes[8]),
            UnconditionalEdge(nodes[3], nodes[8]),
            UnconditionalEdge(nodes[4], nodes[8]),
            UnconditionalEdge(nodes[5], nodes[8]),
            UnconditionalEdge(nodes[6], nodes[8]),
            UnconditionalEdge(nodes[7], nodes[8]),
        ]
    )

    return nodes, cfg


@pytest.fixture()
def graph_phi_fct_in_head2(variable_u, variable_v) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """
    +--------------------+
    |        0.          | ---+
    | u#1 = ϕ(v#0, u#3)  |    |
    | u#2 = ϕ(v#1, u#1)  |    |
    | u#3 = u#1 + u#2    | <--+
    +--------------------+
    """
    instructions = [
        Phi(variable_u[1], [variable_v[0], variable_u[3]]),
        Phi(variable_u[2], [variable_v[1], variable_u[1]]),
        Assignment(variable_u[3], BinaryOperation(OperationType.plus, [variable_u[1], variable_u[2]])),
    ]
    node = BasicBlock(0, instructions[:])
    node.instructions[0]._origin_block = {None: variable_v[0], node: variable_u[3]}
    node.instructions[1]._origin_block = {None: variable_v[1], node: variable_u[1]}

    cfg = ControlFlowGraph()
    cfg.add_node(node)
    cfg.add_edges_from([UnconditionalEdge(node, node)])
    return [node], cfg


@pytest.fixture()
def graph_phi_fct_in_head1(variable_u, variable_v) -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """
    +--------------------+
    |        0.          | ---+
    | v#1 = ϕ(v#0, u#1)  |    |
    | u#1 = ϕ(v#0, u#2)  |    |
    | u#2 = v#1 + 10     | <--+
    +--------------------+
    """
    instructions = [
        Phi(variable_v[1], [variable_v[0], variable_u[1]]),
        Phi(variable_u[1], [variable_v[0], variable_u[2]]),
        Assignment(variable_u[2], BinaryOperation(OperationType.plus, [variable_v[1], Constant(10)])),
    ]
    node = BasicBlock(0, instructions[:])
    node.instructions[0]._origin_block = {None: variable_v[0], node: variable_u[1]}
    node.instructions[1]._origin_block = {None: variable_v[0], node: variable_u[2]}

    cfg = ControlFlowGraph()
    cfg.add_node(node)
    cfg.add_edges_from([UnconditionalEdge(node, node)])
    return [node], cfg


@pytest.fixture()
def graph_with_relation() -> Tuple[List[BasicBlock], ControlFlowGraph]:
    """
        Test loop test2 (simplified)
                                                    +-------------------------------------+
                                                    |                 0.                  |
                                                    |       var_28#1 = &(var_1c#0)        |
                                                    | __isoc99_scanf(0x804b01f, var_28#1) |
                                                    |        var_1c#2 -> var_1c#0         |
                                                    |   edx_3#4 = var_1c#2 * 0x66666667   |
                                                    |      eax_7#8 = edx_3#4 << 0x2       |
                                                    +-------------------------------------+
                                                      |
                                                      |
                                                      v
    +-----------------------------------------+     +-------------------------------------+
    |                   3.                    |     |                 1.                  |
    | printf((var_1c#2 - eax_7#8) + var_1c#3) |     |   var_1c#3 = ϕ(var_1c#2,var_1c#4)   |
    |               return 0x0                | <-- |         if(var_1c#3 > 0x9)          | <+
    +-----------------------------------------+     +-------------------------------------+  |
                                                      |                                      |
                                                      |                                      |
                                                      v                                      |
                                                    +-------------------------------------+  |
                                                    |                 2.                  |  |
                                                    |  var_1c#4 = var_1c#3 * 0x66666667   | -+
                                                    +-------------------------------------+
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
                    Assignment(var_28, UnaryOperation(OperationType.address, [var_1c[0]], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(
                        ListOperation([]),
                        Call(
                            Constant("__isoc99_scanf", UnknownType()),
                            [Constant(134524959, Integer(32, True)), var_28],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Relation(var_1c[2], var_1c[0]),
                    Assignment(
                        edx_3,
                        BinaryOperation(OperationType.multiply, [var_1c[2], Constant(1717986919, Integer(32, True))], Integer(64, True)),
                    ),
                    Assignment(
                        eax_7,
                        BinaryOperation(OperationType.left_shift, [edx_3, Constant(2, Integer(32, True))], Integer(32, True)),
                    ),
                ],
            ),
            BasicBlock(
                1,
                [
                    Phi(var_1c[3], [var_1c[2], var_1c[4]]),
                    Branch(Condition(OperationType.greater, [var_1c[3], Constant(9, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        var_1c[4],
                        BinaryOperation(OperationType.multiply, [var_1c[3], Constant(1717986919, Integer(32, True))], Integer(64, True)),
                    )
                ],
            ),
            BasicBlock(
                3,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            Constant("printf", UnknownType()),
                            [
                                BinaryOperation(
                                    OperationType.plus,
                                    [BinaryOperation(OperationType.minus, [var_1c[2], eax_7], Integer(32, True)), var_1c[3]],
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

    vertices[1].instructions[0]._origin_block = {vertices[0]: var_1c[2], vertices[2]: var_1c[4]}
    cfg.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[1]),
        ]
    )
    return vertices, cfg


def init_phi_functions_of_block(cfg: ControlFlowGraph) -> Dict[BasicBlock, List[Phi]]:
    phi_functions_of: Dict[BasicBlock, List[Phi]] = dict()
    for basicblock in cfg.nodes:
        if phi_instructions := [instruction for instruction in basicblock.instructions if isinstance(instruction, Phi)]:
            phi_functions_of[basicblock] = phi_instructions

    return phi_functions_of


def decompiler_task(cfg: ControlFlowGraph, mode: Optional[Union[SSAOptions, str]] = None, args: Optional[List] = None) -> DecompilerTask:
    if not args:
        args = []
    options = Options()
    if mode:
        options.set("out-of-ssa-translation.mode", mode.value if isinstance(mode, SSAOptions) else mode)
    return DecompilerTask(name="out-of-ssa-test", function_identifier="", cfg=cfg, options=options, function_parameters=args)
