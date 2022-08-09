import pytest
from decompiler.pipeline.commons.cast_simplification_functions import simplify_casts_in_instruction
from decompiler.pipeline.dataflowanalysis.redundant_casts_elimination import RedundantCastsElimination
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo.expressions import Constant, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer, Type
from decompiler.task import DecompilerTask

signed_int = Integer.int32_t()
unsigned_int = Integer.uint32_t()
signed_long = Integer.int64_t()
unsigned_long = Integer.uint64_t()
signed_char = Integer.int8_t()
unsigned_char = Integer.uint8_t()
pointer_t = Pointer(unsigned_int)


def test_when_field_can_be_merged_with_casts():
    """

        +---------------------------------------------------------------+
        |                              0.                               |
        |         reg#1 = (unsigned long) (unsigned int) reg#0          |
        |         if(((4: ) (unsigned long) int_var#0) <= 0x4)          |
        |         if(((1: ) (unsigned long) int_var#0) <= 0x4)          |
        | if(((1: ) (unsigned long) (unsigned int) char_var#0) <= 0x40) |
        | if(((4: ) (unsigned long) (unsigned byte) int_var#0) <= 0x40) |
        +---------------------------------------------------------------+


        +--------------------------------------------------------+
        |                           0.                           |
        |              reg#1 = (unsigned int) reg#0              |
        |                  if(int_var#0 <= 0x4)                  |
        |         if(((unsigned byte) int_var#0) <= 0x4)         |<---- what it (1:) of long?
        |                 if(char_var#0 <= 0x40)                 |
        | if(((unsigned int) (unsigned byte) int_var#0) <= 0x40) |<---- will it be ok for signed? should we not just take the minimal cast if max cast is from field access?
        +--------------------------------------------------------+
    :return:
    :rtype:
    """
    cfg = ControlFlowGraph()
    r32 = [
        Variable(
            "reg",
            unsigned_int,
            i,
        )
        for i in range(10)
    ]
    r64 = [
        Variable(
            "reg",
            unsigned_long,
            i,
        )
        for i in range(10)
    ]
    int_var = Variable("int_var", signed_int, 0)
    char_var = Variable("char_var", signed_char, 0)

    instructions = [
        Assignment(r64[1], cast(unsigned_long, cast(unsigned_int, r64[0]))),
        Branch(Condition(OperationType.less_or_equal, [contract(unsigned_int, cast(unsigned_long, int_var)), Constant(0x4)])),
        Branch(Condition(OperationType.less_or_equal, [contract(unsigned_char, cast(unsigned_long, int_var)), Constant(0x4)])),
        Branch(
            Condition(
                OperationType.less_or_equal, [contract(unsigned_char, cast(unsigned_long, cast(unsigned_int, char_var))), Constant(0x40)]
            )
        ),
        Branch(
            Condition(
                OperationType.less_or_equal, [contract(unsigned_int, cast(unsigned_long, cast(unsigned_char, int_var))), Constant(0x40)]
            )
        ),
    ]
    cfg.add_node(BasicBlock(0, instructions))
    RedundantCastsElimination().run(DecompilerTask("test", cfg))
    assert [i for i in cfg.instructions] == [
        Assignment(r64[1], cast(unsigned_int, r64[0])),
        Branch(Condition(OperationType.less_or_equal, [int_var, Constant(0x4)])),
        Branch(Condition(OperationType.less_or_equal, [cast(unsigned_char, int_var), Constant(0x4)])),
        Branch(Condition(OperationType.less_or_equal, [char_var, Constant(0x40)])),
        Branch(Condition(OperationType.less_or_equal, [cast(unsigned_int, cast(unsigned_char, int_var)), Constant(0x40)])),
    ]


r64 = [
    Variable(
        "reg",
        signed_long,
        i,
    )
    for i in range(10)
]
ur64 = [
    Variable(
        "reg",
        unsigned_long,
        i,
    )
    for i in range(10)
]
int_var = Variable("int_var", signed_int, 0)
r32 = [
    Variable(
        "reg",
        signed_int,
        i,
    )
    for i in range(10)
]

int_var2 = Variable("int_var", signed_int, 1)

char_var = Variable("char_var", signed_char, 0)


def cast(type, var):
    return UnaryOperation(OperationType.cast, [var], vartype=type)


def add(_type, *args):
    return BinaryOperation(OperationType.plus, list(args), vartype=_type)


def branch(operation, *args):
    return Branch(Condition(operation, list(args)))


def contract(_type: Type, var):
    t = _type.copy()
    _field = UnaryOperation(OperationType.cast, [var], vartype=t, contraction=True)
    return _field


def printf(*args):
    return Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0x42), list(args)))


@pytest.mark.parametrize(
    "instruction, simplified_instruction",
    [
        # int_var#0:int = (int) (unsigned long) ((4: ) reg#0:long) + 0x5 <-- int
        # int_var#0:int = reg#0:long + 0x5 <-- int
        (
            Assignment(int_var, cast(signed_int, cast(unsigned_long, add(signed_int, contract(signed_int, r64[0]), Constant(0x5))))),
            Assignment(int_var, add(signed_int, r64[0], Constant(0x5))),
        ),
        # reg#0:unsigned long = (unsigned long) (4: ) (unsigned long) int_var#0:int
        # reg#0:unsigned long = int_var#0:int
        (Assignment(ur64[0], cast(unsigned_long, contract(unsigned_int, cast(unsigned_long, int_var)))), Assignment(ur64[0], int_var)),
        # reg#0:unsigned long = (unsigned long) int_var#0:int
        # reg#0:unsigned long = int_var#0:int
        (Assignment(ur64[0], cast(unsigned_long, int_var)), Assignment(ur64[0], int_var)),
        (
            Assignment(
                contract(CustomType.bool(), Variable("rdx", signed_long, 2)),
                BinaryOperation(OperationType.less_or_equal, [Variable("arg1", signed_int, 0), Constant(1, signed_int)]),
            ),
            Assignment(
                contract(CustomType.bool(), Variable("rdx", signed_long, 2)),
                BinaryOperation(OperationType.less_or_equal, [Variable("arg1", signed_int, 0), Constant(1, signed_int)]),
            ),
        ),
    ],
)
def test_cast_simplification_for_assignments(instruction, simplified_instruction):
    simplify_casts_in_instruction(instruction)
    assert instruction == simplified_instruction


@pytest.mark.parametrize(
    "instruction, simplified_instruction",
    [
        # if(((1: ) (unsigned int) char_var#0:byte) <= 0x7a <-- bool)
        # if(char_var#0:byte <= 0x7a <-- bool)
        (
            branch(OperationType.less_or_equal, contract(unsigned_char, cast(unsigned_int, char_var)), Constant(0x7A)),
            branch(OperationType.less_or_equal, char_var, Constant(0x7A)),
        ),
        # if(((1: ) (unsigned int) char_var#0:byte) <= 0x7a <-- bool)
        # if(char_var#0:byte <= 0x7a <-- bool)
        (
            branch(OperationType.less_or_equal, contract(unsigned_char, cast(unsigned_int, char_var)), Constant(0x7A)),
            branch(OperationType.less_or_equal, char_var, Constant(0x7A)),
        ),
        # if(((1: ) (unsigned long) (unsigned int) char_var#0:byte) <= 0x7a <-- bool)
        # if(char_var#0:byte <= 0x7a <-- bool)
        (
            branch(OperationType.less_or_equal, contract(unsigned_char, cast(unsigned_long, cast(unsigned_int, char_var))), Constant(0x7A)),
            branch(OperationType.less_or_equal, char_var, Constant(0x7A)),
        ),
        # if(int_var#0:int <= ((4: ) (unsigned long) int_var#1:int) <-- bool)
        # if(int_var#0:int <= int_var#1:int <-- bool)
        (
            branch(OperationType.less_or_equal, int_var, contract(unsigned_int, cast(unsigned_long, int_var2))),
            branch(OperationType.less_or_equal, int_var, int_var2),
        ),
        # if(((4: ) reg#0:long) > 0x9)
        # if(((int) reg#0:long) > 0x9)
        (
            branch(OperationType.greater, contract(signed_int, r64[0]), Constant(0x9)),
            branch(OperationType.greater, cast(signed_int, r64[0]), Constant(0x9)),
        ),
        # if(((1: ) reg#0:unsigned long) > 0x9)
        # if(((unsigned byte) reg#0:unsigned long) > 0x9)
        (
            branch(OperationType.greater, contract(unsigned_char, ur64[0]), Constant(0x9)),
            branch(OperationType.greater, cast(unsigned_char, ur64[0]), Constant(0x9)),
        ),
        # if(((4: ) int_var#0:int) > 0x1)
        # if(int_var#0:int > 0x1)
        (
            branch(OperationType.greater, contract(signed_int, int_var), Constant(1)),
            branch(OperationType.greater, int_var, Constant(1)),
        ),
        # if(((4: ) (unsigned long) int_var#0:int) == ((4: ) (unsigned long) int_var#1:int))
        # if(int_var#0:int == int_var#1:int)
        (
            branch(
                OperationType.equal,
                contract(unsigned_int, cast(unsigned_long, int_var)),
                contract(unsigned_int, cast(unsigned_long, int_var2)),
            ),
            branch(OperationType.equal, int_var, int_var2),
        ),
    ],
)
def test_cast_simplification_for_branches(instruction, simplified_instruction):
    simplify_casts_in_instruction(instruction)
    assert instruction == simplified_instruction


@pytest.mark.parametrize(
    "instruction, simplified_instruction",
    [
        # printf("'%c' is Consonant.", (int) (1: ) (unsigned int) char_var#0:byte)
        # printf("'%c' is Consonant.", (int) char_var#0:byte)
        (
            printf(Constant("'%c' is Consonant."), cast(signed_int, contract(unsigned_char, cast(unsigned_int, char_var)))),
            printf(Constant("'%c' is Consonant."), cast(signed_int, char_var)),
        ),
        # printf("'%c' is Consonant.", (unsigned long) (4: ) (unsigned long) (int) (1: ) (unsigned long) (unsigned int) char_var#0:byte)
        # printf("'%c' is Consonant.", (int) char_var#0:byte)
        (
            printf(
                Constant("'%c' is Consonant."),
                cast(
                    unsigned_long,
                    contract(
                        unsigned_int,
                        cast(unsigned_long, cast(signed_int, contract(unsigned_char, cast(unsigned_long, cast(unsigned_int, char_var))))),
                    ),
                ),
            ),
            printf(Constant("'%c' is Consonant."), cast(signed_int, char_var)),
        ),
        # printf("Natural numbers from 1 to %d : ", (unsigned long) (4: ) (unsigned long) int_var#0:int)
        # printf("Natural numbers from 1 to %d : ", int_var#0:int)
        (
            printf(
                Constant("Natural numbers from 1 to %d : "),
                cast(
                    unsigned_long,
                    contract(
                        unsigned_int,
                        cast(unsigned_long, int_var),
                    ),
                ),
            ),
            printf(Constant("Natural numbers from 1 to %d : "), int_var),
        ),
        # printf("%d %d  ", (unsigned long) (4: ) (unsigned long) int_var#0:int, (unsigned long) int_var#1:int)
        # printf("%d %d  ", int_var#0:int, int_var#1:int)
        (
            printf(
                Constant("%d %d  "),
                cast(unsigned_long, contract(unsigned_int, cast(unsigned_long, int_var))),
                cast(unsigned_long, int_var2),
            ),
            printf(Constant("%d %d  "), int_var, int_var2),
        ),
    ],
)
def test_some_prints(instruction, simplified_instruction):
    """Printfs are kind of special, more work on that in upcoming issues"""
    # rax_1#5:unsigned long = printf("%d %d  ", (unsigned long) (4: ) (unsigned long) var_10#2:int, (unsigned long) var_c#2:int)
    print(instruction)

    simplify_casts_in_instruction(instruction)
    print(instruction)
    assert instruction == simplified_instruction


@pytest.mark.parametrize(
    "instruction, simplified_instruction",
    [
        # return (unsigned long) (4: ) (unsigned long) (int) (unsigned long) ((4: ) rax_1#2:long) + 0x1<--int
        # return reg#0:long + 0x1 <--int
        (
            Return(
                [
                    cast(
                        unsigned_long,
                        contract(
                            unsigned_int,
                            cast(
                                unsigned_long,
                                cast(signed_int, cast(unsigned_long, add(signed_int, contract(signed_int, r64[0]), Constant(0x1)))),
                            ),
                        ),
                    )
                ]
            ),
            Return([add(signed_int, r64[0], Constant(0x1))]),
        ),
    ],
)
def test_cast_simplification_for_returns(instruction, simplified_instruction):
    simplify_casts_in_instruction(instruction)
    assert instruction == simplified_instruction


@pytest.mark.parametrize(
    "instruction, simplified_instruction",
    [
        (
            Assignment(int_var, cast(signed_int, cast(pointer_t, cast(unsigned_char, Constant(0x1))))),
            Assignment(int_var, cast(signed_int, cast(pointer_t, cast(unsigned_char, Constant(0x1))))),
        )
    ],
)
def test_cast_simplification_for_ptr_int_cast(instruction, simplified_instruction):
    simplify_casts_in_instruction(instruction)
    assert instruction == simplified_instruction


@pytest.mark.parametrize(
    "instruction, simplified_instruction",
    [
        (
            Return(
                [
                    cast(
                        signed_long,
                        BinaryOperation(
                            OperationType.plus,
                            [int_var, BinaryOperation(OperationType.right_shift_us, [cast(signed_long, int_var), Constant(32)])],
                        ),
                    )
                ]
            ),
            Return(
                [
                    BinaryOperation(
                        OperationType.plus,
                        [int_var, BinaryOperation(OperationType.right_shift_us, [cast(signed_long, int_var), Constant(32)])],
                    )
                ]
            ),
        )
    ],
)
def test_cast_simplification_ignores_bitwise_binop(instruction, simplified_instruction):
    simplify_casts_in_instruction(instruction)
    assert instruction == simplified_instruction
