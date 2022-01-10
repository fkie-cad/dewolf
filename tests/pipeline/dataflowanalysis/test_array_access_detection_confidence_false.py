from decompiler.pipeline.dataflowanalysis.array_access_detection import ArrayAccessDetection
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Return
from decompiler.structures.pseudo.operations import ArrayInfo, BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer
from decompiler.task import DecompilerTask


def imp_function_symbol(name: str, value: int = 0x42) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value)


def graphs_equal(g1: ControlFlowGraph, g2: ControlFlowGraph) -> bool:
    if type(g1) != type(g2):
        return False
    return all(x.instructions == y.instructions for x, y in zip(g1.nodes, g2.nodes))


def run_array_access_detection(cfg: ControlFlowGraph) -> None:
    task = get_task(cfg)
    ArrayAccessDetection().run(task)


def get_task(cfg: ControlFlowGraph) -> DecompilerTask:
    task = DecompilerTask("test", cfg)
    return task


def test1():
    """
                            +------------------------------------------------+
                            |                       0.                       |
                            |            __x86.get_pc_thunk.bx()             |
                            +------------------------------------------------+
                              |
                              |
                              v
    +-----------------+     +------------------------------------------------+
    |       3.        |     |                       1.                       |
    | return var_10#2 |     |           var_10#2 = ϕ(0x0,var_10#3)           |
    |                 | <-- |             if(var_10#2 < arg2#0)              | <+
    +-----------------+     +------------------------------------------------+  |
                              |                                                 |
                              |                                                 |
                              v                                                 |
                            +------------------------------------------------+  |
                            |                       2.                       |  |
                            |                eax_1#3 = rand()                |  |
                            | *(arg1#0 + (var_10#2 << 0x2))  = eax_1#3 + 0xa |  |
                            |             printf("Element %d: %d             |  |
                            |  ", var_10#2, *(arg1#0 + (var_10#2 << 0x2)) )  |  |
                            |           var_10#3 = var_10#2 + 0x1            | -+
                            +------------------------------------------------+


                            +------------------------------------------------------------+
                            |                             0.                             |
                            |                  __x86.get_pc_thunk.bx()                   |
                            +------------------------------------------------------------+
                              |
                              |
                              v
    +-----------------+     +------------------------------------------------------------+
    |       3.        |     |                             1.                             |
    | return var_10#2 |     |                 var_10#2 = ϕ(0x0,var_10#3)                 |
    |                 | <-- |                   if(var_10#2 < arg2#0)                    | <+
    +-----------------+     +------------------------------------------------------------+  |
                              |                                                             |
                              |                                                             |
                              v                                                             |
                            +------------------------------------------------------------+  |
                            |                             2.                             |  |
                            |                      eax_1#3 = rand()                      |  |
                            | *(arg1#0 + (var_10#2 << 0x2)) array access = eax_1#3 + 0xa |  |
                            |                   printf("Element %d: %d                   |  |
                            |  ", var_10#2, *(arg1#0 + (var_10#2 << 0x2)) array access)  |  |
                            |                 var_10#3 = var_10#2 + 0x1                  | -+
                            +------------------------------------------------------------+


        function: fill_with_random_numbers in test_arrays
    """
    input_cfg, output_cfg = graphs_test1()
    run_array_access_detection(input_cfg)
    assert graphs_equal(input_cfg, output_cfg)


def test2():
    """

                           +-----------------------------------------------+
                           |                      0.                       |
                           |            __x86.get_pc_thunk.bx()            |
                           |        eax_2#3 = malloc(arg1#0 << 0x2)        |
                           +-----------------------------------------------+
                             |
                             |
                             v
    +----------------+     +-----------------------------------------------+
    |       3.       |     |                      1.                       |
    | return eax_2#3 |     |          var_10#2 = ϕ(0x0,var_10#3)           |
    |                | <-- |             if(var_10#2 < arg1#0)             | <+
    +----------------+     +-----------------------------------------------+  |
                             |                                                |
                             |                                                |
                             v                                                |
                           +-----------------------------------------------+  |
                           |                      2.                       |  |
                           |               eax_5#8 = rand()                |  |
                           |   *((var_10#2 << 0x2) + eax_2#3)  = eax_5#8   |  |
                           |            printf("Element %d: %d             |  |
                           | ", var_10#2, *(eax_2#3 + (var_10#2 << 0x2)) ) |  |
                           |           var_10#3 = var_10#2 + 0x1           | -+
                           +-----------------------------------------------+

                           +-----------------------------------------------------------+
                           |                            0.                             |
                           |                  __x86.get_pc_thunk.bx()                  |
                           |              eax_2#3 = malloc(arg1#0 << 0x2)              |
                           +-----------------------------------------------------------+
                             |
                             |
                             v
    +----------------+     +-----------------------------------------------------------+
    |       3.       |     |                            1.                             |
    | return eax_2#3 |     |                var_10#2 = ϕ(0x0,var_10#3)                 |
    |                | <-- |                   if(var_10#2 < arg1#0)                   | <+
    +----------------+     +-----------------------------------------------------------+  |
                             |                                                            |
                             |                                                            |
                             v                                                            |
                           +-----------------------------------------------------------+  |
                           |                            2.                             |  |
                           |                     eax_5#8 = rand()                      |  |
                           |   *((var_10#2 << 0x2) + eax_2#3) array access = eax_5#8   |  |
                           |                  printf("Element %d: %d                   |  |
                           | ", var_10#2, *(eax_2#3 + (var_10#2 << 0x2)) array access) |  |
                           |                 var_10#3 = var_10#2 + 0x1                 | -+
                           +-----------------------------------------------------------+

        function generate_random_numbers in test_arrays
    """
    input_cfg, output_cfg = graphs_test2()
    run_array_access_detection(input_cfg)
    assert graphs_equal(input_cfg, output_cfg)


def test3():
    """
    +--------------------------+     +--------------------------------------------------------+
    |                          |     |                           0.                           |
    |            2.            |     |                __x86.get_pc_thunk.bx()                 |
    | eax_2#4 = strlen(arg1#0) |     |                 eax#1 = strlen(arg1#0)                 |
    |                          |     |                eax_1#2 = strlen(arg2#0)                |
    |                          | <-- |                 if(eax#1 u>= eax_1#2)                  |
    +--------------------------+     +--------------------------------------------------------+
      |                                |
      |                                |
      |                                v
      |                              +--------------------------------------------------------+
      |                              |                           1.                           |
      |                              |                eax_2#3 = strlen(arg2#0)                |
      |                              +--------------------------------------------------------+
      |                                |
      |                                |
      |                                v
      |                              +--------------------------------------------------------+
      |                              |                           3.                           |
      +----------------------------> |              eax_2#5 = ϕ(eax_2#3,eax_2#4)              |
                                     +--------------------------------------------------------+
                                       |
                                       |
                                       v
    +--------------------------+     +--------------------------------------------------------+
    |            6.            |     |                           4.                           |
    |     return var_10#2      |     |               var_10#2 = ϕ(0x0,var_10#3)               |
    |                          | <-- |                 if(var_10#2 < eax_2#5)                 | <+
    +--------------------------+     +--------------------------------------------------------+  |
                                       |                                                         |
                                       |                                                         |
                                       v                                                         |
    +--------------------------+     +--------------------------------------------------------+  |
    |            8.            |     |                           5.                           |  |
    | printf(0x1394, var_10#2) | <-- | if((*(arg1#0 + var_10#2) ) == (*(arg2#0 + var_10#2) )) |  |
    +--------------------------+     +--------------------------------------------------------+  |
      |                                |                                                         |
      |                                |                                                         |
      |                                v                                                         |
      |                              +--------------------------------------------------------+  |
      |                              |                           7.                           |  |
      |                              +--------------------------------------------------------+  |
      |                                |                                                         |
      |                                |                                                         |
      |                                v                                                         |
      |                              +--------------------------------------------------------+  |
      |                              |                           9.                           |  |
      +----------------------------> |               var_10#3 = var_10#2 + 0x1                | -+
                                     +--------------------------------------------------------+


    +--------------------------+     +--------------------------------------------------------------------------------+
    |                          |     |                                       0.                                       |
    |            2.            |     |                            __x86.get_pc_thunk.bx()                             |
    | eax_2#4 = strlen(arg1#0) |     |                             eax#1 = strlen(arg1#0)                             |
    |                          |     |                            eax_1#2 = strlen(arg2#0)                            |
    |                          | <-- |                             if(eax#1 u>= eax_1#2)                              |
    +--------------------------+     +--------------------------------------------------------------------------------+
      |                                |
      |                                |
      |                                v
      |                              +--------------------------------------------------------------------------------+
      |                              |                                       1.                                       |
      |                              |                            eax_2#3 = strlen(arg2#0)                            |
      |                              +--------------------------------------------------------------------------------+
      |                                |
      |                                |
      |                                v
      |                              +--------------------------------------------------------------------------------+
      |                              |                                       3.                                       |
      +----------------------------> |                          eax_2#5 = ϕ(eax_2#3,eax_2#4)                          |
                                     +--------------------------------------------------------------------------------+
                                       |
                                       |
                                       v
    +--------------------------+     +--------------------------------------------------------------------------------+
    |            6.            |     |                                       4.                                       |
    |     return var_10#2      |     |                           var_10#2 = ϕ(0x0,var_10#3)                           |
    |                          | <-- |                             if(var_10#2 < eax_2#5)                             | <+
    +--------------------------+     +--------------------------------------------------------------------------------+  |
                                       |                                                                                 |
                                       |                                                                                 |
                                       v                                                                                 |
    +--------------------------+     +--------------------------------------------------------------------------------+  |
    |            8.            |     |                                       5.                                       |  |
    | printf(0x1394, var_10#2) | <-- | if((*(arg1#0 + var_10#2) array access) == (*(arg2#0 + var_10#2) array access)) |  |
    +--------------------------+     +--------------------------------------------------------------------------------+  |
      |                                |                                                                                 |
      |                                |                                                                                 |
      |                                v                                                                                 |
      |                              +--------------------------------------------------------------------------------+  |
      |                              |                                       7.                                       |  |
      |                              +--------------------------------------------------------------------------------+  |
      |                                |                                                                                 |
      |                                |                                                                                 |
      |                                v                                                                                 |
      |                              +--------------------------------------------------------------------------------+  |
      |                              |                                       9.                                       |  |
      +----------------------------> |                           var_10#3 = var_10#2 + 0x1                            | -+
                                     +--------------------------------------------------------------------------------+


        function print_diff in test_arrays
    """
    input_cfg, output_cfg = graphs_test3()
    run_array_access_detection(input_cfg)
    assert graphs_equal(input_cfg, output_cfg)


def test4():
    """
    +------------------------------------------+
    |                    0.                    |
    |         __x86.get_pc_thunk.ax()          |
    | eax#1 = printf(0x1390, *(arg1#0 + 0x4) ) |
    |               return eax#1               |
    +------------------------------------------+

    +------------------------------------------+
    |                    0.                    |
    |         __x86.get_pc_thunk.ax()          |
    | eax#1 = printf(0x1390, *(arg1#0 + 0x4) ) |<--- not an array access, as print_fourth_char(test5) produces same operation
    |               return eax#1               |
    +------------------------------------------+
       function print_second_int in test_arrays
       we don't know given constant offset only if it is a char or int or ... array
    """
    input_cfg, output_cfg = graphs_test4()
    run_array_access_detection(input_cfg)
    assert graphs_equal(input_cfg, output_cfg)


def test5():
    """
    +------------------------------------------------+
    |                       0.                       |
    |            __x86.get_pc_thunk.ax()             |
    | eax#1 = printf(0x1394, (int) *(arg1#0 + 0x4) ) |
    |                  return eax#1                  |
    +------------------------------------------------+

    +------------------------------------------------+
    |                       0.                       |
    |            __x86.get_pc_thunk.ax()             |
    | eax#1 = printf(0x1394, (int) *(arg1#0 + 0x4) ) |<--- not an array access, as print_fourth_char(test4) produces same operation
    |                  return eax#1                  |
    +------------------------------------------------+

        function print_fourth_char in test_arrays
       we don't know given constant offset only if it is a char or int or ... array
    """
    input_cfg, output_cfg = graphs_test5()
    run_array_access_detection(input_cfg)
    assert graphs_equal(input_cfg, output_cfg)


def test6():
    """
    +---------------------------+
    |            0.             |
    |  __x86.get_pc_thunk.bx()  |
    |     printf("Char %c:      |
    |   ", (int) *(arg1#0) )    |<---  char int struct field, not recognized as array access
    | eax_5#6 = printf("Int %d: |
    |   ", *(arg1#0 + 0x4) )    |<--- char int struct field, not recognized as array access
    |      return eax_5#6       |
    +---------------------------+
        function print_char_int_struct_by_pointer
    """
    # print_char_int_struct_by_pointer
    input_cfg, output_cfg = graphs_test6()
    run_array_access_detection(input_cfg)
    assert graphs_equal(input_cfg, output_cfg)


def test7():
    """
    +---------------------------+
    |            0.             |
    |  __x86.get_pc_thunk.bx()  |
    |     printf("Char %c:      |
    |   ", (int) *(arg1#0) )    |<---  packed char int struct field, not recognized as array access
    | eax_5#6 = printf("Int %d: |
    |   ", *(arg1#0 + 0x1) )    |<---  packed char int struct field, not recognized as array access
    |      return eax_5#6       |
    +---------------------------+
        function print_packed_char_int_struct_by_pointer in test_arrays
    """
    input_cfg, output_cfg = graphs_test7()
    run_array_access_detection(input_cfg)
    assert graphs_equal(input_cfg, output_cfg)


def test8():
    """

                            +-------------------------------------------+
                            |                    0.                     |
                            |          __x86.get_pc_thunk.bx()          |
                            |  printf(0x1394, (int) *(arg1#0 + 0x1) )   |
                            |  printf(0x1394, (int) *(arg1#0 + 0x2) )   |
                            +-------------------------------------------+
                              |
                              |
                              v
    +-----------------+     +-------------------------------------------+
    |       3.        |     |                    1.                     |
    | return var_10#2 |     |        var_10#2 = ϕ(0x0,var_10#3)         |
    |                 | <-- |           if(var_10#2 < arg2#0)           | <+
    +-----------------+     +-------------------------------------------+  |
                              |                                            |
                              |                                            |
                              v                                            |
                            +-------------------------------------------+  |
                            |                    2.                     |  |
                            |             eax_8#11 = rand()             |  |
                            | *(arg1#0 + var_10#2)  = (void *) eax_8#11 |  |
                            |         var_10#3 = var_10#2 + 0x1         | -+
                            +-------------------------------------------+


                            +-------------------------------------------------------+
                            |                          0.                           |
                            |                __x86.get_pc_thunk.bx()                |
                            |  printf(0x1394, (int) *(arg1#0 + 0x1) array access)   |<----we recognize them, cause there is another array access
                            |  printf(0x1394, (int) *(arg1#0 + 0x2) array access)   |<----(not constant) and offset % array_type_size (char) == 0
                            +-------------------------------------------------------+
                              |
                              |
                              v
    +-----------------+     +-------------------------------------------------------+
    |       3.        |     |                          1.                           |
    | return var_10#2 |     |              var_10#2 = ϕ(0x0,var_10#3)               |
    |                 | <-- |                 if(var_10#2 < arg2#0)                 | <+
    +-----------------+     +-------------------------------------------------------+  |
                              |                                                        |
                              |                                                        |
                              v                                                        |
                            +-------------------------------------------------------+  |
                            |                          2.                           |  |
                            |                   eax_8#11 = rand()                   |  |
                            | *(arg1#0 + var_10#2) array access = (void *) eax_8#11 |  |<---- char array access
                            |               var_10#3 = var_10#2 + 0x1               | -+
                            +-------------------------------------------------------+

        function mix_of_accesses_arg_char_array in test_arrays
    """
    input_cfg, output_cfg = graphs_test8()
    run_array_access_detection(input_cfg)
    assert graphs_equal(input_cfg, output_cfg)


def graphs_test1():
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    )
                ],
            ),
            BasicBlock(
                1,
                [
                    Phi(
                        Variable("var_10", Integer(32, True), 2, False),
                        [Constant(0, Integer(32, True)), Variable("var_10", Integer(32, True), 3, False)],
                    ),
                    Branch(
                        Condition(
                            OperationType.less,
                            [Variable("var_10", Integer(32, True), 2, False), Variable("arg2", Integer(32, True), 0, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        ListOperation([Variable("eax_1", Integer(32, True), 3, False)]),
                        Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 3),
                    ),
                    Assignment(
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                BinaryOperation(
                                    OperationType.plus,
                                    [
                                        base1 := Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                        BinaryOperation(
                                            OperationType.left_shift,
                                            [index1 := Variable("var_10", Integer(32, True), 2, False), Constant(2, Integer(8, True))],
                                            Integer(32, True),
                                        ),
                                    ],
                                    Pointer(CustomType("void", 0), 32),
                                )
                            ],
                            Pointer(Integer(32, True), 32),
                            4,
                            False,
                        ),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("eax_1", Integer(32, True), 3, False), Constant(10, Integer(32, True))],
                            Pointer(Integer(32, True), 32),
                        ),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant("Element %d: %d\n", Pointer(Integer(8, False), 32)),
                                Variable("var_10", Integer(32, True), 2, False),
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                base2 := Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                BinaryOperation(
                                                    OperationType.left_shift,
                                                    [
                                                        index2 := Variable("var_10", Integer(32, True), 2, False),
                                                        Constant(2, Integer(8, True)),
                                                    ],
                                                    Integer(32, True),
                                                ),
                                            ],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            5,
                        ),
                    ),
                    Assignment(
                        Variable("var_10", Integer(32, True), 3, False),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("var_10", Integer(32, True), 2, False), Constant(1, Integer(32, True))],
                            Integer(32, True),
                        ),
                    ),
                ],
            ),
            BasicBlock(3, [Return(ListOperation([Variable("var_10", Integer(32, True), 2, False)]))]),
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

    out_cfg = ControlFlowGraph()
    out_cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    )
                ],
            ),
            BasicBlock(
                1,
                [
                    Phi(
                        Variable("var_10", Integer(32, True), 2, False),
                        [Constant(0, Integer(32, True)), Variable("var_10", Integer(32, True), 3, False)],
                    ),
                    Branch(
                        Condition(
                            OperationType.less,
                            [Variable("var_10", Integer(32, True), 2, False), Variable("arg2", Integer(32, True), 0, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        ListOperation([Variable("eax_1", Integer(32, True), 3, False)]),
                        Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 3),
                    ),
                    Assignment(
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                BinaryOperation(
                                    OperationType.plus,
                                    [
                                        Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                        BinaryOperation(
                                            OperationType.left_shift,
                                            [Variable("var_10", Integer(32, True), 2, False), Constant(2, Integer(8, True))],
                                            Integer(32, True),
                                        ),
                                    ],
                                    Pointer(CustomType("void", 0), 32),
                                )
                            ],
                            Pointer(Integer(32, True), 32),
                            4,
                            False,
                            array_info=ArrayInfo(base1, index1, False),
                        ),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("eax_1", Integer(32, True), 3, False), Constant(10, Integer(32, True))],
                            Pointer(Integer(32, True), 32),
                        ),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant("Element %d: %d\n", Pointer(Integer(8, False), 32)),
                                Variable("var_10", Integer(32, True), 2, False),
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                BinaryOperation(
                                                    OperationType.left_shift,
                                                    [Variable("var_10", Integer(32, True), 2, False), Constant(2, Integer(8, True))],
                                                    Integer(32, True),
                                                ),
                                            ],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                    array_info=ArrayInfo(base2, index2, False),
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            5,
                        ),
                    ),
                    Assignment(
                        Variable("var_10", Integer(32, True), 3, False),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("var_10", Integer(32, True), 2, False), Constant(1, Integer(32, True))],
                            Integer(32, True),
                        ),
                    ),
                ],
            ),
            BasicBlock(3, [Return(ListOperation([Variable("var_10", Integer(32, True), 2, False)]))]),
        ]
    )
    out_cfg.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[1]),
        ]
    )
    return cfg, out_cfg


def graphs_test2():
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([Variable("eax_2", Pointer(CustomType("void", 0), 32), 3, False)]),
                        Call(
                            imp_function_symbol("malloc"),
                            [
                                BinaryOperation(
                                    OperationType.left_shift,
                                    [Variable("arg1", Integer(32, True), 0, False), Constant(2, Integer(32, True))],
                                    Integer(32, True),
                                )
                            ],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                ],
            ),
            BasicBlock(
                1,
                [
                    Phi(
                        Variable("var_10", Integer(32, True), 2, False),
                        [Constant(0, Integer(32, True)), Variable("var_10", Integer(32, True), 3, False)],
                    ),
                    Branch(
                        Condition(
                            OperationType.less,
                            [Variable("var_10", Integer(32, True), 2, False), Variable("arg1", Integer(32, True), 0, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        ListOperation([Variable("eax_5", Pointer(Integer(32, True), 32), 8, False)]),
                        Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 4),
                    ),
                    Assignment(
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                BinaryOperation(
                                    OperationType.plus,
                                    [
                                        BinaryOperation(
                                            OperationType.left_shift,
                                            [index1 := Variable("var_10", Integer(32, True), 2, False), Constant(2, Integer(8, True))],
                                            Integer(32, True),
                                        ),
                                        base1 := Variable("eax_2", Pointer(CustomType("void", 0), 32), 3, False),
                                    ],
                                    Pointer(CustomType("void", 0), 32),
                                )
                            ],
                            Pointer(Integer(32, True), 32),
                            5,
                            False,
                        ),
                        Variable("eax_5", Pointer(Integer(32, True), 32), 8, False),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant("Element %d: %d\n", Pointer(Integer(8, False), 32)),
                                Variable("var_10", Integer(32, True), 2, False),
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                base2 := Variable("eax_2", Pointer(CustomType("void", 0), 32), 3, False),
                                                BinaryOperation(
                                                    OperationType.left_shift,
                                                    [
                                                        index2 := Variable("var_10", Integer(32, True), 2, False),
                                                        Constant(2, Integer(8, True)),
                                                    ],
                                                    Integer(32, True),
                                                ),
                                            ],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            6,
                        ),
                    ),
                    Assignment(
                        Variable("var_10", Integer(32, True), 3, False),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("var_10", Integer(32, True), 2, False), Constant(1, Integer(32, True))],
                            Integer(32, True),
                        ),
                    ),
                ],
            ),
            BasicBlock(3, [Return(ListOperation([Variable("eax_2", Pointer(CustomType("void", 0), 32), 3, False)]))]),
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

    out_cfg = ControlFlowGraph()
    out_cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([Variable("eax_2", Pointer(CustomType("void", 0), 32), 3, False)]),
                        Call(
                            imp_function_symbol("malloc"),
                            [
                                BinaryOperation(
                                    OperationType.left_shift,
                                    [Variable("arg1", Integer(32, True), 0, False), Constant(2, Integer(32, True))],
                                    Integer(32, True),
                                )
                            ],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                ],
            ),
            BasicBlock(
                1,
                [
                    Phi(
                        Variable("var_10", Integer(32, True), 2, False),
                        [Constant(0, Integer(32, True)), Variable("var_10", Integer(32, True), 3, False)],
                    ),
                    Branch(
                        Condition(
                            OperationType.less,
                            [Variable("var_10", Integer(32, True), 2, False), Variable("arg1", Integer(32, True), 0, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        ListOperation([Variable("eax_5", Pointer(Integer(32, True), 32), 8, False)]),
                        Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 4),
                    ),
                    Assignment(
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                BinaryOperation(
                                    OperationType.plus,
                                    [
                                        BinaryOperation(
                                            OperationType.left_shift,
                                            [Variable("var_10", Integer(32, True), 2, False), Constant(2, Integer(8, True))],
                                            Integer(32, True),
                                        ),
                                        Variable("eax_2", Pointer(CustomType("void", 0), 32), 3, False),
                                    ],
                                    Pointer(CustomType("void", 0), 32),
                                )
                            ],
                            Pointer(Integer(32, True), 32),
                            5,
                            False,
                            array_info=ArrayInfo(base1, index1, False),
                        ),
                        Variable("eax_5", Pointer(Integer(32, True), 32), 8, False),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant("Element %d: %d\n", Pointer(Integer(8, False), 32)),
                                Variable("var_10", Integer(32, True), 2, False),
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                Variable("eax_2", Pointer(CustomType("void", 0), 32), 3, False),
                                                BinaryOperation(
                                                    OperationType.left_shift,
                                                    [Variable("var_10", Integer(32, True), 2, False), Constant(2, Integer(8, True))],
                                                    Integer(32, True),
                                                ),
                                            ],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                    array_info=ArrayInfo(base2, index2, False),
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            6,
                        ),
                    ),
                    Assignment(
                        Variable("var_10", Integer(32, True), 3, False),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("var_10", Integer(32, True), 2, False), Constant(1, Integer(32, True))],
                            Integer(32, True),
                        ),
                    ),
                ],
            ),
            BasicBlock(3, [Return(ListOperation([Variable("eax_2", Pointer(CustomType("void", 0), 32), 3, False)]))]),
        ]
    )
    out_cfg.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[1]),
        ]
    )
    return cfg, out_cfg


def graphs_test3():
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([Variable("eax", Integer(32, True), 1, False)]),
                        Call(
                            imp_function_symbol("strlen"),
                            [Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False)],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Assignment(
                        ListOperation([Variable("eax_1", Integer(32, True), 2, False)]),
                        Call(
                            imp_function_symbol("strlen"),
                            [Variable("arg2", Pointer(CustomType("void", 0), 32), 0, False)],
                            Pointer(CustomType("void", 0), 32),
                            3,
                        ),
                    ),
                    Branch(
                        Condition(
                            OperationType.greater_or_equal_us,
                            [Variable("eax", Integer(32, True), 1, False), Variable("eax_1", Integer(32, True), 2, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                1,
                [
                    Assignment(
                        ListOperation([Variable("eax_2", Integer(32, True), 3, False)]),
                        Call(
                            imp_function_symbol("strlen"),
                            [Variable("arg2", Pointer(CustomType("void", 0), 32), 0, False)],
                            Pointer(CustomType("void", 0), 32),
                            4,
                        ),
                    )
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        ListOperation([Variable("eax_2", Integer(32, True), 4, False)]),
                        Call(
                            imp_function_symbol("strlen"),
                            [Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False)],
                            Pointer(CustomType("void", 0), 32),
                            5,
                        ),
                    )
                ],
            ),
            BasicBlock(
                3,
                [
                    Phi(
                        Variable("eax_2", Integer(32, True), 5, False),
                        [Variable("eax_2", Integer(32, True), 3, False), Variable("eax_2", Integer(32, True), 4, False)],
                    )
                ],
            ),
            BasicBlock(
                4,
                [
                    Phi(
                        Variable("var_10", Integer(32, True), 2, False),
                        [Constant(0, Integer(32, True)), Variable("var_10", Integer(32, True), 3, False)],
                    ),
                    Branch(
                        Condition(
                            OperationType.less,
                            [Variable("var_10", Integer(32, True), 2, False), Variable("eax_2", Integer(32, True), 5, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                5,
                [
                    Branch(
                        Condition(
                            OperationType.equal,
                            [
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                base1 := Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                index1 := Variable("var_10", Integer(32, True), 2, False),
                                            ],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(8, True),
                                    None,
                                    False,
                                ),
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                base2 := Variable("arg2", Pointer(CustomType("void", 0), 32), 0, False),
                                                index2 := Variable("var_10", Integer(32, True), 2, False),
                                            ],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(8, True),
                                    None,
                                    False,
                                ),
                            ],
                            CustomType("bool", 1),
                        )
                    )
                ],
            ),
            BasicBlock(6, [Return(ListOperation([Variable("var_10", Integer(32, True), 2, False)]))]),
            BasicBlock(7, []),
            BasicBlock(
                8,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [Constant(5012, Pointer(CustomType("void", 0), 32)), Variable("var_10", Integer(32, True), 2, False)],
                            Pointer(CustomType("void", 0), 32),
                            8,
                        ),
                    )
                ],
            ),
            BasicBlock(
                9,
                [
                    Assignment(
                        Variable("var_10", Integer(32, True), 3, False),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("var_10", Integer(32, True), 2, False), Constant(1, Integer(32, True))],
                            Integer(32, True),
                        ),
                    )
                ],
            ),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[3]),
            UnconditionalEdge(vertices[3], vertices[4]),
            TrueCase(vertices[4], vertices[5]),
            FalseCase(vertices[4], vertices[6]),
            TrueCase(vertices[5], vertices[7]),
            FalseCase(vertices[5], vertices[8]),
            UnconditionalEdge(vertices[7], vertices[9]),
            UnconditionalEdge(vertices[8], vertices[9]),
            UnconditionalEdge(vertices[9], vertices[4]),
        ]
    )

    out_cfg = ControlFlowGraph()
    out_cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([Variable("eax", Integer(32, True), 1, False)]),
                        Call(
                            imp_function_symbol("strlen"),
                            [Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False)],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Assignment(
                        ListOperation([Variable("eax_1", Integer(32, True), 2, False)]),
                        Call(
                            imp_function_symbol("strlen"),
                            [Variable("arg2", Pointer(CustomType("void", 0), 32), 0, False)],
                            Pointer(CustomType("void", 0), 32),
                            3,
                        ),
                    ),
                    Branch(
                        Condition(
                            OperationType.greater_or_equal_us,
                            [Variable("eax", Integer(32, True), 1, False), Variable("eax_1", Integer(32, True), 2, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                1,
                [
                    Assignment(
                        ListOperation([Variable("eax_2", Integer(32, True), 3, False)]),
                        Call(
                            imp_function_symbol("strlen"),
                            [Variable("arg2", Pointer(CustomType("void", 0), 32), 0, False)],
                            Pointer(CustomType("void", 0), 32),
                            4,
                        ),
                    )
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        ListOperation([Variable("eax_2", Integer(32, True), 4, False)]),
                        Call(
                            imp_function_symbol("strlen"),
                            [Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False)],
                            Pointer(CustomType("void", 0), 32),
                            5,
                        ),
                    )
                ],
            ),
            BasicBlock(
                3,
                [
                    Phi(
                        Variable("eax_2", Integer(32, True), 5, False),
                        [Variable("eax_2", Integer(32, True), 3, False), Variable("eax_2", Integer(32, True), 4, False)],
                    )
                ],
            ),
            BasicBlock(
                4,
                [
                    Phi(
                        Variable("var_10", Integer(32, True), 2, False),
                        [Constant(0, Integer(32, True)), Variable("var_10", Integer(32, True), 3, False)],
                    ),
                    Branch(
                        Condition(
                            OperationType.less,
                            [Variable("var_10", Integer(32, True), 2, False), Variable("eax_2", Integer(32, True), 5, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                5,
                [
                    Branch(
                        Condition(
                            OperationType.equal,
                            [
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                Variable("var_10", Integer(32, True), 2, False),
                                            ],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(8, True),
                                    None,
                                    False,
                                    array_info=ArrayInfo(base1, index1, False),
                                ),
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                Variable("arg2", Pointer(CustomType("void", 0), 32), 0, False),
                                                Variable("var_10", Integer(32, True), 2, False),
                                            ],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(8, True),
                                    None,
                                    False,
                                    array_info=ArrayInfo(base2, index2, False),
                                ),
                            ],
                            CustomType("bool", 1),
                        )
                    )
                ],
            ),
            BasicBlock(6, [Return(ListOperation([Variable("var_10", Integer(32, True), 2, False)]))]),
            BasicBlock(7, []),
            BasicBlock(
                8,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [Constant(5012, Pointer(CustomType("void", 0), 32)), Variable("var_10", Integer(32, True), 2, False)],
                            Pointer(CustomType("void", 0), 32),
                            8,
                        ),
                    )
                ],
            ),
            BasicBlock(
                9,
                [
                    Assignment(
                        Variable("var_10", Integer(32, True), 3, False),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("var_10", Integer(32, True), 2, False), Constant(1, Integer(32, True))],
                            Integer(32, True),
                        ),
                    )
                ],
            ),
        ]
    )
    out_cfg.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[3]),
            UnconditionalEdge(vertices[3], vertices[4]),
            TrueCase(vertices[4], vertices[5]),
            FalseCase(vertices[4], vertices[6]),
            TrueCase(vertices[5], vertices[7]),
            FalseCase(vertices[5], vertices[8]),
            UnconditionalEdge(vertices[7], vertices[9]),
            UnconditionalEdge(vertices[8], vertices[9]),
            UnconditionalEdge(vertices[9], vertices[4]),
        ]
    )
    return cfg, out_cfg


def graphs_test4():
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.ax"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([Variable("eax", Integer(32, True), 1, False)]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant(5008, Pointer(CustomType("void", 0), 32)),
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                Constant(4, Integer(32, True)),
                                            ],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Return(ListOperation([Variable("eax", Integer(32, True), 1, False)])),
                ],
            )
        ]
    )

    out_cfg = cfg.copy()
    return cfg, out_cfg


def graphs_test5():
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.ax"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([Variable("eax", Integer(32, True), 1, False)]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant(5012, Pointer(CustomType("void", 0), 32)),
                                UnaryOperation(
                                    OperationType.cast,
                                    [
                                        UnaryOperation(
                                            OperationType.dereference,
                                            [
                                                BinaryOperation(
                                                    OperationType.plus,
                                                    [
                                                        Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                        Constant(4, Integer(32, True)),
                                                    ],
                                                    Pointer(CustomType("void", 0), 32),
                                                )
                                            ],
                                            Integer(8, True),
                                            None,
                                            False,
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Return(ListOperation([Variable("eax", Integer(32, True), 1, False)])),
                ],
            )
        ]
    )
    out_cfg = cfg.copy()
    return cfg, out_cfg


def graphs_test6():
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant("Char %c:\n", Pointer(Integer(8, False), 32)),
                                UnaryOperation(
                                    OperationType.cast,
                                    [
                                        UnaryOperation(
                                            OperationType.dereference,
                                            [Variable("arg1", Pointer(Integer(8, True), 32), 0, False)],
                                            Integer(8, True),
                                            None,
                                            False,
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Assignment(
                        ListOperation([Variable("eax_5", Integer(32, True), 6, False)]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant("Int %d:\n", Pointer(Integer(8, False), 32)),
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [Variable("arg1", Pointer(Integer(8, True), 32), 0, False), Constant(4, Integer(32, True))],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            3,
                        ),
                    ),
                    Return(ListOperation([Variable("eax_5", Integer(32, True), 6, False)])),
                ],
            )
        ]
    )
    out_cfg = cfg.copy()
    return cfg, out_cfg


def graphs_test7():
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant("Char %c:\n", Pointer(Integer(8, False), 32)),
                                UnaryOperation(
                                    OperationType.cast,
                                    [
                                        UnaryOperation(
                                            OperationType.dereference,
                                            [Variable("arg1", Pointer(Integer(8, True), 32), 0, False)],
                                            Integer(8, True),
                                            None,
                                            False,
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Assignment(
                        ListOperation([Variable("eax_5", Integer(32, True), 6, False)]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant("Int %d:\n", Pointer(Integer(8, False), 32)),
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [Variable("arg1", Pointer(Integer(8, True), 32), 0, False), Constant(1, Integer(32, True))],
                                            Pointer(CustomType("void", 0), 32),
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            3,
                        ),
                    ),
                    Return(ListOperation([Variable("eax_5", Integer(32, True), 6, False)])),
                ],
            )
        ]
    )
    out_cfg = cfg.copy()
    return cfg, out_cfg


def graphs_test8():
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant(5012, Pointer(CustomType("void", 0), 32)),
                                UnaryOperation(
                                    OperationType.cast,
                                    [
                                        UnaryOperation(
                                            OperationType.dereference,
                                            [
                                                BinaryOperation(
                                                    OperationType.plus,
                                                    [
                                                        base1 := Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                        Constant(1, Integer(32, True)),
                                                    ],
                                                    Pointer(CustomType("void", 0), 32),
                                                )
                                            ],
                                            Integer(8, True),
                                            None,
                                            False,
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant(5012, Pointer(CustomType("void", 0), 32)),
                                UnaryOperation(
                                    OperationType.cast,
                                    [
                                        UnaryOperation(
                                            OperationType.dereference,
                                            [
                                                BinaryOperation(
                                                    OperationType.plus,
                                                    [
                                                        base2 := Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                        Constant(2, Integer(32, True)),
                                                    ],
                                                    Pointer(CustomType("void", 0), 32),
                                                )
                                            ],
                                            Integer(8, True),
                                            None,
                                            False,
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            3,
                        ),
                    ),
                ],
            ),
            BasicBlock(
                1,
                [
                    Phi(
                        Variable("var_10", Integer(32, True), 2, False),
                        [Constant(0, Integer(32, True)), Variable("var_10", Integer(32, True), 3, False)],
                    ),
                    Branch(
                        Condition(
                            OperationType.less,
                            [Variable("var_10", Integer(32, True), 2, False), Variable("arg2", Integer(32, True), 0, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        ListOperation([Variable("eax_8", Integer(32, True), 11, False)]),
                        Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 5),
                    ),
                    Assignment(
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                BinaryOperation(
                                    OperationType.plus,
                                    [
                                        base3 := Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                        index3 := Variable("var_10", Integer(32, True), 2, False),
                                    ],
                                    Pointer(CustomType("void", 0), 32),
                                )
                            ],
                            Pointer(CustomType("void", 0), 32),
                            6,
                            False,
                        ),
                        UnaryOperation(
                            OperationType.cast,
                            [Variable("eax_8", Integer(32, True), 11, False)],
                            Pointer(CustomType("void", 0), 32),
                            None,
                            False,
                        ),
                    ),
                    Assignment(
                        Variable("var_10", Integer(32, True), 3, False),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("var_10", Integer(32, True), 2, False), Constant(1, Integer(32, True))],
                            Integer(32, True),
                        ),
                    ),
                ],
            ),
            BasicBlock(3, [Return(ListOperation([Variable("var_10", Integer(32, True), 2, False)]))]),
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
    out_cfg = ControlFlowGraph()
    out_cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant(5012, Pointer(CustomType("void", 0), 32)),
                                UnaryOperation(
                                    OperationType.cast,
                                    [
                                        UnaryOperation(
                                            OperationType.dereference,
                                            [
                                                BinaryOperation(
                                                    OperationType.plus,
                                                    [
                                                        Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                        Constant(1, Integer(32, True)),
                                                    ],
                                                    Pointer(CustomType("void", 0), 32),
                                                )
                                            ],
                                            Integer(8, True),
                                            None,
                                            False,
                                            array_info=ArrayInfo(base1, 1, False),
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant(5012, Pointer(CustomType("void", 0), 32)),
                                UnaryOperation(
                                    OperationType.cast,
                                    [
                                        UnaryOperation(
                                            OperationType.dereference,
                                            [
                                                BinaryOperation(
                                                    OperationType.plus,
                                                    [
                                                        Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                                        Constant(2, Integer(32, True)),
                                                    ],
                                                    Pointer(CustomType("void", 0), 32),
                                                )
                                            ],
                                            Integer(8, True),
                                            None,
                                            False,
                                            array_info=ArrayInfo(base2, 2, False),
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            3,
                        ),
                    ),
                ],
            ),
            BasicBlock(
                1,
                [
                    Phi(
                        Variable("var_10", Integer(32, True), 2, False),
                        [Constant(0, Integer(32, True)), Variable("var_10", Integer(32, True), 3, False)],
                    ),
                    Branch(
                        Condition(
                            OperationType.less,
                            [Variable("var_10", Integer(32, True), 2, False), Variable("arg2", Integer(32, True), 0, False)],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        ListOperation([Variable("eax_8", Integer(32, True), 11, False)]),
                        Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 5),
                    ),
                    Assignment(
                        UnaryOperation(
                            OperationType.dereference,
                            [
                                BinaryOperation(
                                    OperationType.plus,
                                    [
                                        Variable("arg1", Pointer(CustomType("void", 0), 32), 0, False),
                                        Variable("var_10", Integer(32, True), 2, False),
                                    ],
                                    Pointer(CustomType("void", 0), 32),
                                )
                            ],
                            Pointer(CustomType("void", 0), 32),
                            6,
                            False,
                            array_info=ArrayInfo(base3, index3, False),
                        ),
                        UnaryOperation(
                            OperationType.cast,
                            [Variable("eax_8", Integer(32, True), 11, False)],
                            Pointer(CustomType("void", 0), 32),
                            None,
                            False,
                        ),
                    ),
                    Assignment(
                        Variable("var_10", Integer(32, True), 3, False),
                        BinaryOperation(
                            OperationType.plus,
                            [Variable("var_10", Integer(32, True), 2, False), Constant(1, Integer(32, True))],
                            Integer(32, True),
                        ),
                    ),
                ],
            ),
            BasicBlock(3, [Return(ListOperation([Variable("var_10", Integer(32, True), 2, False)]))]),
        ]
    )
    out_cfg.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[1]),
        ]
    )
    return cfg, out_cfg
