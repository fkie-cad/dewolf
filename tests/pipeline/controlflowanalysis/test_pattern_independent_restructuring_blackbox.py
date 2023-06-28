""" Tests for the PatternIndependentRestructuring pipeline stage"""

import pytest
from decompiler.pipeline.controlflowanalysis.restructuring import PatternIndependentRestructuring
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType
from decompiler.structures.pseudo.typing import CustomType, Integer
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedCFG


@pytest.fixture
def task() -> DecompilerTask:
    """A mock task with an empty cfg."""
    return DecompilerTask("test", ControlFlowGraph())

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
    task._cfg.add_nodes_from(
        [
            b0 := BasicBlock(
                0,
                [
                    Branch(
                        Condition(
                            OperationType.less_or_equal,
                            [
                                var_2,
                                Constant(0x2, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            b1 := BasicBlock(
                1,
                [
                    Assignment(var_3, Constant(-0x3, Integer(32, True))),
                ]
            ),
            b3 := BasicBlock(
                3,
                [
                    Branch(
                        Condition(
                            OperationType.equal,
                            [
                                var_5,
                                Constant(0x2, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            b4 := BasicBlock(
                4,
                [
                    Return([Constant(0xffffffff, Integer(32, True))])
                    ],
            ),
            b5 := BasicBlock(
                5,
                [
                    Assignment(
                        var_6,
                        BinaryOperation(
                            OperationType.plus,
                            [
                                var_5, Constant(-0x3, Integer(32, True))
                            ]
                        ),
                    ),
                    Branch(
                        Condition(
                            OperationType.greater_us,
                            [
                                var_5,
                                Constant(0x2, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            b7 := BasicBlock(
                7,
                [
                    Branch(
                        Condition(
                            OperationType.equal,
                            [
                                var_5,
                                Constant(0x0, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    )
                ],
            ),
            b10 := BasicBlock(
                10,
                [
                    Assignment(
                        var_6,
                        Constant(0x0, Integer(32, True))
                    )
                ],
            ),
            b11 := BasicBlock(
                11,
                [
                    Branch(
                        Condition(
                            OperationType.not_equal,
                            [
                                var_5,
                                Constant(0x1, Integer(32, True)),
                                ],
                            CustomType("bool", 1),
                            )
                        )
                    ]
            ),
            b15 := BasicBlock(
                15,
                [
                    Return([var_6])
                ],
            ),
           b17 := BasicBlock(
                17,
                [
                    Assignment(var_6, Constant(0x1, Integer(32, True)))
                ],
            ),
           b22 := BasicBlock(
                22,
                [
                    Return([
                        BinaryOperation(
                            OperationType.plus,
                            [
                                var_3, BinaryOperation(OperationType.plus, [var_4, var_5])
                            ]
                        )
                    ])
                ],
            ),
        ]
    )
    task._cfg.add_edges_from(
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
