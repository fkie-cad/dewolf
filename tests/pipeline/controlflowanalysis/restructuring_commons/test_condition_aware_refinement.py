""" Tests for the PatternIndependentRestructuring pipeline stage condition aware refinement."""

from itertools import combinations
from typing import List, Tuple, Union

import pytest
from decompiler.pipeline.controlflowanalysis.restructuring import PatternIndependentRestructuring
from decompiler.structures.ast.ast_nodes import CaseNode, CodeNode, ConditionNode, SeqNode, SwitchNode, WhileLoopNode
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, Expression, FunctionSymbol, ImportedFunctionSymbol, StringSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Break, Continue, IndirectBranch, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer, Type, UnknownType
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def imp_function_symbol(name: str, value: int = 0x42, vartype: Type = UnknownType()) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value, vartype)


class MockDecompilerTask(DecompilerTask):
    """Mock class for decompilerTasks only containing a cfg."""

    class MockFunction:
        class FunctionType:
            def __init__(self):
                self.return_value = "void"
                self.parameters = []

        def __init__(self):
            self.name = "test"
            self.function_type = self.FunctionType()

    def __init__(self, cfg):
        super().__init__("test", None)
        self._cfg = cfg
        self.set_options()
        self.function = self.MockFunction()

    def set_options(self):
        self.options = Options()
        self.options.set("pattern-independent-restructuring.switch_reconstruction", True)
        self.options.set("pattern-independent-restructuring.nested_switch_nodes", True)
        self.options.set("pattern-independent-restructuring.min_switch_case_number", 2)

    def reset(self):
        pass


@pytest.fixture
def task() -> ControlFlowGraph:
    """A mock task with an empty cfg."""
    return MockDecompilerTask(ControlFlowGraph())


def print_call(string: str, memory: int) -> Call:
    return Call(
        imp_function_symbol("printf"), [Constant(string, Pointer(Integer(8, False), 32))], Pointer(CustomType("void", 0), 32), memory
    )


def print_call64(function_const: int, const: int, memory: int) -> Call:
    return Call(
        FunctionSymbol("printf", function_const, Pointer(Integer(8, True), 32)),
        [Constant(const, Pointer(Integer(8, True), 32))],
        Pointer(CustomType("void", 0), 64),
        memory,
    )


def scanf_call(var_1: Expression, constant: Union[int, str], memory: int) -> Call:
    return Call(
        imp_function_symbol("__isoc99_scanf"),
        [Constant(constant, Integer(32, True)), var_1],
        Pointer(CustomType("void", 0), 32),
        memory,
    )


def scanf_call64(var_1: Variable, constant: Union[int, str], memory: int) -> Call:
    return Call(
        imp_function_symbol("__isoc99_scanf", 4199948, Pointer(Integer(8, True), 32)),
        [Constant(constant, Pointer(Integer(8, True), 32)), var_1],
        Pointer(CustomType("void", 0), 64),
        memory,
    )


def putchar_call(constant: int, memory: int) -> Call:
    return Call(imp_function_symbol("putchar"), [Constant(constant, Integer(32, True))], Pointer(CustomType("void", 0), 32), memory)


def printf_chk_call(string: Union[str, Variable], variable_1: Variable, variable_2: Variable, memory: int) -> Call:
    if isinstance(string, str):
        return Call(
            imp_function_symbol("__printf_chk"),
            [Constant(1, Integer(32, True)), Constant(string, Pointer(Integer(8, False), 32)), variable_1, variable_2],
            Pointer(CustomType("void", 0), 32),
            memory,
        )
    return Call(
        imp_function_symbol("__printf_chk"),
        [Constant(1, Integer(32, True)), string, variable_1, variable_2],
        Pointer(CustomType("void", 0), 32),
        memory,
    )


def _basic_switch_cfg(task) -> Tuple[Variable, List[BasicBlock]]:
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(7, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 10))]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("Monday", 3))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("Tuesday", 4))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Wednesday", 5))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Thursday", 6))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Friday", 7))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Saturday", 8))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Sunday", 9))]),
            BasicBlock(11, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(0, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[3], [Constant(1, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[4], [Constant(2, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[5], [Constant(3, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[6], [Constant(4, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[7], [Constant(5, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[8], [Constant(6, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[9], [Constant(7, Integer(32, signed=True))]),
            UnconditionalEdge(vertices[2], vertices[10]),
            UnconditionalEdge(vertices[3], vertices[10]),
            UnconditionalEdge(vertices[4], vertices[10]),
            UnconditionalEdge(vertices[5], vertices[10]),
            UnconditionalEdge(vertices[6], vertices[10]),
            UnconditionalEdge(vertices[7], vertices[10]),
            UnconditionalEdge(vertices[8], vertices[10]),
            UnconditionalEdge(vertices[9], vertices[10]),
        ]
    )
    return var_0, vertices


def _switch_empty_fallthrough(task) -> Tuple[Variable, List[BasicBlock]]:
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter month number(1-12): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(12, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter month number between 1-12", 6))]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("31 days", 3))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("30 days", 4))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("28/29 days", 5))]),
            BasicBlock(7, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(0, Integer(32, True))]),
            SwitchCase(vertices[1], vertices[3], [Constant(i, Integer(32, True)) for i in (1, 3, 5, 7, 8, 10, 12)]),
            SwitchCase(vertices[1], vertices[4], [Constant(i, Integer(32, True)) for i in (4, 6, 9, 11)]),
            SwitchCase(vertices[1], vertices[5], [Constant(2, Integer(32, True))]),
            UnconditionalEdge(vertices[2], vertices[6]),
            UnconditionalEdge(vertices[3], vertices[6]),
            UnconditionalEdge(vertices[4], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[6]),
        ]
    )
    return var_0, vertices


def _switch_no_empty_fallthrough(task) -> Tuple[Variable, List[BasicBlock]]:
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter a digit (0-9): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(9, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Assignment(ListOperation([]), print_call("Not a digit ", 3))]),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(4, [Assignment(ListOperation([]), putchar_call(48, 4))]),
            BasicBlock(5, [Assignment(ListOperation([]), putchar_call(49, 6))]),
            BasicBlock(6, [Assignment(ListOperation([]), putchar_call(50, 7))]),
            BasicBlock(7, [Assignment(ListOperation([]), putchar_call(51, 9))]),
            BasicBlock(8, [Assignment(ListOperation([]), putchar_call(52, 11))]),
            BasicBlock(9, [Assignment(ListOperation([]), putchar_call(53, 12))]),
            BasicBlock(10, [Assignment(ListOperation([]), putchar_call(54, 14))]),
            BasicBlock(11, [Assignment(ListOperation([]), putchar_call(55, 16))]),
            BasicBlock(12, [Assignment(ListOperation([]), putchar_call(56, 18))]),
            BasicBlock(13, [Assignment(ListOperation([]), putchar_call(57, 20))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            SwitchCase(vertices[2], vertices[4], [Constant(0, Integer(32))]),
            SwitchCase(vertices[2], vertices[5], [Constant(1, Integer(32))]),
            SwitchCase(vertices[2], vertices[6], [Constant(2, Integer(32))]),
            SwitchCase(vertices[2], vertices[7], [Constant(3, Integer(32))]),
            SwitchCase(vertices[2], vertices[8], [Constant(4, Integer(32))]),
            SwitchCase(vertices[2], vertices[9], [Constant(5, Integer(32))]),
            SwitchCase(vertices[2], vertices[10], [Constant(6, Integer(32))]),
            SwitchCase(vertices[2], vertices[11], [Constant(7, Integer(32))]),
            SwitchCase(vertices[2], vertices[12], [Constant(8, Integer(32))]),
            SwitchCase(vertices[2], vertices[13], [Constant(9, Integer(32))]),
            UnconditionalEdge(vertices[4], vertices[5]),
            UnconditionalEdge(vertices[5], vertices[3]),
            UnconditionalEdge(vertices[6], vertices[7]),
            UnconditionalEdge(vertices[7], vertices[8]),
            UnconditionalEdge(vertices[8], vertices[3]),
            UnconditionalEdge(vertices[9], vertices[10]),
            UnconditionalEdge(vertices[10], vertices[11]),
            UnconditionalEdge(vertices[11], vertices[12]),
            UnconditionalEdge(vertices[12], vertices[13]),
            UnconditionalEdge(vertices[13], vertices[3]),
        ]
    )
    return var_0, vertices


def _switch_in_switch(task) -> Tuple[Variable, Variable, List[BasicBlock]]:
    var_1 = Variable("var_1", Integer(32, True), None, True, Variable("var_14", Integer(32, True), 0, True, None))
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_2_1 = Variable(
        "var_2", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_2_2 = Variable(
        "var_2", Pointer(Integer(32, True), 32), None, False, Variable("var_28_1", Pointer(Integer(32, True), 32), 2, False, None)
    )
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_2_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_2_1, 134524965, 2)),
                    Assignment(ListOperation([]), print_call("Enter a time (1-4): ", 3)),
                    Assignment(var_2_2, UnaryOperation(OperationType.address, [var_1], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_2_2, 134524965, 4)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(7, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 22))]),
            BasicBlock(4, [Branch(Condition(OperationType.equal, [var_1, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("Tuesday", 11))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Wednesday", 12))]),
            BasicBlock(7, [Branch(Condition(OperationType.equal, [var_1, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Friday", 19))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Saturday", 20))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Sunday", 21))]),
            BasicBlock(11, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(12, [Assignment(ListOperation([]), print_call("Monday midnight", 5))]),
            BasicBlock(13, [Branch(Condition(OperationType.greater, [var_1, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(14, [Assignment(ListOperation([]), print_call("Thursday midnight", 13))]),
            BasicBlock(15, [Branch(Condition(OperationType.greater, [var_1, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(18, [Branch(Condition(OperationType.equal, [var_1, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(21, [Branch(Condition(OperationType.equal, [var_1, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(22, [Assignment(ListOperation([]), print_call("Monday", 9))]),
            BasicBlock(23, [Assignment(ListOperation([]), print_call("Monday evening", 6))]),
            BasicBlock(24, [Branch(Condition(OperationType.greater, [var_1, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(25, [Assignment(ListOperation([]), print_call("Thursday", 17))]),
            BasicBlock(26, [Assignment(ListOperation([]), print_call("Thursday evening", 14))]),
            BasicBlock(27, [Branch(Condition(OperationType.greater, [var_1, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(29, [Branch(Condition(OperationType.equal, [var_1, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(31, [Branch(Condition(OperationType.equal, [var_1, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(32, [Assignment(ListOperation([]), print_call("Monday morning", 7))]),
            BasicBlock(33, [Branch(Condition(OperationType.equal, [var_1, Constant(2, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(34, [Assignment(ListOperation([]), print_call("Thursday morning", 15))]),
            BasicBlock(35, [Branch(Condition(OperationType.equal, [var_1, Constant(2, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(36, [Assignment(ListOperation([]), print_call("Monday afternoon", 8))]),
            BasicBlock(38, [Assignment(ListOperation([]), print_call("Thursday afternoon", 16))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(0, Integer(32))]),
            SwitchCase(vertices[1], vertices[3], [Constant(1, Integer(32))]),
            SwitchCase(vertices[1], vertices[4], [Constant(2, Integer(32))]),
            SwitchCase(vertices[1], vertices[5], [Constant(3, Integer(32))]),
            SwitchCase(vertices[1], vertices[6], [Constant(4, Integer(32))]),
            SwitchCase(vertices[1], vertices[7], [Constant(5, Integer(32))]),
            SwitchCase(vertices[1], vertices[8], [Constant(6, Integer(32))]),
            SwitchCase(vertices[1], vertices[9], [Constant(7, Integer(32))]),
            UnconditionalEdge(vertices[2], vertices[10]),
            TrueCase(vertices[3], vertices[11]),
            FalseCase(vertices[3], vertices[12]),
            UnconditionalEdge(vertices[4], vertices[10]),
            UnconditionalEdge(vertices[5], vertices[10]),
            TrueCase(vertices[6], vertices[13]),
            FalseCase(vertices[6], vertices[14]),
            UnconditionalEdge(vertices[7], vertices[10]),
            UnconditionalEdge(vertices[8], vertices[10]),
            UnconditionalEdge(vertices[9], vertices[10]),
            UnconditionalEdge(vertices[11], vertices[10]),
            FalseCase(vertices[12], vertices[15]),
            TrueCase(vertices[12], vertices[17]),
            UnconditionalEdge(vertices[13], vertices[10]),
            FalseCase(vertices[14], vertices[16]),
            TrueCase(vertices[14], vertices[20]),
            TrueCase(vertices[15], vertices[18]),
            FalseCase(vertices[15], vertices[19]),
            TrueCase(vertices[16], vertices[21]),
            FalseCase(vertices[16], vertices[22]),
            UnconditionalEdge(vertices[17], vertices[10]),
            UnconditionalEdge(vertices[18], vertices[10]),
            FalseCase(vertices[19], vertices[23]),
            TrueCase(vertices[19], vertices[17]),
            UnconditionalEdge(vertices[20], vertices[10]),
            UnconditionalEdge(vertices[21], vertices[10]),
            FalseCase(vertices[22], vertices[24]),
            TrueCase(vertices[22], vertices[20]),
            TrueCase(vertices[23], vertices[25]),
            FalseCase(vertices[23], vertices[26]),
            TrueCase(vertices[24], vertices[27]),
            FalseCase(vertices[24], vertices[28]),
            UnconditionalEdge(vertices[25], vertices[10]),
            TrueCase(vertices[26], vertices[29]),
            FalseCase(vertices[26], vertices[17]),
            UnconditionalEdge(vertices[27], vertices[10]),
            TrueCase(vertices[28], vertices[30]),
            FalseCase(vertices[28], vertices[20]),
            UnconditionalEdge(vertices[29], vertices[10]),
            UnconditionalEdge(vertices[30], vertices[10]),
        ]
    )
    return var_0, var_1, vertices


def _switch_test_19(task) -> Tuple[Variable, List[BasicBlock]]:
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0_1 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_0_2 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 9, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0_1], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.less_or_equal, [var_0_1, Constant(39, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.greater_us, [var_0_1, Constant(40, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                2,
                [
                    Assignment(ListOperation([var_0_2]), Call(imp_function_symbol("rand"), [], Pointer(CustomType("void", 0), 32), 8)),
                    Branch(Condition(OperationType.not_equal, [var_0_2, Constant(50, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(4, [IndirectBranch(var_0_1)]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Friday", 10))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 12))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Monday", 3))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Tuesday", 4))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Wednesday", 5))]),
            BasicBlock(11, [Assignment(ListOperation([]), print_call("Saturday", 6))]),
            BasicBlock(12, [Assignment(ListOperation([]), print_call("Sunday", 7))]),
            BasicBlock(13, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            TrueCase(vertices[1], vertices[5]),
            FalseCase(vertices[2], vertices[4]),
            TrueCase(vertices[2], vertices[5]),
            SwitchCase(
                vertices[3],
                vertices[5],
                [
                    Constant(0, Integer(32)),
                    Constant(2, Integer(32)),
                    Constant(3, Integer(32)),
                    Constant(4, Integer(32)),
                    Constant(5, Integer(32)),
                    Constant(7, Integer(32)),
                    Constant(8, Integer(32)),
                    Constant(10, Integer(32)),
                    Constant(11, Integer(32)),
                    Constant(13, Integer(32)),
                    Constant(14, Integer(32)),
                    Constant(15, Integer(32)),
                    Constant(16, Integer(32)),
                    Constant(17, Integer(32)),
                    Constant(18, Integer(32)),
                    Constant(19, Integer(32)),
                    Constant(20, Integer(32)),
                    Constant(21, Integer(32)),
                    Constant(22, Integer(32)),
                    Constant(23, Integer(32)),
                    Constant(24, Integer(32)),
                    Constant(25, Integer(32)),
                    Constant(26, Integer(32)),
                    Constant(27, Integer(32)),
                    Constant(28, Integer(32)),
                    Constant(29, Integer(32)),
                    Constant(30, Integer(32)),
                    Constant(31, Integer(32)),
                    Constant(32, Integer(32)),
                    Constant(33, Integer(32)),
                    Constant(35, Integer(32)),
                    Constant(36, Integer(32)),
                    Constant(37, Integer(32)),
                    Constant(38, Integer(32)),
                    Constant(39, Integer(32)),
                ],
            ),
            SwitchCase(vertices[3], vertices[6], [Constant(1, Integer(32))]),
            SwitchCase(vertices[3], vertices[7], [Constant(12, Integer(32))]),
            SwitchCase(vertices[3], vertices[8], [Constant(34, Integer(32))]),
            SwitchCase(vertices[3], vertices[9], [Constant(6, Integer(32))]),
            SwitchCase(vertices[3], vertices[10], [Constant(9, Integer(32))]),
            UnconditionalEdge(vertices[4], vertices[11]),
            UnconditionalEdge(vertices[5], vertices[11]),
            UnconditionalEdge(vertices[6], vertices[11]),
            UnconditionalEdge(vertices[7], vertices[11]),
            UnconditionalEdge(vertices[8], vertices[11]),
            UnconditionalEdge(vertices[9], vertices[11]),
            UnconditionalEdge(vertices[10], vertices[11]),
        ]
    )
    return var_0_1, vertices


def test_basic_switch(task):
    """
      test_switch test1

                                  +--------------------------------------------------------------------------------------------------------------------------------------------+
                                  |                                                                                                                                            |
                                  |                                                                    +------------------------------------+                                  |
                                  |                                                                    |                 9.                 |                                  |
    +-----------------------------+------------------------------------------------------------------- |         printf("Saturday")         | <+                               |
    |                             |                                                                    +------------------------------------+  |                               |
    |                             |                                                                                                            |                               |
    |                             |                                                                                                            |                               |
    |                             v                                                                                                            |                               |
    |                           +----------------------------------------------------------------+     +------------------------------------+  |  +--------------------+       |
    |                           |                                                                |     |                 0.                 |  |  |                    |       |
    |                           |                               3.                               |     | printf("Enter week number(1-7): ") |  |  |         7.         |       |
    |                           | printf("Invalid input! Please enter week number between 1-7.") |     |          var_1 = &(var_0)          |  |  | printf("Thursday") |       |
    |                           |                                                                |     |  __isoc99_scanf(0x804b025, var_1)  |  |  |                    |       |
    |                           |                                                                | <-- |          if(var_0 u> 0x7)          |  |  |                    | ------+------------------------------------------------+
    |                           +----------------------------------------------------------------+     +------------------------------------+  |  +--------------------+       |                                                |
    |                             |                                                                      |                                     |    ^                          |                                                |
    |                             |                                                                      |                                     |    |                          |                                                |
    |                             |                                                                      v                                     |    |                          |                                                |
    |  +------------------+       |                                                                    +-----------------------------------------------------------------------------------------+     +---------------------+  |
    |  |        8.        |       |                                                                    |                                                                                         |     |         6.          |  |
    |  | printf("Friday") | <-----+------------------------------------------------------------------- |                                           2.                                            | --> | printf("Wednesday") |  |
    |  +------------------+       |                                                                    |                                        jmp var_0                                        |     +---------------------+  |
    |    |                        |                                                                    |                                                                                         |       |                      |
    |    |                        |                                                                    |                                                                                         |       |                      |
    |    |                        |                                                                    +-----------------------------------------------------------------------------------------+       |                      |
    |    |                        |                                                                      |                                          |                          |                         |                      |
    |    |                        |                                                                      |                                          |                          |                         |                      |
    |    |                        |                                                                      v                                          v                          v                         |                      |
    |    |                        |                                                                    +------------------------------------+     +--------------------+     +-------------------+       |                      |
    |    |                        |                                                                    |                10.                 |     |         4.         |     |        5.         |       |                      |
    |    |                        |                                                                    |          printf("Sunday")          |     |  printf("Monday")  |     | printf("Tuesday") |       |                      |
    |    |                        |                                                                    +------------------------------------+     +--------------------+     +-------------------+       |                      |
    |    |                        |                                                                      |                                          |                          |                         |                      |
    |    |                        |                                                                      |                                          |                          |                         |                      |
    |    |                        |                                                                      v                                          v                          v                         |                      |
    |    |                        |                                                                    +-----------------------------------------------------------------------------------------+       |                      |
    |    |                        +------------------------------------------------------------------> |                                                                                         | <-----+                      |
    |    |                                                                                             |                                                                                         |                              |
    |    |                                                                                             |                                           11.                                           |                              |
    |    +-------------------------------------------------------------------------------------------> |                                       return 0x0                                        | <----------------------------+
    |                                                                                                  |                                                                                         |
    |                                                                                                  |                                                                                         |
    +------------------------------------------------------------------------------------------------> |                                                                                         |
                                                                                                       +-----------------------------------------------------------------------------------------+
    """
    var_0, vertices = _basic_switch_cfg(task)

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert (
        isinstance(case1 := switch.cases[0], CaseNode)
        and case1.constant == Constant(1, Integer(32, signed=True))
        and case1.break_case is True
    )
    assert (
        isinstance(case2 := switch.cases[1], CaseNode)
        and case2.constant == Constant(2, Integer(32, signed=True))
        and case2.break_case is True
    )
    assert (
        isinstance(case3 := switch.cases[2], CaseNode)
        and case3.constant == Constant(3, Integer(32, signed=True))
        and case3.break_case is True
    )
    assert (
        isinstance(case4 := switch.cases[3], CaseNode)
        and case4.constant == Constant(4, Integer(32, signed=True))
        and case4.break_case is True
    )
    assert (
        isinstance(case5 := switch.cases[4], CaseNode)
        and case5.constant == Constant(5, Integer(32, signed=True))
        and case5.break_case is True
    )
    assert (
        isinstance(case6 := switch.cases[5], CaseNode)
        and case6.constant == Constant(6, Integer(32, signed=True))
        and case6.break_case is True
    )
    assert (
        isinstance(case7 := switch.cases[6], CaseNode)
        and case7.constant == Constant(7, Integer(32, signed=True))
        and case7.break_case is True
    )
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[3].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[4].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[5].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[6].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[7].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[8].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[9].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions


def test_switch_cases_without_break_and_no_instruction(task):
    """
      test_switch test2
       +-----------------------------------------------------------------++----------------------+
       |                               0.                                ||                      |
       |              printf("Enter month number(1-12): ")               ||          6.          |
       |                        var_1 = &(var_0)                         || printf("28/29 days") |
       |                __isoc99_scanf(0x804b025, var_1)                 ||                      |
    +- |                        if(var_0 u> 0xc)                         ||                      | ---------------------------+
    |  +-----------------------------------------------------------------++----------------------+                            |
    |    |                                                                  ^                                                 |
    |    |                                                                  |                                                 |
    |    v                                                                  |                                                 |
    |  +-----------------------------------------------------------------------------------------+     +-------------------+  |
    |  |                                           2.                                            |     |        5.         |  |
    |  |                                        jmp var_0                                        | --> | printf("30 days") |  |
    |  +-----------------------------------------------------------------------------------------+     +-------------------+  |
    |    |                                                                  |                            |                    |
    |    |                                                                  |                            |                    |
    |    v                                                                  v                            |                    |
    |  +-----------------------------------------------------------------++----------------------+       |                    |
    |  |                               3.                                ||          4.          |       |                    |
    +> | printf("Invalid input! Please enter month number between 1-12") ||  printf("31 days")   |       |                    |
       +-----------------------------------------------------------------++----------------------+       |                    |
         |                                                                  |                            |                    |
         |                                                                  |                            |                    |
         v                                                                  v                            |                    |
       +-----------------------------------------------------------------------------------------+       |                    |
       |                                           7.                                            |       |                    |
       |                                       return 0x0                                        | <-----+                    |
       +-----------------------------------------------------------------------------------------+                            |
                                                                            ^                                                 |
                                                                            +-------------------------------------------------+
    """
    var_0, vertices = _switch_empty_fallthrough(task)

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 13
    # 31 days:
    for idx, const in enumerate([1, 3, 5, 7, 8, 10]):
        assert (
            isinstance(case := switch.cases[idx], CaseNode)
            and case.constant == Constant(const, Integer(32, True))
            and case.break_case is False
            and case.child.is_empty_code_node
        )
    assert isinstance(case := switch.cases[6], CaseNode) and case.constant == Constant(12, Integer(32, True)) and case.break_case is True
    assert isinstance(case.child, CodeNode) and case.child.instructions == vertices[3].instructions
    # 28 days:
    assert isinstance(case := switch.cases[7], CaseNode) and case.constant == Constant(2, Integer(32, True)) and case.break_case is True
    assert isinstance(case.child, CodeNode) and case.child.instructions == vertices[5].instructions
    # 30 days:
    for idx, const in enumerate([4, 6, 9]):
        assert (
            isinstance(case := switch.cases[idx + 8], CaseNode)
            and case.constant == Constant(const, Integer(32, True))
            and case.break_case is False
            and case.child.is_empty_code_node
        )
    assert isinstance(case := switch.cases[11], CaseNode) and case.constant == Constant(11, Integer(32, True)) and case.break_case is True
    assert isinstance(case.child, CodeNode) and case.child.instructions == vertices[4].instructions
    # default case:
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions


def test_switch_one_large_number(task):
    """
      test_switch test7 (correct jump-table)
              +-----------------------------------------------------+
              |                                                     |
              |                                                     |
    +---------+    +--------------------------+                     |
    |              |                          |                     |
    |              |                          |                     |
    |    +---------+                     +----+---------------------+---------------------------------------------------------------------------------+
    |    |                               |    v                     v                                                                                 |
    |    |                               |  +----------------------------------------------------------------+                                        |
    |    |                               |  |                               8.                               |                                        |
    |    |    +--------------------------+  | printf("Invalid input! Please enter week number between 1-7.") | ----------------------------------+    |
    |    |    |                             +----------------------------------------------------------------+                                   |    |
    |    |    |                               ^                           ^                                                                      |    |
    +----+----+--------------------------+    |                           +-------------------------------------+                                |    |
         |    |                          |    |                                                                 |                                |    |
         |    |                          |  +--------------------+      +------------------------------------+  |                                |    |
         |    |                          |  |                    |      |                 0.                 |  |                                |    |
         |    |                          |  |         1.         |      | printf("Enter week number(1-7): ") |  |                                |    |
         |    |                          |  | if(var_0 == 0x1f4) |      |          var_1 = &(var_0)          |  |                                |    |
         |    |                          |  |                    |      |  __isoc99_scanf(0x804b025, var_1)  |  |                                |    |
         |    |                          |  |                    | <--- |          if(var_0 > 0x28)          |  |                                |    |
         |    |                          |  +--------------------+      +------------------------------------+  |                                |    |
         |    |                          |    |                           |                                     |                                |    |
         |    |                          |    |                           |                                     |    +---------------------------+----+
         |    |                          |    v                           v                                     |    v                           |
         |    |                          |  +--------------------+      +------------------------------------+  |  +---------------------+       |
         |    |                          |  |         3.         |      |                 2.                 |  |  |         16.         |       |
         |    |                          |  |  printf("Friday")  |      |          if(var_0 <= 0x0)          | -+  |  printf("Sunday")   | ------+-------------------------------+
         |    |                          |  +--------------------+      +------------------------------------+     +---------------------+       |                               |
         |    |                          |    |                           |                                                                      |                               |
         |    |                          |    |                           |                                                                      |                               |
         |    |                          |    |                           v                                                                      |                               |
         |    |                          |    |                         +------------------------------------+     +---------------------+       |                               |
         |    |                          |    |                         |                 6.                 |     |         13.         |       |                               |
         |    |                          +----+------------------------ |         if(var_0 u> 0x28)          |  +> | printf("Wednesday") |       |                               |
         |    |                               |                         +------------------------------------+  |  +---------------------+       |                               |
         |    |                               |                           |                                     |    |                           |                               |
         |    |                               |                           |                                     |    +----------------------+    |                               |
         |    |                               |                           v                                     |                           |    |                               |
         |    |  +--------------------+       |                         +----------------------------------------------------------------+  |    |       +--------------------+  |
         |    |  |        14.         |       |                         |                                                                |  |    |       |        15.         |  |
         |    |  | printf("Thursday") | <-----+------------------------ |                                                                | -+----+-----> | printf("Saturday") |  |
         |    |  +--------------------+       |                         |                                                                |  |    |       +--------------------+  |
         |    |    |                          |                         |                              10.                               |  |    |         |                     |
         |    |    |                     +----+------------------------ |                           jmp var_0                            |  |    |         |                     |
         |    |    |                     |    |                         |                                                                |  |    |         |                     |
         |    |    |                     |    |                         |                                                                |  |    |         |                     |
         |    +----+---------------------+    |                     +-- |                                                                |  |    |         |                     |
         |         |                          |                     |   +----------------------------------------------------------------+  |    |         |                     |
         |         |                          |                     |     |                                          |                      |    |         |                     |
         +---------+--------------------------+---------------------+     |                                          |                      |    |         |                     |
                   |                          |                           v                                          v                      |    |         |                     |
                   |                          |                         +------------------------------------+     +---------------------+  |    |         |                     |
                   |                          |                         |                11.                 |     |         12.         |  |    |         |                     |
                   |                          |                         |          printf("Monday")          |     |  printf("Tuesday")  |  |    |         |                     |
                   |                          |                         +------------------------------------+     +---------------------+  |    |         |                     |
                   |                          |                           |                                          |                      |    |         |                     |
                   |                          |                           |                                          |                      |    |         |                     |
                   |                          |                           v                                          v                      v    v         |                     |
                   |                          |                         +--------------------------------------------------------------------------+       |                     |
                   |                          +-----------------------> |                                                                          | <-----+                     |
                   |                                                    |                                    7.                                    |                             |
                   |                                                    |                                return 0x0                                |                             |
                   +--------------------------------------------------> |                                                                          | <---------------------------+
                                                                        +--------------------------------------------------------------------------+
    """
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.greater, [var_0, Constant(40, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.equal, [var_0, Constant(500, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(2, [Branch(Condition(OperationType.less_or_equal, [var_0, Constant(0, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Friday", 3))]),
            BasicBlock(6, [Branch(Condition(OperationType.greater_us, [var_0, Constant(40, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(7, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 11))]),
            BasicBlock(10, [IndirectBranch(var_0)]),
            BasicBlock(11, [Assignment(ListOperation([]), print_call("Monday", 4))]),
            BasicBlock(12, [Assignment(ListOperation([]), print_call("Tuesday", 5))]),
            BasicBlock(13, [Assignment(ListOperation([]), print_call("Wednesday", 6))]),
            BasicBlock(14, [Assignment(ListOperation([]), print_call("Thursday", 7))]),
            BasicBlock(15, [Assignment(ListOperation([]), print_call("Saturday", 8))]),
            BasicBlock(16, [Assignment(ListOperation([]), print_call("Sunday", 9))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[1], vertices[6]),
            FalseCase(vertices[2], vertices[4]),
            TrueCase(vertices[2], vertices[6]),
            UnconditionalEdge(vertices[3], vertices[5]),
            FalseCase(vertices[4], vertices[7]),
            TrueCase(vertices[4], vertices[6]),
            UnconditionalEdge(vertices[6], vertices[5]),
            SwitchCase(vertices[7], vertices[6], [Constant(i) for i in range(2, 40) if i not in {6, 9, 12, 34}]),
            SwitchCase(vertices[7], vertices[8], [Constant(1, Integer(32, True))]),
            SwitchCase(vertices[7], vertices[9], [Constant(12, Integer(32, True))]),
            SwitchCase(vertices[7], vertices[10], [Constant(34, Integer(32, True))]),
            SwitchCase(vertices[7], vertices[11], [Constant(40, Integer(32, True))]),
            SwitchCase(vertices[7], vertices[12], [Constant(6, Integer(32, True))]),
            SwitchCase(vertices[7], vertices[13], [Constant(9, Integer(32, True))]),
            UnconditionalEdge(vertices[8], vertices[5]),
            UnconditionalEdge(vertices[9], vertices[5]),
            UnconditionalEdge(vertices[10], vertices[5]),
            UnconditionalEdge(vertices[11], vertices[5]),
            UnconditionalEdge(vertices[12], vertices[5]),
            UnconditionalEdge(vertices[13], vertices[5]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[5].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32, True)) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(6, Integer(32, True)) and case2.break_case is True
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(9, Integer(32, True)) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(12, Integer(32, True)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(34, Integer(32, True)) and case5.break_case is True
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(40, Integer(32, True)) and case6.break_case is True
    assert (
        isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(500, Integer(32, True)) and case7.break_case is True
    )
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[8].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[12].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[13].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[9].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[10].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[11].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[3].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[6].instructions


def test_switch_two_large_numbers(task):
    """
    test_switch test7_a
                              +------------------+     +------------------------------------+
                              |                  |     |                 0.                 |
                              |        1.        |     | printf("Enter week number(1-7): ") |
                              | printf("Friday") |     |          var_1 = &(var_0)          |
                              |                  |     |  __isoc99_scanf(0x804b025, var_1)  |
                              |                  | <-- |         if(var_0 == 0x1f4)         |
                              +------------------+     +------------------------------------+
                                |                        |
                                |                        |
                                |                        v
                                |                      +------------------------------------+
                                |                      |                 2.                 |
                                |                   +- |         if(var_0 > 0x1f4)          |
                                |                   |  +------------------------------------+
                                |                   |    |
                                |                   |    |
                                |                   |    v
                                |                   |  +------------------------------------+     +---------------------+     +--------------------+
                                |                   |  |                 5.                 |     |         7.          |     |         9.         |
                                |                   |  |          if(var_0 > 0x22)          | --> | if(var_0 == 0x190)  | --> | printf("Thursday") |
                                |                   |  +------------------------------------+     +---------------------+     +--------------------+
                                |                   |    |                                                                      |
                                |                   |    |                                                                      |
                                |                   |    v                                                                      |
                                |                   |  +------------------------------------+                                   |
                                |                   |  |                 8.                 |                                   |
                                |                   |  |          if(var_0 < 0x0)           | -----------------------------+    |
                                |                   |  +------------------------------------+                              |    |
                                |                   |    |                                                                 |    |
                                |                   |    |                                                                 |    +---------------------+
                                |                   |    v                                                                 |                          |
                                |                   |  +------------------------------------+                              |                          |
                                |                   |  |                12.                 |                              |                          |
                                |                   |  |         if(var_0 u> 0x22)          | -----------------------------+----+                     |
                                |                   |  +------------------------------------+                              |    |                     |
                                |                   |    |                                                                 |    |                     |
                                |                   |    |                                          +----------------------+----+---------------------+--------------+
                                |                   |    v                                          |                      |    |                     |              |
     +------------------+       |                   |  +----------------------------------------------------------------+  |    |                     |              |
     |       15.        |       |                   |  |                                                                |  |    |                     |              |
     | printf("Monday") | <-----+-------------------+- |                                                                |  |    |                     |              |
     +------------------+       |                   |  |                                                                |  |    |                     |              |
       |                        |                   |  |                              14.                               |  |    |                     |              |
       |                        |                   |  |                           jmp var_0                            | -+----+---------------------+---------+    |
       |                        |                   |  |                                                                |  |    |                     |         |    |
       |                        |                   |  |                                                                |  |    |                     |         |    |
       |                   +----+-------------------+- |                                                                | -+----+---------------------+----+    |    |
       |                   |    |                   |  +----------------------------------------------------------------+  |    |                     |    |    |    |
       |                   |    |                   |    |                                                                 |    |                     |    |    |    |
       |                   |    |                   |    |                                                                 |    |                     |    |    |    |
       |                   |    |                   |    v                                                                 |    |                     |    |    |    |
       |                   |    |                   |  +----------------------------------------------------------------+  |    |                     |    |    |    |
       |                   |    |                   |  |                               6.                               |  |    |                     |    |    |    |
       |                   |    |                   +> | printf("Invalid input! Please enter week number between 1-7.") | <+    |                     |    |    |    |
       |                   |    |                      +----------------------------------------------------------------+       |                     |    |    |    |
       |                   |    |                        |                                          ^                           |                     |    |    |    |
       |                   |    |                        |                                          +---------------------------+                     |    |    |    |
       |                   |    |                        v                                                                                            |    |    |    |
       |                   |    |                      +-------------------------------------------------------------------------------------------+  |    |    |    |
       |                   |    +--------------------> |                                                                                           | <+    |    |    |
       |                   |                           |                                            3.                                             |       |    |    |
       |                   |                           |                                        return 0x0                                         |       |    |    |
       +-------------------+-------------------------> |                                                                                           |       |    |    |
                           |                           +-------------------------------------------------------------------------------------------+       |    |    |
                           |                             ^                                     ^    ^                           ^                          |    |    |
                           |                             |                                     |    |                           |                          |    |    |
                           |                             |                                     |    |                           |                          |    |    |
                           |                           +------------------------------------+  |  +---------------------+       |                          |    |    |
                           |                           |                16.                 |  |  |         17.         |       |                          |    |    |
                           +-------------------------> |         printf("Tuesday")          |  |  | printf("Wednesday") | <-----+--------------------------+    |    |
                                                       +------------------------------------+  |  +---------------------+       |                               |    |
                                                                                               |                                |                               |    |
                                +--------------------------------------------------------------+                                |                               |    |
                                |                                                                                               |                               |    |
                                |                      +------------------------------------+                                   |                               |    |
                                |                      |                18.                 |                                   |                               |    |
                                |                      |         printf("Saturday")         | ----------------------------------+                               |    |
                                |                      +------------------------------------+                                                                   |    |
                                |                        ^                                                                                                      |    |
                                |                        +------------------------------------------------------------------------------------------------------+    |
                                |                                                                                                                                    |
                                |                      +------------------------------------+                                                                        |
                                |                      |                19.                 |                                                                        |
                                +--------------------- |          printf("Sunday")          | <----------------------------------------------------------------------+
                                                       +------------------------------------+
    """
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.equal, [var_0, Constant(500, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Assignment(ListOperation([]), print_call("Friday", 3))]),
            BasicBlock(2, [Branch(Condition(OperationType.greater, [var_0, Constant(500, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(3, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(5, [Branch(Condition(OperationType.greater, [var_0, Constant(34, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 10))]),
            BasicBlock(7, [Branch(Condition(OperationType.equal, [var_0, Constant(400, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(8, [Branch(Condition(OperationType.less, [var_0, Constant(0, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Thursday", 4))]),
            BasicBlock(12, [Branch(Condition(OperationType.greater_us, [var_0, Constant(34, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(14, [IndirectBranch(var_0)]),
            BasicBlock(15, [Assignment(ListOperation([]), print_call("Monday", 5))]),
            BasicBlock(16, [Assignment(ListOperation([]), print_call("Tuesday", 6))]),
            BasicBlock(17, [Assignment(ListOperation([]), print_call("Wednesday", 7))]),
            BasicBlock(18, [Assignment(ListOperation([]), print_call("Saturday", 8))]),
            BasicBlock(19, [Assignment(ListOperation([]), print_call("Sunday", 9))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            FalseCase(vertices[2], vertices[4]),
            TrueCase(vertices[2], vertices[5]),
            TrueCase(vertices[4], vertices[6]),
            FalseCase(vertices[4], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[3]),
            TrueCase(vertices[6], vertices[8]),
            FalseCase(vertices[6], vertices[5]),
            FalseCase(vertices[7], vertices[9]),
            TrueCase(vertices[7], vertices[5]),
            UnconditionalEdge(vertices[8], vertices[3]),
            FalseCase(vertices[9], vertices[10]),
            TrueCase(vertices[9], vertices[5]),
            SwitchCase(vertices[10], vertices[5], [Constant(x, Integer(32, True)) for x in set(range(1, 34)) - {6, 9, 12}]),
            SwitchCase(vertices[10], vertices[11], [Constant(0, Integer(32, True))]),
            SwitchCase(vertices[10], vertices[12], [Constant(12, Integer(32, True))]),
            SwitchCase(vertices[10], vertices[13], [Constant(34, Integer(32, True))]),
            SwitchCase(vertices[10], vertices[14], [Constant(6, Integer(32, True))]),
            SwitchCase(vertices[10], vertices[15], [Constant(9, Integer(32, True))]),
            UnconditionalEdge(vertices[11], vertices[3]),
            UnconditionalEdge(vertices[12], vertices[3]),
            UnconditionalEdge(vertices[13], vertices[3]),
            UnconditionalEdge(vertices[14], vertices[3]),
            UnconditionalEdge(vertices[15], vertices[3]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[3].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(0, Integer(32, True)) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(6, Integer(32, True)) and case2.break_case is True
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(9, Integer(32, True)) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(12, Integer(32, True)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(34, Integer(32, True)) and case5.break_case is True
    assert (
        isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(400, Integer(32, True)) and case6.break_case is True
    )
    assert (
        isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(500, Integer(32, True)) and case7.break_case is True
    )
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False
    #
    # # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[11].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[14].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[15].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[12].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[13].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[8].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[1].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[5].instructions


def test_switch_cases_without_break_and_instructions(task):
    """
        test_switch test_11

                                                                        +------------------------------------------------+
                                                                        |                                                v
    +-----------------------+     +----------------------------------+  |  +---------------+     +---------------+     +---------------+
    |                       |     |                0.                |  |  |               |     |               |     |               |
    |          1.           |     | printf("Enter a digit (0-9): ")  |  |  |      6.       |     |      7.       |     |      8.       |
    | printf("Not a digit") |     |         var_1 = &(var_0)         |  |  | putchar(0x32) |     | putchar(0x33) |     | putchar(0x34) |
    |                       |     | __isoc99_scanf(0x804b025, var_1) |  |  |               |     |               |     |               |
    |                       | <-- |         if(var_0 u> 0x9)         |  |  |               | --> |               | --> |               |
    +-----------------------+     +----------------------------------+  |  +---------------+     +---------------+     +---------------+
      |                             |                                   |    ^                     ^                     |
      |                             |                                   |    |                     |                     +----------------+
      |                             v                                   |    |                     |                                      |
      |                           +------------------------------------------------------------------------------+     +---------------+  |
      |                           |                                                                              |     |      4.       |  |
      |                           |                                                                              | --> | putchar(0x30) |  |
      |                           |                                                                              |     +---------------+  |
      |                           |                                                                              |       |                |
      |                           |                                                                              |       |                |
      |                           |                                                                              |       v                |
      |                           |                                      2.                                      |     +---------------+  |
      |                           |                                  jmp var_0                                   |     |      5.       |  |
      |                           |                                                                              | --> | putchar(0x31) |  |
      |                           |                                                                              |     +---------------+  |
      |                           |                                                                              |       |                |
      |                           |                                                                              |       |                |
      |                           |                                                                              |       |                |
      |                           |                                                                              |       |                |
      |                        +- |                                                                              |       |                |
      |                        |  +------------------------------------------------------------------------------+       |                |
      |                        |    |                                   |    |                |                          |                |
      |                        |    |                                   |    |                |                          |                |
      |                        |    v                                   |    |                |                          |                |
      |                        |  +----------------------------------+  |    |                |                          |                |
      |                        |  |                9.                |  |    |                |                          |                |
      |                        |  |          putchar(0x35)           |  |    |                |                          |                |
      |                        |  +----------------------------------+  |    |                |                          |                |
      |                        |    |                                   |    |                |                          |                |
      |                        |    |                                   |    |                |                          |                |
      |                        |    v                                   |    |                |                          |                |
      |                        |  +----------------------------------+  |    |                |                          |                |
      |                        |  |               10.                |  |    |                |                          |                |
      |                        |  |          putchar(0x36)           | <+    |                |                          |                |
      |                        |  +----------------------------------+       |                |                          |                |
      |                        |    |                                        |                |                          |                |
      |                        |    |                                        |                |                          |                |
      |                        |    v                                        |                |                          |                |
      |                        |  +----------------------------------+       |                |                          |                |
      |                        |  |               11.                |       |                |                          |                |
      |                        +> |          putchar(0x37)           |       |                |                          |                |
      |                           +----------------------------------+       |                |                          |                |
      |                             |                                        |                |                          |                |
      |                             |                                        |                |                          |                |
      |                             v                                        |                |                          |                |
      |                           +----------------------------------+       |                |                          |                |
      |                           |               12.                |       |                |                          |                |
      |                           |          putchar(0x38)           | <-----+                |                          |                |
      |                           +----------------------------------+                        |                          |                |
      |                             |                                                         |                          |                |
      |                             |                                                         |                          |                |
      |                             v                                                         |                          |                |
      |                           +----------------------------------+                        |                          |                |
      |                           |               13.                |                        |                          |                |
      |                           |          putchar(0x39)           | <----------------------+                          |                |
      |                           +----------------------------------+                                                   |                |
      |                             |                                                                                    |                |
      |                             |                                                                                    |                |
      |                             v                                                                                    |                |
      |                           +--------------------------------------------------------+                             |                |
      |                           |                           3.                           |                             |                |
      +-------------------------> |                       return 0x0                       | <---------------------------+                |
                                  +--------------------------------------------------------+                                              |
                                                                             ^                                                            |
                                                                             +------------------------------------------------------------+


    """
    var_0, vertices = _switch_no_empty_fallthrough(task)

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[3].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 11
    assert isinstance(case0 := switch.cases[0], CaseNode) and case0.constant == Constant(0, Integer(32)) and case0.break_case is False
    assert isinstance(case1 := switch.cases[1], CaseNode) and case1.constant == Constant(1, Integer(32)) and case1.break_case is True
    assert isinstance(case2 := switch.cases[2], CaseNode) and case2.constant == Constant(2, Integer(32)) and case2.break_case is False
    assert isinstance(case3 := switch.cases[3], CaseNode) and case3.constant == Constant(3, Integer(32)) and case3.break_case is False
    assert isinstance(case4 := switch.cases[4], CaseNode) and case4.constant == Constant(4, Integer(32)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[5], CaseNode) and case5.constant == Constant(5, Integer(32)) and case5.break_case is False
    assert isinstance(case6 := switch.cases[6], CaseNode) and case6.constant == Constant(6, Integer(32)) and case6.break_case is False
    assert isinstance(case7 := switch.cases[7], CaseNode) and case7.constant == Constant(7, Integer(32)) and case7.break_case is False
    assert isinstance(case8 := switch.cases[8], CaseNode) and case8.constant == Constant(8, Integer(32)) and case8.break_case is False
    assert isinstance(case9 := switch.cases[9], CaseNode) and case9.constant == Constant(9, Integer(32)) and case9.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case0.child, CodeNode) and case0.child.instructions == vertices[4].instructions
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[5].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[6].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[7].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[8].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[9].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[10].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[11].instructions
    assert isinstance(case8.child, CodeNode) and case8.child.instructions == vertices[12].instructions
    assert isinstance(case9.child, CodeNode) and case9.child.instructions == vertices[13].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[1].instructions


def test_switch_cases_without_break_and_some_instructions(task):
    """
    test_switch test22
      +---------------------------------------------------------------------------------------------------------------+
      v                                                                                                               |
    +-----------------------------------------------------------------+     +--------------------------------------+  |  +----------------------+
    |                                                                 |     |                  0.                  |  |  |                      |
    |                               3.                                |     | printf("Enter month number(1-12): ") |  |  |          7.          |
    | printf("Invalid input! Please enter month number between 1-12") |     |           var_1 = &(var_0)           |  |  | printf("28/29 days") |
    |                                                                 |     |   __isoc99_scanf(0x804b025, var_1)   |  |  |                      |
    |                                                                 | <-- |           if(var_0 u> 0xc)           |  |  |                      | ---------------------------+
    +-----------------------------------------------------------------+     +--------------------------------------+  |  +----------------------+                            |
      |                                                                       |                                       |    ^                                                 |
      |                                                                       |                                       |    |                                                 |
      |                                                                       v                                       |    |                                                 |
      |                                                                     +-------------------------------------------------------------------+     +-------------------+  |
      |                                                                     |                                2.                                 |     |        6.         |  |
      |                                                                     |                             jmp var_0                             | --> | printf("30 days") |  |
      |                                                                     +-------------------------------------------------------------------+     +-------------------+  |
      |                                                                       |                                       |                                 |                    |
      |                                                                       |                                       |                                 |                    |
      |                                                                       v                                       |                                 |                    |
      |                                                                     +--------------------------------------+  |                                 |                    |
      |                                                                     |                  4.                  |  |                                 |                    |
      |                                                                     |   printf("first half of the year")   |  |                                 |                    |
      |                                                                     +--------------------------------------+  |                                 |                    |
      |                                                                       |                                       |                                 |                    |
      |                                                                       |                                       |                                 |                    |
      |                                                                       v                                       |                                 |                    |
      |                                                                     +--------------------------------------+  |                                 |                    |
      |                                                                     |                  5.                  |  |                                 |                    |
      |                                                                     |          printf("31 days")           | <+                                 |                    |
      |                                                                     +--------------------------------------+                                    |                    |
      |                                                                       |                                                                         |                    |
      |                                                                       |                                                                         |                    |
      |                                                                       v                                                                         |                    |
      |                                                                     +-------------------------------------------------------------------+       |                    |
      |                                                                     |                                8.                                 |       |                    |
      +-------------------------------------------------------------------> |                            return 0x0                             | <-----+                    |
                                                                            +-------------------------------------------------------------------+                            |
                                                                                                                           ^                                                 |
                                                                                                                           +-------------------------------------------------+
    """
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter month number(1-12): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(12, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter month number between 1-12", 8))]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("first half of the year", 3))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("31 days", 5))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("30 days", 6))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("28/29 days", 7))]),
            BasicBlock(8, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(0, Integer(32))]),
            SwitchCase(vertices[1], vertices[3], [Constant(i, Integer(32)) for i in (1, 3, 5)]),
            SwitchCase(vertices[1], vertices[4], [Constant(i, Integer(32)) for i in (7, 8, 10, 12)]),
            SwitchCase(vertices[1], vertices[5], [Constant(i, Integer(32)) for i in (4, 6, 9, 11)]),
            SwitchCase(vertices[1], vertices[6], [Constant(2, Integer(32))]),
            UnconditionalEdge(vertices[2], vertices[7]),
            UnconditionalEdge(vertices[3], vertices[4]),
            UnconditionalEdge(vertices[4], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[7]),
            UnconditionalEdge(vertices[6], vertices[7]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[7].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 13
    # 31 days - first half:
    for idx, const in enumerate([1, 3]):
        assert (
            isinstance(case := switch.cases[idx], CaseNode)
            and case.constant == Constant(const, Integer(32))
            and case.break_case is False
            and case.child.is_empty_code_node
        )
    assert isinstance(case := switch.cases[2], CaseNode) and case.constant == Constant(5, Integer(32)) and case.break_case is False
    assert isinstance(case.child, CodeNode) and case.child.instructions == vertices[3].instructions
    # 31 days - second half
    for idx, const in enumerate([7, 8, 10]):
        assert (
            isinstance(case := switch.cases[idx + 3], CaseNode)
            and case.constant == Constant(const, Integer(32))
            and case.break_case is False
            and case.child.is_empty_code_node
        )
    assert isinstance(case := switch.cases[6], CaseNode) and case.constant == Constant(12, Integer(32)) and case.break_case is True
    assert isinstance(case.child, CodeNode) and case.child.instructions == vertices[4].instructions
    # 28 days:
    assert isinstance(case := switch.cases[7], CaseNode) and case.constant == Constant(2, Integer(32)) and case.break_case is True
    assert isinstance(case.child, CodeNode) and case.child.instructions == vertices[6].instructions
    # 30 days:
    for idx, const in enumerate([4, 6, 9]):
        assert (
            isinstance(case := switch.cases[idx + 8], CaseNode)
            and case.constant == Constant(const, Integer(32))
            and case.break_case is False
            and case.child.is_empty_code_node
        )
    assert isinstance(case := switch.cases[11], CaseNode) and case.constant == Constant(11, Integer(32)) and case.break_case is True
    assert isinstance(case.child, CodeNode) and case.child.instructions == vertices[5].instructions
    # default case:
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions


def test_switch_condition_node_as_case_node_child(task):
    """
    test_switch test13
                                                                +---------------------------------------------------+
                                                                |                        9.                         |
                                                                |                   putchar(0x37)                   | --------------------------------------------------+
                                                                +---------------------------------------------------+                                                   |
                                                                  ^                                                                                                     |
                                                                  +----------------------------------------------------+                                                |
                                                                                                                       |                                                |
                             +----------------------------+     +---------------------------------------------------+  |  +---------------+                             |
                             |                            |     |                        0.                         |  |  |               |                             |
                             |                            |     | printf("Enter an even number between 4 and 14: ") |  |  |               |                             |
                             |                            |     |                 var_2 = &(var_0)                  |  |  |               |                             |
                             |             3.             |     |         __isoc99_scanf(0x804b025, var_2)          |  |  |      7.       |                             |
                             | printf("Not in the range") |     | printf("Enter 1 if you want to divide by two: ")  |  |  | putchar(0x35) |                             |
                             |                            |     |                 var_2 = &(var_1)                  |  |  |               |                             |
                             |                            |     |         __isoc99_scanf(0x804b025, var_2)          |  |  |               |                             |
    +----------------------> |                            | <-- |             if((var_0 - 0x4) u> 0xa)              |  |  |               | -----------------------+    |
    |                        +----------------------------+     +---------------------------------------------------+  |  +---------------+                        |    |
    |                          |                                  |                                                    |    ^                                      |    |
    |                          |                                  |                                                    |    |                                      |    |
    |                          |                                  v                                                    |    |                                      |    |
    |  +---------------+       |                                +-------------------------------------------------------------------------+     +---------------+  |    |
    |  |      8.       |       |                                |                                                                         |     |      6.       |  |    |
    |  | putchar(0x36) | <-----+------------------------------- |                                                                         | --> | putchar(0x34) |  |    |
    |  +---------------+       |                                |                                                                         |     +---------------+  |    |
    |    |                     |                                |                                   2.                                    |       |                |    |
    |    |                +----+------------------------------- |                             jmp var_0 - 0x4                             |       |                |    |
    |    |                |    |                                |                                                                         |       |                |    |
    |    |                |    |                                |                                                                         |       |                |    |
    +----+----------------+    |                                |                                                                         |       |                |    |
         |                     |                                +-------------------------------------------------------------------------+       |                |    |
         |                     |                                  |                                                    |                          |                |    |
         |                     |                                  |                                                    |                          |                |    |
         |                     |                                  v                                                    |                          |                |    |
         |                     |                                +---------------------------------------------------+  |                          |                |    |
         |                     |                                |                        5.                         |  |                          |                |    |
         |                +----+------------------------------- |                 if(var_1 != 0x1)                  |  |                          |                |    |
         |                |    |                                +---------------------------------------------------+  |                          |                |    |
         |                |    |                                  |                                                    |                          |                |    |
         |                |    |                             +----+                                                    |                          |                |    |
         |                |    |                             |                                                         |                          |                |    |
         |                |    |                             |  +---------------------------------------------------+  |                          |                |    |
         |                |    |                             |  |                        4.                         |  |                          |                |    |
    +----+----------------+----+-----------------------------+- |                 if(var_1 != 0x1)                  | <+                          |                |    |
    |    |                |    |                             |  +---------------------------------------------------+                             |                |    |
    |    |                |    |                             |    |                                                                               |                |    |
    |    |                |    |                             |    |                                                                               |                |    |
    |    |                |    |                             |    v                                                                               |                |    |
    |    |                |    |                             |  +---------------------------------------------------+                             |                |    |
    |    |                |    |                             |  |                        11.                        |                             |                |    |
    |    |                |    |                             |  |                   putchar(0x34)                   |                             |                |    |
    |    |                |    |                             |  +---------------------------------------------------+                             |                |    |
    |    |                |    |                             |    |                                                                               |                |    |
    |    |                |    |                             |    |                                                                               |                |    |
    |    |                |    |                             |    v                                                                               v                |    |
    |    |                |    |                             |  +-----------------------------------------------------------------------------------------------+  |    |
    |    |                |    |                             +> |                                                                                               | <+    |
    |    |                |    |                                |                                                                                               |       |
    |    |                |    |                                |                                              10.                                              |       |
    |    |                |    +------------------------------> |                                          return 0x0                                           | <-----+
    |    |                |                                     |                                                                                               |
    |    |                |                                     |                                                                                               |
    |    +----------------+-----------------------------------> |                                                                                               |
    |                     |                                     +-----------------------------------------------------------------------------------------------+
    |                     |                                       ^                                                         ^
    |                     |                                       |                                                         |
    |                     |                                       |                                                         |
    |                     |                                     +---------------------------------------------------+     +---------------+
    |                     |                                     |                        14.                        |     |      12.      |
    |                     +-----------------------------------> |                   putchar(0x33)                   |     | putchar(0x32) |
    |                                                           +---------------------------------------------------+     +---------------+
    |                                                                                                                       ^
    +-----------------------------------------------------------------------------------------------------------------------+
    """
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_1 = Variable("var_1", Integer(32, True), None, True, Variable("var_14", Integer(32, True), 0, True, None))
    var_2_1 = Variable(
        "var_2", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_2_2 = Variable(
        "var_2", Pointer(Integer(32, True), 32), None, False, Variable("var_28_1", Pointer(Integer(32, True), 32), 2, False, None)
    )
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter an even number between 4 and 14: ", 1)),
                    Assignment(var_2_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_2_1, 134524965, 2)),
                    Assignment(ListOperation([]), print_call("Enter 1 if you want to divide by two: ", 3)),
                    Assignment(var_2_2, UnaryOperation(OperationType.address, [var_1], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_2_2, 134524965, 4)),
                    Branch(
                        Condition(
                            OperationType.greater_us,
                            [
                                BinaryOperation(OperationType.minus, [var_0, Constant(4, Integer(32, True))], Integer(32, True)),
                                Constant(10, Integer(32, True)),
                            ],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                2, [IndirectBranch(BinaryOperation(OperationType.minus, [var_0, Constant(4, Integer(32, True))], Integer(32, True)))]
            ),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Not in the range", 13))]),
            BasicBlock(4, [Branch(Condition(OperationType.not_equal, [var_1, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(5, [Branch(Condition(OperationType.not_equal, [var_1, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(6, [Assignment(ListOperation([]), putchar_call(52, 9))]),
            BasicBlock(7, [Assignment(ListOperation([]), putchar_call(53, 10))]),
            BasicBlock(8, [Assignment(ListOperation([]), putchar_call(54, 11))]),
            BasicBlock(9, [Assignment(ListOperation([]), putchar_call(55, 12))]),
            BasicBlock(10, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(11, [Assignment(ListOperation([]), putchar_call(52, 5))]),
            BasicBlock(12, [Assignment(ListOperation([]), putchar_call(50, 6))]),
            BasicBlock(14, [Assignment(ListOperation([]), putchar_call(51, 7))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(i, Integer(32)) for i in (1, 3, 5, 7, 9)]),
            SwitchCase(vertices[1], vertices[3], [Constant(0, Integer(32))]),
            SwitchCase(vertices[1], vertices[4], [Constant(2, Integer(32))]),
            SwitchCase(vertices[1], vertices[5], [Constant(4, Integer(32))]),
            SwitchCase(vertices[1], vertices[6], [Constant(6, Integer(32))]),
            SwitchCase(vertices[1], vertices[7], [Constant(8, Integer(32))]),
            SwitchCase(vertices[1], vertices[8], [Constant(10, Integer(32))]),
            UnconditionalEdge(vertices[2], vertices[9]),
            TrueCase(vertices[3], vertices[10]),
            FalseCase(vertices[3], vertices[11]),
            FalseCase(vertices[4], vertices[12]),
            TrueCase(vertices[4], vertices[9]),
            UnconditionalEdge(vertices[5], vertices[9]),
            UnconditionalEdge(vertices[6], vertices[9]),
            UnconditionalEdge(vertices[7], vertices[9]),
            UnconditionalEdge(vertices[8], vertices[9]),
            UnconditionalEdge(vertices[10], vertices[9]),
            UnconditionalEdge(vertices[11], vertices[9]),
            UnconditionalEdge(vertices[12], vertices[9]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[9].instructions

    # switch node:
    assert (
        switch.expression == BinaryOperation(OperationType.minus, [var_0, Constant(4, Integer(32, True))], Integer(32, True))
        and len(switch.children) == 7
    )
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(0, Integer(32)) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer(32)) and case2.break_case is True
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(4, Integer(32)) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(6, Integer(32)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(8, Integer(32)) and case5.break_case is True
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(10, Integer(32)) and case6.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(cond_node1 := case1.child, ConditionNode)
    assert isinstance(cond_node1.true_branch.child, CodeNode) and isinstance(cond_node1.false_branch.child, CodeNode)
    if cond_node1.condition.is_symbol:
        assert task._ast.condition_map[cond_node1.condition] == vertices[3].instructions[0].condition
        assert cond_node1.true_branch_child.instructions == vertices[10].instructions
        assert cond_node1.false_branch_child.instructions == vertices[11].instructions
    else:
        assert task._ast.condition_map[~cond_node1.condition] == vertices[3].instructions[0].condition
        assert cond_node1.true_branch_child.instructions == vertices[11].instructions
        assert cond_node1.false_branch_child.instructions == vertices[10].instructions

    assert isinstance(cond_node2 := case2.child, ConditionNode)
    assert isinstance(cond_node2.true_branch.child, CodeNode) and cond_node2.false_branch is None
    assert cond_node2.condition.is_negation and (~cond_node2.condition).is_symbol
    assert task._ast.condition_map[~cond_node2.condition] == vertices[4].instructions[0].condition
    assert cond_node2.true_branch_child.instructions == vertices[12].instructions

    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[5].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[6].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[7].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[8].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions


def test_switch_in_switch_easy(task):
    """
        test_switch test 4
                                                           +--------------------------------------------------------------------------+
                                                       |                                    0.                                    |
                                                       |                       printf("Enter any number: ")                       |
                                                       |                             var_1 = &(var_0)                             |
                                                       |                     __isoc99_scanf(0x804b025, var_1)                     |
                                                       | if(((unsigned int) (byte) (var_0 & 0xffffff00) || (var_0 > 0x0)) == 0x0) | -+
                                                       +--------------------------------------------------------------------------+  |
                                                         |                                                                           |
                                                         |                                                                           |
                                                         v                                                                           |
    +----------------------------------+               +--------------------------------------------------------------------------+  |
    |                6.                |               |                                    2.                                    |  |
    | printf("%d is positive.", var_0) | <------------ | if(((unsigned int) (byte) (var_0 & 0xffffff00) || (var_0 > 0x0)) != 0x1) |  |
    +----------------------------------+               +--------------------------------------------------------------------------+  |
      |                                                  |                                                                           |
      |                                             +----+                                                                           |
      |                                             |                                                                                |
      |                                             |  +--------------------------------------------------------------------------+  |
      |                                             |  |                                    1.                                    |  |
      |                                        +----+- |        if(((unsigned int) (unsigned byte) var_0 u>> 0x1f) == 0x0)        | <+
      |                                        |    |  +--------------------------------------------------------------------------+
      |                                        |    |    |
      |                                        |    |    |
      |                                        |    |    v
      |                                        |    |  +--------------------------------------------------------------------------+               +----------------------------------+
      |                                        |    |  |                                    4.                                    |               |                9.                |
      |                                        |    |  |        if(((unsigned int) (unsigned byte) var_0 u>> 0x1f) != 0x1)        | ------+    +> | printf("%d is negative.", var_0) |
      |                                        |    |  +--------------------------------------------------------------------------+       |    |  +----------------------------------+
      |                                        |    |    |                                                                                |    |    |
      |                                        |    |    +--------------------------------------------------------------------------------+----+    |
      |                                        |    |                                                                                     |         |
      |                                        |    |  +--------------------------------------------------------------------------+       |         |
      |                                        |    |  |                                    3.                                    |       |         |
      |                                        +----+> |                       printf("%d is zero.", var_0)                       |       |         |
      |                                             |  +--------------------------------------------------------------------------+       |         |
      |                                             |    |                                                                                |         |
      |                                             |    |                                                                                |         |
      |                                             |    v                                                                                v         |
      |                                             |  +------------------------------------------------------------------------------------+       |
      |                                             +> |                                                                                    | <-----+
      |                                                |                                        10.                                         |
      |                                                |                                     return 0x0                                     |
      +----------------------------------------------> |                                                                                    |
                                                       +------------------------------------------------------------------------------------+
    """
    var_0 = Variable("var_0", Pointer(Integer(32, True), 32), None, True, Variable("var_10", Pointer(Integer(32, True), 32), 0, True, None))
    switch_expr_2 = UnaryOperation(
        OperationType.cast,
        [
            UnaryOperation(
                OperationType.cast,
                [BinaryOperation(OperationType.right_shift_us, [var_0, Constant(31, Integer(32, True))], Integer(32, False))],
                Integer(8, False),
                None,
                False,
            )
        ],
        Integer(32, False),
        None,
        False,
    )
    switch_expr_1 = UnaryOperation(
        OperationType.cast,
        [
            UnaryOperation(
                OperationType.cast,
                [
                    BinaryOperation(
                        OperationType.logical_or,
                        [
                            BinaryOperation(OperationType.logical_and, [var_0, Constant(4294967040, UnknownType())], CustomType("bool", 1)),
                            Condition(OperationType.greater, [var_0, Constant(0, Integer(32, True))], CustomType("bool", 1)),
                        ],
                        Integer(32, True),
                    )
                ],
                Integer(8, True),
                None,
                False,
            )
        ],
        Integer(32, False),
        None,
        False,
    )
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter any number: ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.equal, [switch_expr_1, Constant(0, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.equal, [switch_expr_2, Constant(0, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                2, [Branch(Condition(OperationType.not_equal, [switch_expr_1, Constant(1, Integer(32, True))], CustomType("bool", 1)))]
            ),
            BasicBlock(
                3,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [Constant("%d is zero.", Pointer(Integer(8, False), 32)), var_0],
                            Pointer(CustomType("void", 0), 32),
                            3,
                        ),
                    )
                ],
            ),
            BasicBlock(
                4, [Branch(Condition(OperationType.not_equal, [switch_expr_2, Constant(1, Integer(32, True))], CustomType("bool", 1)))]
            ),
            BasicBlock(
                6,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [Constant("%d is positive.", Pointer(Integer(8, False), 32)), var_0],
                            Pointer(CustomType("void", 0), 32),
                            6,
                        ),
                    )
                ],
            ),
            BasicBlock(
                9,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [Constant("%d is negative.", Pointer(Integer(8, False), 32)), var_0],
                            Pointer(CustomType("void", 0), 32),
                            4,
                        ),
                    )
                ],
            ),
            BasicBlock(10, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[1], vertices[4]),
            FalseCase(vertices[2], vertices[5]),
            TrueCase(vertices[2], vertices[7]),
            UnconditionalEdge(vertices[3], vertices[7]),
            FalseCase(vertices[4], vertices[6]),
            TrueCase(vertices[4], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[7]),
            UnconditionalEdge(vertices[6], vertices[7]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    assert switch.expression == switch_expr_1 and len(switch.children) == 2
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(0, Integer(32, True)) and case1.break_case is True
    assert isinstance(inner_switch := case1.child, SwitchNode)
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(1, Integer(32, True)) and case2.break_case is True
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[5].instructions

    # inner switch
    assert inner_switch.expression == switch_expr_2 and len(inner_switch.children) == 2
    assert (
        isinstance(case1 := inner_switch.cases[0], CaseNode)
        and case1.constant == Constant(0, Integer(32, True))
        and case1.break_case is True
    )
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[3].instructions
    assert (
        isinstance(case2 := inner_switch.cases[1], CaseNode)
        and case2.constant == Constant(1, Integer(32, True))
        and case2.break_case is True
    )
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[6].instructions


def test_switch_in_switch_long(task):
    """
      test_switch test 20
                                                                                                                                                                                                                                   +----------------------------+
                                                                                                                                                                                                                                   |            26.             |
                                                                                                                                                                                                                                   | printf("Thursday evening") | --------------------------------------+
                                                                                                                                                                                                                                   +----------------------------+                                       |
                                                                                                                                                                                                                                     ^                                                                  |
         +-------------------------------------------+                                                                                                                                                                               |                                                                  |
         |                                           |                                                                                                                                                                               |                                                                  |
         |                                           |                                                                    +------------------------------------+     +-----------------------------+                                 |                                                                  |
         |                                           |                                                                    |                 9.                 |     |             14.             |                                 |                                                                  |
         |    +--------------------------------------+------------------------------------------------------------------- |         printf("Saturday")         | <+  | printf("Thursday midnight") | --------------------------------+-------------------------------------------------------------+    |
         |    |                                      |                                                                    +------------------------------------+  |  +-----------------------------+                                 |                                                             |    |
         |    |                                      |                                                                                                            |    ^                                                             |                                                             |    |
         |    |                                      |                                                                                                            |    |                                                             |                                                             |    |
         |    |                                      v                                                                                                            |    |                                                             |                                                             |    |
         |    |                                    +----------------------------------------------------------------+     +------------------------------------+  |  +-----------------------------+     +-------------------+     +----------------------------+     +--------------------+       |    |
         |    |                                    |                                                                |     |                 0.                 |  |  |                             |     |                   |     |                            |     |                    |       |    |
         |    |                                    |                                                                |     | printf("Enter week number(1-7): ") |  |  |                             |     |                   |     |                            |     |                    |       |    |
         |    |                                    |                                                                |     |          var_2 = &(var_0)          |  |  |                             |     |                   |     |                            |     |                    |       |    |
         |    |                                    |                               3.                               |     |  __isoc99_scanf(0x804b025, var_2)  |  |  |             7.              |     |        15.        |     |            21.             |     |        27.         |       |    |
         |    |                                    | printf("Invalid input! Please enter week number between 1-7.") |     |   printf("Enter a time (1-4): ")   |  |  |      if(var_1 == 0x4)       |     |  if(var_1 > 0x4)  |     |      if(var_1 == 0x3)      |     |  if(var_1 > 0x3)   |       |    |
         |    |                                    |                                                                |     |          var_2 = &(var_1)          |  |  |                             |     |                   |     |                            |     |                    |       |    |
         |    |                                    |                                                                |     |  __isoc99_scanf(0x804b025, var_2)  |  |  |                             |     |                   |     |                            |     |                    |       |    |
         |    |                                    |                                                                | <-- |          if(var_0 u> 0x7)          |  |  |                             | --> |                   | --> |                            | --> |                    | -+    |    |
         |    |                                    +----------------------------------------------------------------+     +------------------------------------+  |  +-----------------------------+     +-------------------+     +----------------------------+     +--------------------+  |    |    |
         |    |                                      |                                                                      |                                     |    ^                                   |                                                            |                     |    |    |
         |    |                                      |                                                                      |                                     |    |                                   +-------------------------------------------------------+    |                     |    |    |
         |    |                                      |                                                                      v                                     |    |                                                                                           |    v                     |    |    |
         |    |  +---------------------------+       |                                                                    +--------------------------------------------------------------------------------------------------+     +----------------------------+  |  +--------------------+  |    |    |
         |    |  |            8.             |       |                                                                    |                                                                                                  |     |             6.             |  |  |        31.         |  |    |    |
         |    |  |     printf("Friday")      | <-----+------------------------------------------------------------------- |                                                                                                  | --> |    printf("Wednesday")     |  |  |  if(var_1 == 0x1)  | -+----+----+----+
         |    |  +---------------------------+       |                                                                    |                                                                                                  |     +----------------------------+  |  +--------------------+  |    |    |    |
         |    |    |                                 |                                                                    |                                                2.                                                |       |                             |    |                     |    |    |    |
         |    |    |                            +----+------------------------------------------------------------------- |                                            jmp var_0                                             |       |                             |    |                     |    |    |    |
         |    |    |                            |    |                                                                    |                                                                                                  |       |                             |    v                     |    |    |    |
         |    |    |                            |    |                                                                    |                                                                                                  |       |                             |  +--------------------+  |    |    |    |
         |    |    |                            |    |                                                                    |                                                                                                  |       |                             |  |        35.         |  |    |    |    |
         +----+----+----------------------------+    |                                                                    |                                                                                                  |       |                             |  |  if(var_1 == 0x2)  | -+----+----+----+----+
              |    |                                 |                                                                    +--------------------------------------------------------------------------------------------------+       |                             |  +--------------------+  |    |    |    |    |
              |    |                                 |                                                                      |                                          |                                   |                         |                             |    |                     |    |    |    |    |
              |    |                                 |                                                                      |                                          |                                   |                         |                             |    |                     |    |    |    |    |
              |    |                                 |                                                                      v                                          v                                   v                         |                             |    v                     |    |    |    |    |
              |    |                                 |                                                                    +------------------------------------+     +-----------------------------+     +-------------------+       |                             |  +--------------------+  |    |    |    |    |
              |    |                                 |                                                                    |                 4.                 |     |             10.             |     |        5.         |       |                             |  |        25.         |  |    |    |    |    |
              |    |                                 |                                                                 +- |          if(var_1 == 0x4)          |     |      printf("Sunday")       |     | printf("Tuesday") |       |                             +> | printf("Thursday") | <+    |    |    |    |
              |    |                                 |                                                                 |  +------------------------------------+     +-----------------------------+     +-------------------+       |                                +--------------------+       |    |    |    |
              |    |                                 |                                                                 |    |                                          |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |    |                                          |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |    v                                          |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |  +------------------------------------+       |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |  |                13.                 |       |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |  |          if(var_1 > 0x4)           | -+    |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |  +------------------------------------+  |    |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |    |                                     |    |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |    |                                     |    |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |    v                                     |    |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |  +------------------------------------+  |    |                                   |                         |                                  |                          |    |    |    |
              |    |                                 |                                                                 |  |                18.                 |  |    |                                   |                         |                                  |                          |    |    |    |
              |    |                            +----+-----------------------------------------------------------------+  |          if(var_1 == 0x3)          | -+----+------------------------------+    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                    +------------------------------------+  |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                      |                                     |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                      |                                     |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                      v                                     |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                    +------------------------------------+  |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                    |                24.                 |  |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                 +- |          if(var_1 > 0x3)           |  |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                 |  +------------------------------------+  |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                 |    |                                     |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                 |    |                                     |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                 |    v                                     |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                 |  +------------------------------------+  |    |                              |    |                         |                                  |                          |    |    |    |
              |    |                            |    |                                                                 |  |                29.                 |  |    |                              |    |                         |                                  |                          |    |    |    |
         +----+----+----------------------------+----+-----------------------------------------------------------------+- |          if(var_1 == 0x1)          |  |    |                              |    |                         |                                  |                          |    |    |    |
         |    |    |                            |    |                                                                 |  +------------------------------------+  |    |                              |    |                         |                                  |                          |    |    |    |
         |    |    |                            |    |                                                                 |    |                                     |    |                              |    |                         |                                  |                          |    |    |    |
         |    |    |                            |    |                                                                 |    |                                     |    |                              |    |                         |                                  |                          |    |    |    |
         |    |    |                            |    |                                                                 |    v                                     |    |                              |    |                         |                                  |                          |    |    |    |
         |    |    |                            |    |                                                                 |  +------------------------------------+  |    |                              |    |                         |                                  |                          |    |    |    |
         |    |    |                            |    |                                                                 |  |                33.                 |  |    |                              |    |                         |                                  |                          |    |    |    |
    +----+----+----+----------------------------+----+-----------------------------------------------------------------+- |          if(var_1 == 0x2)          |  |    |                              |    |                         |                                  |                          |    |    |    |
    |    |    |    |                            |    |                                                                 |  +------------------------------------+  |    |                              |    |                         |                                  |                          |    |    |    |
    |    |    |    |                            |    |                                                                 |    |                                     |    |                              |    |                         |                                  |                          |    |    |    |
    |    |    |    |                            |    |                                                                 |    |                                     |    |                              |    |                         |                                  |                          |    |    |    |
    |    |    |    |                            |    |                                                                 |    v                                     |    |                              |    |                         |                                  |                          |    |    |    |
    |    |    |    |                            |    |                                                                 |  +------------------------------------+  |    |                              |    |                         |                                  |                          |    |    |    |
    |    |    |    |                            |    |                                                                 |  |                22.                 |  |    |                              |    |                         |                                  |                          |    |    |    |
    |    |    |    |                            |    |                                                                 +> |          printf("Monday")          | <+    |                              +----+-------------------------+----------------------------------+--------------------------+----+----+----+----+
    |    |    |    |                            |    |                                                                    +------------------------------------+       |                                   |                         |                                  |                          |    |    |    |    |
    |    |    |    |                            |    |                                                                      |                                          |                                   |                         |                                  |                          |    |    |    |    |
    |    |    |    |                            |    |                                                                      |                                          |                                   |                         |                                  |                          |    |    |    |    |
    |    |    |    |                            |    |                                                                      v                                          v                                   v                         v                                  v                          v    |    |    |    |
    |    |    |    |                            |    |                                                                    +--------------------------------------------------------------------------------------------------------------------------------------------------------------------------+  |    |    |    |
    |    |    |    |                            |    +------------------------------------------------------------------> |                                                                                                                                                                          | <+    |    |    |
    |    |    |    |                            |                                                                         |                                                                                                                                                                          |       |    |    |
    |    |    |    |                            |                                                                         |                                                                                                                                                                          |       |    |    |
    |    |    |    +----------------------------+-----------------------------------------------------------------------> |                                                                                                                                                                          |       |    |    |
    |    |    |                                 |                                                                         |                                                                                                                                                                          |       |    |    |
    |    |    |                                 |  +----------------------------------------------------------------+     |                                                                                                                                                                          |       |    |    |
    |    |    |                                 |  |                              38.                               |     |                                                                                                                                                                          |       |    |    |
    |    |    |                                 |  |                  printf("Thursday afternoon")                  | --> |                                                                                                                                                                          |       |    |    |
    |    |    |                                 |  +----------------------------------------------------------------+     |                                                                                                                                                                          |       |    |    |
    |    |    |                                 |    ^                                                                    |                                                                                                                                                                          |       |    |    |
    |    |    |                                 |    |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |    |                                 |    |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |    |                                 |    |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |    +---------------------------------+----+------------------------------------------------------------------> |                                                                                   11.                                                                                    |       |    |    |
    |    |                                      |    |                                                                    |                                                                                return 0x0                                                                                |       |    |    |
    |    |                                      |    |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |         +----------------------------+    |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |         v                                 |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |       +---------------------------+       |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |       |            12.            |       |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |       | printf("Monday midnight") | ------+------------------------------------------------------------------> |                                                                                                                                                                          |       |    |    |
    |    |       +---------------------------+       |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |                                           |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |    +--------------------------------------+------------------------------------------------------------------> |                                                                                                                                                                          |       |    |    |
    |    |    |                                      |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |    |  +---------------------------+       |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |    |  |            23.            |       |                                                                    |                                                                                                                                                                          |       |    |    |
    |    |    |  | printf("Monday evening")  | ------+------------------------------------------------------------------> |                                                                                                                                                                          |       |    |    |
    |    |    |  +---------------------------+       |                                                                    +--------------------------------------------------------------------------------------------------------------------------------------------------------------------------+       |    |    |
    |    |    |    ^                                 |                                                                      ^                                          ^                                                                                                                                     |    |    |
    |    |    |    |                                 |                                                                      |                                          |                                                                                                                                     |    |    |
    |    |    |    |                                 |                                                                      |                                          |                                                                                                                                     |    |    |
    |    |    |    |                                 |                                                                    +------------------------------------+       |                                                                                                                                     |    |    |
    |    |    |    |                                 |                                                                    |                34.                 |       |                                                                                                                                     |    |    |
    |    |    |    |                                 |                                                                    |     printf("Thursday morning")     | <-----+-------------------------------------------------------------------------------------------------------------------------------------+    |    |
    |    |    |    |                                 |                                                                    +------------------------------------+       |                                                                                                                                          |    |
    |    |    |    |                                 |                                                                                                                 |                                                                                                                                          |    |
    |    |    |    |                                 +-----------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+    |
    |    |    |    |                                                                                                                                                   |                                                                                                                                               |
    |    |    |    |                                                                                                                                                   |                                                                                                                                               |
    |    |    |    +---------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
    |    |    |                                                                                                                                                        |
    |    |    |                                                                                                           +------------------------------------+       |
    |    |    |                                                                                                           |                32.                 |       |
    |    |    +---------------------------------------------------------------------------------------------------------- |      printf("Monday morning")      |       |
    |    |                                                                                                                +------------------------------------+       |
    |    |                                                                                                                  ^                                          |
    |    +------------------------------------------------------------------------------------------------------------------+                                          |
    |                                                                                                                                                                  |
    |                                                                                                                     +------------------------------------+       |
    |                                                                                                                     |                36.                 |       |
    +-------------------------------------------------------------------------------------------------------------------> |     printf("Monday afternoon")     | ------+
                                                                                                                          +------------------------------------+

    """
    var_0, var_1, vertices = _switch_in_switch(task)

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[10].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32)) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer(32)) and case2.break_case is True
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(3, Integer(32)) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(4, Integer(32)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(5, Integer(32)) and case5.break_case is True
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(6, Integer(32)) and case6.break_case is True
    assert isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(7, Integer(32)) and case7.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(switch_mo := case1.child, SwitchNode)
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[4].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[5].instructions
    assert isinstance(switch_th := case4.child, SwitchNode)
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[7].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[8].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[9].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions

    # inner switches:
    for switch, offset in [(switch_mo, 0), (switch_th, 1)]:
        assert switch.expression == var_1 and len(switch.children) == 5
        assert (
            isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32, True)) and case1.break_case is True
        )
        assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[25 + 2 * offset].instructions
        assert (
            isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer(32, True)) and case2.break_case is True
        )
        assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[29 + offset].instructions
        assert (
            isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(3, Integer(32, True)) and case3.break_case is True
        )
        assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[18 + 3 * offset].instructions
        assert (
            isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(4, Integer(32, True)) and case4.break_case is True
        )
        assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[11 + 2 * offset].instructions
        assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False
        assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[17 + 3 * offset].instructions


@pytest.mark.skip("Not implemented yet")
def test_switch_in_switch_complicated(task):
    """test_switch test 20b -> later"""
    pass


def test_switch_only_if_else(task):
    """
        test_condition test6
                                +------------------+     +----------------------------------------------------------------+
                                |                  |     |                               0.                               |
                                |                  |     |                    __x86.get_pc_thunk.bx()                     |
                                |        2.        |     |              printf("Enter week number (1-7): ")               |
                                | printf("Monday") |     |                        var_1 = &(var_0)                        |
                                |                  |     |                  __isoc99_scanf("%d", var_1)                   |
                                |                  | <-- |                        if(var_0 != 0x1)                        |
                                +------------------+     +----------------------------------------------------------------+
                                  |                        |
                                  |                        |
                                  |                        v
                                  |                      +----------------------------------------------------------------+     +--------------------+
                                  |                      |                               1.                               |     |         4.         |
                                  |                      |                        if(var_0 != 0x2)                        | --> | printf("Tuesday")  |
                                  |                      +----------------------------------------------------------------+     +--------------------+
                                  |                        |                                                                      |
                                  |                        |                                                                      |
                                  |                        v                                                                      |
    +---------------------+       |                      +----------------------------------------------------------------+       |
    |         7.          |       |                      |                               3.                               |       |
    | printf("Wednesday") | <-----+--------------------- |                        if(var_0 != 0x3)                        |       |
    +---------------------+       |                      +----------------------------------------------------------------+       |
      |                           |                        |                                                                      |
      |                           |                        |                                                                      |
      |                           |                        v                                                                      |
      |                           |                      +----------------------------------------------------------------+       |                        +--------------------+
      |                           |                      |                               6.                               |       |                        |         9.         |
      |                           |                      |                        if(var_0 != 0x4)                        | ------+----------------------> | printf("Thursday") |
      |                           |                      +----------------------------------------------------------------+       |                        +--------------------+
      |                           |                        |                                                                      |                          |
      |                           |                        |                                                                      |                          |
      |                           |                        v                                                                      |                          |
      |                           |                      +----------------------------------------------------------------+       |                          |
      |                           |                      |                               8.                               |       |                          |
      |                           |                   +- |                        if(var_0 != 0x5)                        |       |                          |
      |                           |                   |  +----------------------------------------------------------------+       |                          |
      |                           |                   |    |                                                                      |                          |
      |                           |                   |    |                                                                      |                          |
      |                           |                   |    v                                                                      |                          |
      |                           |                   |  +----------------------------------------------------------------+       |                          |
      |                           |                   |  |                              10.                               |       |                          |
      |                           |                   |  |                        if(var_0 != 0x6)                        | -+    |                          |
      |                           |                   |  +----------------------------------------------------------------+  |    |                          |
      |                           |                   |    |                                                                 |    |                          |
      |                           |                   |    |                                                                 |    |                          |
      |                           |                   |    v                                                                 |    |                          |
      |                           |                   |  +----------------------------------------------------------------+  |    |                          |
      |                           |                   |  |                              12.                               |  |    |                          |
      |                           |                   |  |                        if(var_0 != 0x7)                        | -+----+--------------------------+--------------------------+
      |                           |                   |  +----------------------------------------------------------------+  |    |                          |                          |
      |                           |                   |    |                                                                 |    |                          |                          |
      |                           |                   |    |                                                                 |    |                          |                          |
      |                           |                   |    v                                                                 |    |                          |                          |
      |                           |                   |  +----------------------------------------------------------------+  |    |                          |                          |
      |                           |                   |  |                              14.                               |  |    |                          |                          |
      |                           |                   |  | printf("Invalid Input! Please enter week number between 1-7.") |  +----+--------------------------+---------------------+    |
      |                           |                   |  +----------------------------------------------------------------+       |                          |                     |    |
      |                           |                   |    |                                                                      |                          |                     |    |
      |                      +----+-------------------+    |                                                                      |                          |                     |    |
      |                      |    |                        v                                                                      v                          v                     |    |
      |                      |    |                      +----------------------------------------------------------------------------------------------------------------------+  |    |
      |                      |    +--------------------> |                                                                                                                      |  |    |
      |                      |                           |                                                          5.                                                          |  |    |
      |                      |                           |                                                      return 0x0                                                      |  |    |
      +----------------------+-------------------------> |                                                                                                                      |  |    |
                             |                           +----------------------------------------------------------------------------------------------------------------------+  |    |
                             |                             ^                                                                      ^                          ^                     |    |
                             |                             |                                                                      |                          |                     |    |
                             |                             |                                                                      |                          |                     |    |
                             |                           +----------------------------------------------------------------+     +--------------------+       |                     |    |
                             |                           |                              11.                               |     |        13.         |       |                     |    |
                             +-------------------------> |                        printf("Friday")                        |     | printf("Saturday") | <-----+---------------------+    |
                                                         +----------------------------------------------------------------+     +--------------------+       |                          |
                                                         +----------------------------------------------------------------+                                  |                          |
                                                         |                              15.                               |                                  |                          |
                                                         |                        printf("Sunday")                        | ---------------------------------+                          |
                                                         +----------------------------------------------------------------+                                                             |
                                                           ^                                                                                                                            |
                                                           +----------------------------------------------------------------------------------------------------------------------------+
    """
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.not_equal, [var_1, Constant(1, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.not_equal, [var_1, Constant(2, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(2, [Branch(Condition(OperationType.not_equal, [var_1, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(3, [Branch(Condition(OperationType.not_equal, [var_1, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(4, [Branch(Condition(OperationType.not_equal, [var_1, Constant(5, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(5, [Branch(Condition(OperationType.not_equal, [var_1, Constant(6, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(6, [Branch(Condition(OperationType.not_equal, [var_1, Constant(7, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 14))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Monday", 3))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Tuesday", 5))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Wednesday", 6))]),
            BasicBlock(11, [Assignment(ListOperation([]), print_call("Thursday", 8))]),
            BasicBlock(12, [Assignment(ListOperation([]), print_call("Friday", 9))]),
            BasicBlock(13, [Assignment(ListOperation([]), print_call("Saturday", 11))]),
            BasicBlock(14, [Assignment(ListOperation([]), print_call("Sunday", 13))]),
            BasicBlock(15, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[8]),
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[1], vertices[9]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[2], vertices[10]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[3], vertices[11]),
            TrueCase(vertices[3], vertices[4]),
            FalseCase(vertices[4], vertices[12]),
            TrueCase(vertices[4], vertices[5]),
            FalseCase(vertices[5], vertices[13]),
            TrueCase(vertices[5], vertices[6]),
            FalseCase(vertices[6], vertices[14]),
            TrueCase(vertices[6], vertices[7]),
            UnconditionalEdge(vertices[7], vertices[15]),
            UnconditionalEdge(vertices[8], vertices[15]),
            UnconditionalEdge(vertices[9], vertices[15]),
            UnconditionalEdge(vertices[10], vertices[15]),
            UnconditionalEdge(vertices[11], vertices[15]),
            UnconditionalEdge(vertices[12], vertices[15]),
            UnconditionalEdge(vertices[13], vertices[15]),
            UnconditionalEdge(vertices[14], vertices[15]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    assert switch.expression == var_1 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32, True)) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer(32, True)) and case2.break_case is True
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(3, Integer(32, True)) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(4, Integer(32, True)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(5, Integer(32, True)) and case5.break_case is True
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(6, Integer(32, True)) and case6.break_case is True
    assert isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(7, Integer(32, True)) and case7.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[8].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[9].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[10].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[11].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[12].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[13].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[14].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[7].instructions


def test_switch_find_case_in_condition(task):
    """test_condition test6d"""
    var_0_2 = Variable("var_0", Pointer(Integer(32, True), 32), None, False, Variable("var_10", Integer(32, True), 0, True, None))
    var_0_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(
                        ListOperation([]),
                        scanf_call(UnaryOperation(OperationType.address, [var_0_0], Pointer(Integer(32, True), 32), None, False), "%d", 2),
                    ),
                    Branch(Condition(OperationType.not_equal, [var_0_2, Constant(1, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.equal, [var_0_2, Constant(2, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(2, [Assignment(ListOperation([]), print_call("Monday", 3))]),
            BasicBlock(4, [Branch(Condition(OperationType.equal, [var_0_2, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(5, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Wednesday", 6))]),
            BasicBlock(7, [Branch(Condition(OperationType.not_equal, [var_0_2, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(8, [Branch(Condition(OperationType.equal, [var_0_2, Constant(5, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Thursday", 8))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Friday", 9))]),
            BasicBlock(11, [Branch(Condition(OperationType.not_equal, [var_0_2, Constant(6, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(12, [Branch(Condition(OperationType.equal, [var_0_2, Constant(7, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(13, [Assignment(ListOperation([]), print_call("Saturday", 11))]),
            BasicBlock(14, [Assignment(ListOperation([]), print_call("Sunday", 13))]),
            BasicBlock(15, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 14))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[4]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[4]),
            TrueCase(vertices[3], vertices[5]),
            FalseCase(vertices[3], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[4]),
            TrueCase(vertices[6], vertices[7]),
            FalseCase(vertices[6], vertices[8]),
            TrueCase(vertices[7], vertices[9]),
            FalseCase(vertices[7], vertices[10]),
            UnconditionalEdge(vertices[8], vertices[4]),
            UnconditionalEdge(vertices[9], vertices[4]),
            TrueCase(vertices[10], vertices[11]),
            FalseCase(vertices[10], vertices[12]),
            TrueCase(vertices[11], vertices[13]),
            FalseCase(vertices[11], vertices[14]),
            UnconditionalEdge(vertices[12], vertices[4]),
            UnconditionalEdge(vertices[13], vertices[4]),
            UnconditionalEdge(vertices[14], vertices[4]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch_cond := seq_node.children[1], ConditionNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[4].instructions

    # switch condition:
    assert switch_cond.false_branch is None and isinstance(switch := switch_cond.true_branch_child, SwitchNode)
    assert switch_cond.condition.is_literal and not switch_cond.condition.is_symbol
    assert task._ast.condition_map[~switch_cond.condition] == vertices[1].instructions[-1].condition

    # switch node:
    assert switch.expression == var_0_2 and len(switch.children) == 7
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32, True)) and case1.break_case is True
    assert isinstance(case3 := switch.cases[1], CaseNode) and case3.constant == Constant(3, Integer(32, True)) and case3.break_case is True
    assert isinstance(case4 := switch.cases[2], CaseNode) and case4.constant == Constant(4, Integer(32, True)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[3], CaseNode) and case5.constant == Constant(5, Integer(32, True)) and case5.break_case is True
    assert isinstance(case6 := switch.cases[4], CaseNode) and case6.constant == Constant(6, Integer(32, True)) and case6.break_case is True
    assert isinstance(case7 := switch.cases[5], CaseNode) and case7.constant == Constant(7, Integer(32, True)) and case7.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[2].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[5].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[8].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[9].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[12].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[13].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[14].instructions


def test_two_entries_to_one_case(task):
    """
        test_switch test14b
      +------------------------------------------------------------------------------------------------------------+
      v                                                                                                            |
    +----------------------------------------------------------------+     +------------------------------------+  |
    |                                                                |     |                 0.                 |  |
    |                               3.                               |     | printf("Enter week number(1-7): ") |  |
    | printf("Invalid input! Please enter week number between 1-7.") |     |          var_1 = &(var_0)          |  |
    |                                                                |     |  __isoc99_scanf(0x804b025, var_1)  |  |
    |                                                                | <-- |          if(var_0 u> 0x7)          |  |
    +----------------------------------------------------------------+     +------------------------------------+  |
      |                                                                      |                                     |
      |                                                                      |                                     |
      |                                                                      v                                     |
      |                                                                    +--------------------------------------------------------------------------+     +------------------+
      |                                                                    |                                                                          |     |        8.        |
      |                                                                    |                                                                          | --> | printf("Friday") |
      |                                                                    |                                                                          |     +------------------+
      |                                                                    |                                    2.                                    |       |
      |                                                                    |                                jmp var_0                                 |       |
      |                                                                    |                                                                          |       |
      |                                                                    |                                                                          |       |
      |                                                                 +- |                                                                          |       |
      |                                                                 |  +--------------------------------------------------------------------------+       |
      |                                                                 |    |                                     |    |    |    |                           |
      |                                                                 |    |                                     |    |    |    |                           |
      |                                                                 |    v                                     |    |    |    v                           |
      |                                                                 |  +------------------------------------+  |    |    |  +---------------------+       |
      |                                                                 |  |                 4.                 |  |    |    |  |         6.          |       |
      |                                                                 |  |          printf("Monday")          |  |    |    |  | printf("Wednesday") |       |
      |                                                                 |  +------------------------------------+  |    |    |  +---------------------+       |
      |                                                                 |    |                                     |    |    |    |                           |
      |                                                                 |    |                                     |    |    |    |                           |
      |                                                                 |    v                                     |    |    |    v                           |
      |                                                                 |  +------------------------------------+  |    |    |  +---------------------+       |
      |                                                                 |  |                 5.                 |  |    |    |  |         7.          |       |
      |                                                                 |  |         printf("Tuesday")          | <+    |    +> | printf("Thursday")  |       |
      |                                                                 |  +------------------------------------+       |       +---------------------+       |
      |                                                                 |    |                                          |         |                           |
      |                                                                 |    |                                          |         |                           |
      |                                                                 |    v                                          |         |                           |
      |                                                                 |  +------------------------------------+       |         |                           |
      |                                                                 |  |                 9.                 |       |         |                           |
      |                                                                 +> |         printf("Saturday")         | <-----+---------+                           |
      |                                                                    +------------------------------------+       |                                     |
      |                                                                      |                                          |                                     |
      |                                                                      |                                          |                                     |
      |                                                                      v                                          |                                     |
      |                                                                    +------------------------------------+       |                                     |
      |                                                                    |                10.                 |       |                                     |
      |                                                                    |          printf("Sunday")          | <-----+                                     |
      |                                                                    +------------------------------------+                                             |
      |                                                                      |                                                                                |
      |                                                                      |                                                                                |
      |                                                                      v                                                                                |
      |                                                                    +------------------------------------+                                             |
      |                                                                    |                11.                 |                                             |
      +------------------------------------------------------------------> |             return 0x0             | <-------------------------------------------+
                                                                           +------------------------------------+
    """
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(7, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 14))]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("Monday", 3))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("Tuesday", 5))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Wednesday", 6))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Thursday", 8))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Friday", 9))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Saturday", 11))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Sunday", 13))]),
            BasicBlock(11, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(0, Integer(32))]),
            SwitchCase(vertices[1], vertices[3], [Constant(1, Integer(32))]),
            SwitchCase(vertices[1], vertices[4], [Constant(2, Integer(32))]),
            SwitchCase(vertices[1], vertices[5], [Constant(3, Integer(32))]),
            SwitchCase(vertices[1], vertices[6], [Constant(4, Integer(32))]),
            SwitchCase(vertices[1], vertices[7], [Constant(5, Integer(32))]),
            SwitchCase(vertices[1], vertices[8], [Constant(6, Integer(32))]),
            SwitchCase(vertices[1], vertices[9], [Constant(7, Integer(32))]),
            UnconditionalEdge(vertices[2], vertices[10]),
            UnconditionalEdge(vertices[3], vertices[4]),
            UnconditionalEdge(vertices[4], vertices[8]),
            UnconditionalEdge(vertices[5], vertices[6]),
            UnconditionalEdge(vertices[6], vertices[8]),
            UnconditionalEdge(vertices[7], vertices[10]),
            UnconditionalEdge(vertices[8], vertices[9]),
            UnconditionalEdge(vertices[9], vertices[10]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32)) and case1.break_case is False
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer(32)) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(3, Integer(32)) and case3.break_case is False
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(4, Integer(32)) and case4.break_case is False
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(6, Integer(32)) and case5.break_case is False
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(7, Integer(32)) and case6.break_case is True
    assert isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(5, Integer(32)) and case7.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[3].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[4].instructions
    assert isinstance(cond_1 := case3.child, ConditionNode)
    assert isinstance(cond_2 := case4.child, ConditionNode)
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[8].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[9].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[7].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions

    # condition nodes:
    for cond, child in [(cond_1, 5), (cond_2, 6)]:
        assert (
            cond.condition.is_conjunction and len(operands := cond.condition.operands) == 2 and all(operands[i].is_negation for i in [0, 1])
        )
        term_1 = task._ast.condition_map[~operands[0]]
        term_2 = task._ast.condition_map[~operands[1]]
        assert {term_1, term_2} == {
            Condition(OperationType.equal, [var_0, Constant(1, Integer(32))]),
            Condition(OperationType.equal, [var_0, Constant(2, Integer(32))]),
        }
        assert (
            isinstance(cond.true_branch_child, CodeNode)
            and cond.true_branch_child.instructions == vertices[child].instructions
            and cond.false_branch is None
        )


def test_two_exits_to_one_case_depend_on_switch(task):
    """
      test_switch test 14c
    +---------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                                                                                                         |
    |                                                                                                                                                         |
    |    +------------------------------------------------------------------------------------------------------------+                                       |
    |    v                                                                                                            |                                       |
    |  +----------------------------------------------------------------+     +------------------------------------+  |                                       |
    |  |                                                                |     |                 0.                 |  |                                       |
    |  |                               3.                               |     | printf("Enter week number(1-7): ") |  |                                       |
    |  | printf("Invalid input! Please enter week number between 1-7.") |     |          var_1 = &(var_0)          |  |                                       |
    |  |                                                                |     |  __isoc99_scanf(0x804b025, var_1)  |  |                                       |
    |  |                                                                | <-- |          if(var_0 u> 0x7)          |  |                                       |
    |  +----------------------------------------------------------------+     +------------------------------------+  |                                       |
    |    |                                                                      |                                     |                                       |
    |    |                                                                      |                                     |                                       |
    |    |                                                                      v                                     |                                       v
    |    |                                                                    +-----------------------------------------------------------------------+     +--------------------+
    |    |                                                                    |                                                                       |     |         8.         |
    |    |                                                                    |                                                                       | --> |  printf("Friday")  |
    |    |                                                                    |                                                                       |     +--------------------+
    |    |                                                                    |                                  2.                                   |       |
    |    |                                                                    |                               jmp var_0                               |       |
    |    |                                                                    |                                                                       |       v
    |    |                                                                    |                                                                       |     +--------------------+
    |    |                                                                    |                                                                       |     |         9.         |
    |    |                                                                 +- |                                                                       | --> | printf("Saturday") |
    |    |                                                                 |  +-----------------------------------------------------------------------+     +--------------------+
    |    |                                                                 |    |                                     |    |         |                        |
    |    |                                                                 |    |                                     |    |         |                        |
    |    |                                                                 |    v                                     |    |         v                        |
    |    |                                                                 |  +------------------------------------+  |    |       +------------------+       |
    |    |                                                                 |  |                 4.                 |  |    |       |       10.        |       |
    |    |                                                                 |  |          printf("Monday")          |  |    |       | printf("Sunday") |       |
    |    |                                                                 |  +------------------------------------+  |    |       +------------------+       |
    |    |                                                                 |    |                                     |    |         |                        |
    |    |                                                                 |    |                                     |    |         |                        |
    |    |                                                                 |    v                                     |    |         |                        |
    |    |                                                                 |  +------------------------------------+  |    |         |                        |
    |    |                                                                 |  |                 5.                 |  |    |         |                        |
    |    |                                                                 |  |         printf("Tuesday")          |  |    |         |                        |
    +----+-----------------------------------------------------------------+- |          if(var_0 != 0x1)          | <+    |         |                        |
         |                                                                 |  +------------------------------------+       |         |                        |
         |                                                                 |    |                                          |         |                        |
         |                                                                 |    |                                          |         |                        |
         |                                                                 |    v                                          |         |                        |
         |                                                                 |  +------------------------------------+       |         |                        |
         |                                                                 |  |                 6.                 |       |         |                        |
         |                                                                 +> |        printf("Wednesday")         |       |         |                        |
         |                                                                    +------------------------------------+       |         |                        |
         |                                                                      |                                          |         |                        |
         |                                                                      |                                          |         |                        |
         |                                                                      v                                          |         |                        |
         |                                                                    +------------------------------------+       |         |                        |
         |                                                                    |                 7.                 |       |         |                        |
         |                                                                    |         printf("Thursday")         | <-----+         |                        |
         |                                                                    +------------------------------------+                 |                        |
         |                                                                      |                                                    |                        |
         |                                                                      |                                                    |                        |
         |                                                                      v                                                    |                        |
         |                                                                    +----------------------------------------------+       |                        |
         |                                                                    |                     11.                      |       |                        |
         +------------------------------------------------------------------> |                  return 0x0                  | <-----+                        |
                                                                              +----------------------------------------------+                                |
                                                                                                                           ^                                  |
                                                                                                                           +----------------------------------+
    """
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(7, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 15))]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("Monday", 3))]),
            BasicBlock(
                5,
                [
                    Assignment(ListOperation([]), print_call("Tuesday", 5)),
                    Branch(Condition(OperationType.not_equal, [var_0, Constant(1, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Wednesday", 7))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Thursday", 9))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Friday", 11))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Saturday", 13))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Sunday", 14))]),
            BasicBlock(11, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(0, Integer(32))]),
            SwitchCase(vertices[1], vertices[3], [Constant(1, Integer(32))]),
            SwitchCase(vertices[1], vertices[4], [Constant(2, Integer(32))]),
            SwitchCase(vertices[1], vertices[5], [Constant(3, Integer(32))]),
            SwitchCase(vertices[1], vertices[6], [Constant(4, Integer(32))]),
            SwitchCase(vertices[1], vertices[7], [Constant(5, Integer(32))]),
            SwitchCase(vertices[1], vertices[8], [Constant(6, Integer(32))]),
            SwitchCase(vertices[1], vertices[9], [Constant(7, Integer(32))]),
            UnconditionalEdge(vertices[2], vertices[10]),
            UnconditionalEdge(vertices[3], vertices[4]),
            TrueCase(vertices[4], vertices[7]),
            FalseCase(vertices[4], vertices[5]),
            UnconditionalEdge(vertices[5], vertices[6]),
            UnconditionalEdge(vertices[6], vertices[10]),
            UnconditionalEdge(vertices[7], vertices[8]),
            UnconditionalEdge(vertices[8], vertices[10]),
            UnconditionalEdge(vertices[9], vertices[10]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32)) and case1.break_case is False
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer(32)) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(3, Integer(32)) and case3.break_case is False
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(4, Integer(32)) and case4.break_case is False
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(5, Integer(32)) and case5.break_case is False
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(6, Integer(32)) and case6.break_case is True
    assert isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(7, Integer(32)) and case7.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[3].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[4].instructions[:-1]
    assert isinstance(cond_1 := case3.child, ConditionNode)
    assert isinstance(cond_2 := case4.child, ConditionNode)
    assert isinstance(cond_3 := case5.child, ConditionNode)
    assert isinstance(cond_4 := case6.child, ConditionNode)
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[9].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions

    # condition nodes exit one:
    for cond, child in [(cond_1, 5), (cond_2, 6)]:
        assert cond.condition.is_negation and ~cond.condition.is_symbol
        assert task._ast.condition_map[~cond.condition] == Condition(OperationType.equal, [var_0, Constant(2, Integer(32))])
        assert (
            isinstance(cond.true_branch_child, CodeNode)
            and cond.true_branch_child.instructions == vertices[child].instructions
            and cond.false_branch is None
        )

    # condition nodes exit two:
    for cond, child in [(cond_3, 7), (cond_4, 8)]:
        assert (
            cond.condition.is_conjunction
            and len(operands := cond.condition.operands) == 3
            and all(operands[i].is_negation for i in [0, 1, 2])
        )
        term_1 = task._ast.condition_map[~operands[0]]
        term_2 = task._ast.condition_map[~operands[1]]
        term_3 = task._ast.condition_map[~operands[2]]
        assert {term_1, term_2, term_3} == {
            Condition(OperationType.equal, [var_0, Constant(1, Integer(32))]),
            Condition(OperationType.equal, [var_0, Constant(3, Integer(32))]),
            Condition(OperationType.equal, [var_0, Constant(4, Integer(32))]),
        }
        assert (
            isinstance(cond.true_branch_child, CodeNode)
            and cond.true_branch_child.instructions == vertices[child].instructions
            and cond.false_branch is None
        )


def test_two_exits_to_one_case_not_depend_on_switch(task):
    """
      test_switch test 14d
    +---------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                                                                                                         |
    |                                                                                                                                                         |
    |    +------------------------------------------------------------------------------------------------------------+                                       |
    |    v                                                                                                            |                                       |
    |  +----------------------------------------------------------------+     +------------------------------------+  |                                       |
    |  |                                                                |     |                 0.                 |  |                                       |
    |  |                                                                |     | printf("Enter week number(1-7): ") |  |                                       |
    |  |                                                                |     |          var_2 = &(var_0)          |  |                                       |
    |  |                               3.                               |     |  __isoc99_scanf(0x804b025, var_2)  |  |                                       |
    |  | printf("Invalid input! Please enter week number between 1-7.") |     |     printf("Enter 1 or 2): ")      |  |                                       |
    |  |                                                                |     |          var_2 = &(var_1)          |  |                                       |
    |  |                                                                |     |  __isoc99_scanf(0x804b025, var_2)  |  |                                       |
    |  |                                                                | <-- |          if(var_0 u> 0x7)          |  |                                       |
    |  +----------------------------------------------------------------+     +------------------------------------+  |                                       |
    |    |                                                                      |                                     |                                       |
    |    |                                                                      |                                     |                                       |
    |    |                                                                      v                                     |                                       v
    |    |                                                                    +-----------------------------------------------------------------------+     +--------------------+
    |    |                                                                    |                                                                       |     |         8.         |
    |    |                                                                    |                                                                       | --> |  printf("Friday")  |
    |    |                                                                    |                                                                       |     +--------------------+
    |    |                                                                    |                                  2.                                   |       |
    |    |                                                                    |                               jmp var_0                               |       |
    |    |                                                                    |                                                                       |       v
    |    |                                                                    |                                                                       |     +--------------------+
    |    |                                                                    |                                                                       |     |         9.         |
    |    |                                                                 +- |                                                                       | --> | printf("Saturday") |
    |    |                                                                 |  +-----------------------------------------------------------------------+     +--------------------+
    |    |                                                                 |    |                                     |    |         |                        |
    |    |                                                                 |    |                                     |    |         |                        |
    |    |                                                                 |    v                                     |    |         v                        |
    |    |                                                                 |  +------------------------------------+  |    |       +------------------+       |
    |    |                                                                 |  |                 4.                 |  |    |       |       10.        |       |
    |    |                                                                 |  |          printf("Monday")          |  |    |       | printf("Sunday") |       |
    |    |                                                                 |  +------------------------------------+  |    |       +------------------+       |
    |    |                                                                 |    |                                     |    |         |                        |
    |    |                                                                 |    |                                     |    |         |                        |
    |    |                                                                 |    v                                     |    |         |                        |
    |    |                                                                 |  +------------------------------------+  |    |         |                        |
    |    |                                                                 |  |                 5.                 |  |    |         |                        |
    |    |                                                                 |  |         printf("Tuesday")          |  |    |         |                        |
    +----+-----------------------------------------------------------------+- |          if(var_1 != 0x1)          | <+    |         |                        |
         |                                                                 |  +------------------------------------+       |         |                        |
         |                                                                 |    |                                          |         |                        |
         |                                                                 |    |                                          |         |                        |
         |                                                                 |    v                                          |         |                        |
         |                                                                 |  +------------------------------------+       |         |                        |
         |                                                                 |  |                 6.                 |       |         |                        |
         |                                                                 +> |        printf("Wednesday")         |       |         |                        |
         |                                                                    +------------------------------------+       |         |                        |
         |                                                                      |                                          |         |                        |
         |                                                                      |                                          |         |                        |
         |                                                                      v                                          |         |                        |
         |                                                                    +------------------------------------+       |         |                        |
         |                                                                    |                 7.                 |       |         |                        |
         |                                                                    |         printf("Thursday")         | <-----+         |                        |
         |                                                                    +------------------------------------+                 |                        |
         |                                                                      |                                                    |                        |
         |                                                                      |                                                    |                        |
         |                                                                      v                                                    |                        |
         |                                                                    +----------------------------------------------+       |                        |
         |                                                                    |                     11.                      |       |                        |
         +------------------------------------------------------------------> |                  return 0x0                  | <-----+                        |
                                                                              +----------------------------------------------+                                |
                                                                                                                           ^                                  |
                                                                                                                           +----------------------------------+
    """
    var_1 = Variable("var_1", Integer(32, True), None, True, Variable("var_14", Integer(32, True), 0, True, None))
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_2_1 = Variable(
        "var_2", Pointer(Integer(32, True), 32), None, False, Variable("var_28_1", Pointer(Integer(32, True), 32), 2, False, None)
    )
    var_2_2 = Variable(
        "var_2", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_2_2, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_2_2, 134524965, 2)),
                    Assignment(ListOperation([]), print_call("Enter 1 or 2): ", 3)),
                    Assignment(var_2_1, UnaryOperation(OperationType.address, [var_1], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_2_1, 134524965, 4)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(7, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 17))]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("Monday", 5))]),
            BasicBlock(
                5,
                [
                    Assignment(ListOperation([]), print_call("Tuesday", 7)),
                    Branch(Condition(OperationType.not_equal, [var_1, Constant(1, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Wednesday", 9))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Thursday", 11))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Friday", 13))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Saturday", 15))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Sunday", 16))]),
            BasicBlock(11, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(0, Integer(32))]),
            SwitchCase(vertices[1], vertices[3], [Constant(1, Integer(32))]),
            SwitchCase(vertices[1], vertices[4], [Constant(2, Integer(32))]),
            SwitchCase(vertices[1], vertices[5], [Constant(3, Integer(32))]),
            SwitchCase(vertices[1], vertices[6], [Constant(4, Integer(32))]),
            SwitchCase(vertices[1], vertices[7], [Constant(5, Integer(32))]),
            SwitchCase(vertices[1], vertices[8], [Constant(6, Integer(32))]),
            SwitchCase(vertices[1], vertices[9], [Constant(7, Integer(32))]),
            UnconditionalEdge(vertices[2], vertices[10]),
            UnconditionalEdge(vertices[3], vertices[4]),
            TrueCase(vertices[4], vertices[7]),
            FalseCase(vertices[4], vertices[5]),
            UnconditionalEdge(vertices[5], vertices[6]),
            UnconditionalEdge(vertices[6], vertices[10]),
            UnconditionalEdge(vertices[7], vertices[8]),
            UnconditionalEdge(vertices[8], vertices[10]),
            UnconditionalEdge(vertices[9], vertices[10]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32)) and case1.break_case is False
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer(32)) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(3, Integer(32)) and case3.break_case is False
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(4, Integer(32)) and case4.break_case is False
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(5, Integer(32)) and case5.break_case is False
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(6, Integer(32)) and case6.break_case is True
    assert isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(7, Integer(32)) and case7.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[3].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[4].instructions[:-1]
    assert isinstance(cond_1 := case3.child, ConditionNode)
    assert isinstance(cond_2 := case4.child, ConditionNode)
    assert isinstance(cond_3 := case5.child, ConditionNode)
    assert isinstance(cond_4 := case6.child, ConditionNode)
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[9].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions

    # condition nodes exit one - cond_1:
    assert cond_1.condition.is_disjunction and len(operands := cond_1.condition.operands) == 2
    assert any((cc_1 := operands[i]).is_symbol for i in [0, 1]) and any((cc_2 := operands[i]).is_negation for i in [0, 1])
    assert (cc_2 := ~cc_2).is_symbol
    assert [task._ast.condition_map[cc_1], task._ast.condition_map[cc_2]] == [
        Condition(OperationType.equal, [var_0, Constant(3, Integer(32))]),
        Condition(OperationType.not_equal, [var_1, Constant(1, Integer(32, True))]),
    ]
    assert (
        isinstance(cond_1.true_branch_child, CodeNode)
        and cond_1.true_branch_child.instructions == vertices[5].instructions
        and cond_1.false_branch is None
    )

    # condition nodes exit one - cond_2:
    assert cond_2.condition.is_disjunction and len(operands := cond_2.condition.operands) == 3
    assert any((cc_not := operands[i]).is_negation for i in [0, 1, 2]) and (cc := ~cc_not).is_symbol
    assert task._ast.condition_map[cc] == Condition(OperationType.not_equal, [var_1, Constant(1, Integer(32, True))])
    assert all(cc.is_symbol for cc in operands if str(cc) != str(cc_not))
    assert {task._ast.condition_map[cc] for cc in operands if str(cc) != str(cc_not)} == {
        Condition(OperationType.equal, [var_0, Constant(3, Integer(32))]),
        Condition(OperationType.equal, [var_0, Constant(4, Integer(32))]),
    }
    assert (
        isinstance(cond_2.true_branch_child, CodeNode)
        and cond_2.true_branch_child.instructions == vertices[6].instructions
        and cond_2.false_branch is None
    )

    # Friday & Saturday
    for cond, or_args, node_idx in [(cond_3, 2, 7), (cond_4, 3, 8)]:
        assert cond.condition.is_conjunction and len(operands := cond.condition.operands) == 3
        or_conditions = [arg for arg in operands if arg.is_disjunction]
        not_conditions = [arg for arg in operands if arg.is_negation]
        assert len(not_conditions) == 2
        term_1 = task._ast.condition_map[~not_conditions[0]]
        term_2 = task._ast.condition_map[~not_conditions[1]]
        assert {term_1, term_2} == {
            Condition(OperationType.equal, [var_0, Constant(3, Integer(32))]),
            Condition(OperationType.equal, [var_0, Constant(4, Integer(32))]),
        }
        assert len(or_conditions) == 1
        or_cond = or_conditions[0]
        assert len(operands := or_cond.operands) == or_args and all(arg.is_symbol for arg in operands)
        term_1 = task._ast.condition_map[operands[0]]
        term_2 = task._ast.condition_map[operands[1]]
        if or_args == 2:
            assert {term_1, term_2} == {
                Condition(OperationType.not_equal, [var_1, Constant(1, Integer(32, True))]),
                Condition(OperationType.equal, [var_0, Constant(5, Integer(32))]),
            }
        else:
            term_3 = task._ast.condition_map[operands[2]]
            assert {term_1, term_2, term_3} == {
                Condition(OperationType.not_equal, [var_1, Constant(1, Integer(32, True))]),
                Condition(OperationType.equal, [var_0, Constant(5, Integer(32))]),
                Condition(OperationType.equal, [var_0, Constant(6, Integer(32))]),
            }
        assert (
            isinstance(cond.true_branch_child, CodeNode)
            and cond.true_branch_child.instructions == vertices[node_idx].instructions
            and cond.false_branch is None
        )


@pytest.mark.skip("Not implemented yet")
def test_switch_add_existing_cases(task):
    """test_switch test7_b or 18 -> later: insert case that is already their (but empty)"""
    # print(DecoratedCFG.from_cfg(task.graph).export_ascii())
    # PatternIndependentRestructuring().run(task)
    # DecoratedAST.from_ast(task._ast).export_plot("/home/eva/Projects/decompiler/AST/out.png")
    pass


def test_no_switch_ssa_variable_wrong(task):
    """
      test_switch test_19

    +---------+
    |         v
    |       +----------------------------------------------------------------+     +-------------------+     +------------------------------------+     +--------------------+
    |       |                                                                |     |                   |     |                 0.                 |     |                    |
    |       |                               7.                               |     |        2.         |     | printf("Enter week number(1-7): ") |     |         9.         |
    |       | printf("Invalid input! Please enter week number between 1-7.") |     |  var_0 = rand()   |     |          var_1 = &(var_0)          |     | printf("Tuesday")  |
    |       |                                                                |     | if(var_0 != 0x32) |     |  __isoc99_scanf(0x804b025, var_1)  |     |                    |
    |    +> |                                                                | <-- |                   | <-- |         if(var_0 <= 0x27)          |  +> |                    | -------------------------------+
    |    |  +----------------------------------------------------------------+     +-------------------+     +------------------------------------+  |  +--------------------+                                |
    |    |    |                                                                      |                         |                                     |                                                        |
    |    |    |                                                                      |                         |                                     |                                                        |
    |    |    |                                                                      v                         v                                     |                                                        |
    |    |    |                                                                    +-------------------+     +------------------------------------+  |  +--------------------+                                |
    |    |    |                                                                    |        6.         |     |                 1.                 |  |  |         8.         |                                |
    |    +----+-----------------------------------------------------------------+  | printf("Friday")  |  +- |         if(var_0 u> 0x28)          |  |  |  printf("Monday")  | --------------------------+    |
    |         |                                                                 |  +-------------------+  |  +------------------------------------+  |  +--------------------+                           |    |
    |         |                                                                 |    |                    |    |                                     |    ^                                              |    |
    |         |                                                                 |    |                    |    |                                     |    |                                              |    |
    |         |                                                                 |    |                    |    v                                     |    |                                              |    |
    |         |                                                                 |    |                    |  +---------------------------------------------------------------+     +------------------+  |    |
    |         |                                                                 |    |                    |  |                                                               |     |       12.        |  |    |
    |         |                                                                 +----+--------------------+  |                              4.                               | --> | printf("Sunday") |  |    |
    |         |                                                                      |                       |                           jmp var_0                           |     +------------------+  |    |
    |         |                                                                      |                       |                                                               |       |                   |    |
    +---------+----------------------------------------------------------------------+---------------------- |                                                               |       |                   |    |
              |                                                                      |                       +---------------------------------------------------------------+       |                   |    |
              |                                                                      |                         |                                          |                          |                   |    |
              |                                                                      |                         |                                          |                          |                   |    |
              |                                                                      |                         v                                          v                          |                   |    |
              |                                                                      |                       +------------------------------------+     +--------------------+       |                   |    |
              |                                                                      |                       |                10.                 |     |        11.         |       |                   |    |
              |                                                                      |                       |        printf("Wednesday")         |     | printf("Saturday") |       |                   |    |
              |                                                                      |                       +------------------------------------+     +--------------------+       |                   |    |
              |                                                                      |                         |                                          |                          |                   |    |
              |                                                                      |                         |                                          |                          |                   |    |
              |                                                                      |                         v                                          v                          v                   |    |
              |                                                                      |                       +----------------------------------------------------------------------------------------+  |    |
              |                                                                      +---------------------> |                                                                                        | <+    |
              |                                                                                              |                                          13.                                           |       |
              |                                                                                              |                                       return 0x0                                       |       |
              +--------------------------------------------------------------------------------------------> |                                                                                        | <-----+
                                                                                                             +----------------------------------------------------------------------------------------+

    """
    var_0_1, vertices = _switch_test_19(task)

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 4
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(friday_case := seq_node.children[1], ConditionNode) and friday_case.condition.is_literal
    assert isinstance(switch_cond := seq_node.children[2], ConditionNode)
    assert isinstance(seq_node.children[3], CodeNode) and seq_node.children[3].instructions == vertices[11].instructions

    # friday case
    assert task._ast.condition_map[~friday_case.condition] == vertices[0].instructions[-1].condition
    assert isinstance(branch_seq := friday_case.true_branch_child, SeqNode) and friday_case.false_branch is None
    assert len(branch_seq.children) == 2
    assert isinstance(branch_seq.children[0], CodeNode) and branch_seq.children[0].instructions == vertices[2].instructions[:1]
    assert isinstance(friday := branch_seq.children[1], ConditionNode)
    assert task._ast.condition_map[~friday.condition] == vertices[2].instructions[-1].condition
    assert isinstance(friday.true_branch_child, CodeNode) and friday.false_branch is None
    assert friday.true_branch_child.instructions == vertices[4].instructions

    # switch_condition:
    assert switch_cond.false_branch is None and isinstance(switch := switch_cond.true_branch_child, SwitchNode)
    assert switch_cond.condition.is_disjunction and len(switch_cond.condition.operands) == 2
    assert {task._ast.condition_map[op] for op in switch_cond.condition.operands} == {
        vertices[0].instructions[-1].condition,
        vertices[2].instructions[-1].condition,
    }

    # switch
    assert switch.expression == var_0_1 and len(switch.children) == 6
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32)) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(6, Integer(32)) and case2.break_case is True
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(9, Integer(32)) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(12, Integer(32)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(34, Integer(32)) and case5.break_case is True
    assert isinstance(default := switch.default, CaseNode)

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[6].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[9].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[10].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[7].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[8].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[5].instructions


@pytest.mark.skip("Not implemented yet.")
def test_switch_default_on_top_without_break(task):
    """test_switch test21 -> later: insert missing cases problem if have default node."""
    pass


def test_switch_with_loop1(task):
    """
      test_switch test16 -> Here we need the Case-Constant "add_to_previous_case"
         +---------------------------------------------------------------------------------------------------------------------------------------+
         |                                                                                                                                       |
         |                                                                                                                                       |
    +----+------------------------------------------------------------------------------------------------------------+                          |
    |    v                                                                                                            |                          |
    |  +----------------------------------------------------------------+     +------------------------------------+  |  +--------------------+  |
    |  |                                                                |     |                 0.                 |  |  |                    |  |
    |  |                               3.                               |     | printf("Enter week number(1-7): ") |  |  |         7.         |  |
    |  | printf("Invalid input! Please enter week number between 1-7.") |     |          var_1 = &(var_0)          |  |  | printf("Thursday") |  |
    |  |                                                                |     | __isoc99_scanf(0x134524965, var_1) |  |  |                    |  |
    |  |                                                                | <-- |          if(var_0 u> 0x7)          |  +- |                    |  |
    |  +----------------------------------------------------------------+     +------------------------------------+     +--------------------+  |
    |    |                                                                      |                                          ^                     |
    |    |                                                                      |                                          |                     |
    |    v                                                                      v                                          |                     |
    |  +----------------------------------------------------------------+     +------------------------------------------------------------------------------------------+     +-------------------+
    |  |                              11.                               |     |                                                                                          |     |        5.         |
    +> |                           return 0x0                           |     |                                                                                          | --> | printf("Tuesday") |
       +----------------------------------------------------------------+     |                                                                                          |     +-------------------+
         ^                                                                    |                                            2.                                            |       |
         |                                                                    |                                        jmp var_0                                         |       |
         |                                                                    |                                                                                          |       |
         |                                                                    |                                                                                          |       |
         |                                                                 +- |                                                                                          |       |
         |                                                                 |  +------------------------------------------------------------------------------------------+       |
         |                                                                 |    |                                     |                          |    |                          |
         |                                                                 |    |                                     |                          |    |                          |
         |                                                                 |    v                                     |                          |    v                          |
         |                                                                 |  +------------------------------------+  |                          |  +--------------------+       |
         |                                                                 |  |                10.                 |  |                          |  |         8.         |       |
         |                                                                 |  |          printf("Sunday")          | <+----+                     |  |  printf("Friday")  |       |
         |                                                                 |  +------------------------------------+  |    |                     |  +--------------------+       |
         |                                                                 |    |                                     |    |                     |    |                          |
         |                                                                 |    |                                     |    |                     |    |                          |
         |                                                                 |    v                                     |    |                     |    v                          |
         |                                                                 |  +------------------------------------+  |    |                     |  +--------------------+       |
         |                                                                 |  |                 4.                 |  |    |                     |  |         9.         |       |
         |                                                                 |  |          printf("Monday")          | <+    |                     +> | printf("Saturday") |       |
         |                                                                 |  +------------------------------------+       |                        +--------------------+       |
         |                                                                 |    |                                          |                          |                          |
         |                                                                 |    |                                          |                          |                          |
         |                                                                 |    v                                          |                          |                          |
         |                                                                 |  +------------------------------------+       |                          |                          |
         |                                                                 |  |                 6.                 |       |                          |                          |
         |                                                                 +> |        printf("Wednesday")         | ------+                          |                          |
         |                                                                    +------------------------------------+                                  |                          |
         |                                                                      ^                                                                     |                          |
         +----------------------------------------------------------------------+---------------------------------------------------------------------+                          |
                                                                                |                                                                                                |
                                                                                |                                                                                                |
                                                                                +------------------------------------------------------------------------------------------------+

    """
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 0x134524965, 2)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(7, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 14))]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("Monday", 4))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("Tuesday", 5))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Wednesday", 7))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Thursday", 8))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Friday", 9))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Saturday", 11))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Sunday", 13))]),
            BasicBlock(11, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(0, Integer(32))]),
            SwitchCase(vertices[1], vertices[3], [Constant(1, Integer(32))]),
            SwitchCase(vertices[1], vertices[4], [Constant(2, Integer(32))]),
            SwitchCase(vertices[1], vertices[5], [Constant(3, Integer(32))]),
            SwitchCase(vertices[1], vertices[6], [Constant(4, Integer(32))]),
            SwitchCase(vertices[1], vertices[7], [Constant(5, Integer(32))]),
            SwitchCase(vertices[1], vertices[8], [Constant(6, Integer(32))]),
            SwitchCase(vertices[1], vertices[9], [Constant(7, Integer(32))]),
            UnconditionalEdge(vertices[2], vertices[10]),
            UnconditionalEdge(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[5]),
            UnconditionalEdge(vertices[5], vertices[9]),
            UnconditionalEdge(vertices[6], vertices[10]),
            UnconditionalEdge(vertices[7], vertices[8]),
            UnconditionalEdge(vertices[8], vertices[10]),
            UnconditionalEdge(vertices[9], vertices[3]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(return_cond := seq_node.children[2], ConditionNode)

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32)) and case1.break_case is False
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer(32)) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(3, Integer(32)) and case3.break_case is False
    assert isinstance(case7 := switch.cases[3], CaseNode) and case7.constant == Constant(7, Integer(32)) and case7.break_case is True
    assert isinstance(case4 := switch.cases[4], CaseNode) and case4.constant == Constant(4, Integer(32)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[5], CaseNode) and case5.constant == Constant(5, Integer(32)) and case5.break_case is False
    assert isinstance(case6 := switch.cases[6], CaseNode) and case6.constant == Constant(6, Integer(32)) and case6.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    new_variable = case1.child.instructions[0].definitions[0]
    new_assignment = Assignment(new_variable, Constant(0, Integer.int32_t()))
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == [new_assignment]
    assert isinstance(cn2 := case2.child, ConditionNode) and cn2.false_branch is None
    assert task._ast.condition_map[~cn2.condition] == Condition(OperationType.equal, [var_0, Constant(1, Integer(32))])
    assert cn2.true_branch_child.instructions == vertices[4].instructions
    assert isinstance(cn3 := case3.child, ConditionNode) and cn3.false_branch is None
    assert task._ast.condition_map[~cn3.condition] == Condition(OperationType.equal, [var_0, Constant(1, Integer(32))])
    assert cn3.true_branch_child.instructions == [Assignment(new_variable, Constant(1, Integer.int32_t()))]
    assert isinstance(loop_seq := case7.child, SeqNode) and len(loop_seq.children) == 2
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[6].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[7].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[8].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions

    # loop sequence:
    assert isinstance(last_entry := loop_seq.children[0], ConditionNode)
    assert last_entry.condition.is_conjunction and len(operands := last_entry.condition.operands) == 3
    assert {task._ast.condition_map[~cond] for cond in operands} == {
        Condition(OperationType.equal, [var_0, Constant(const, Integer(32))]) for const in {1, 2, 3}
    }
    assert last_entry.false_branch is None and isinstance(last_entry.true_branch_child, CodeNode)
    assert last_entry.true_branch_child.instructions == [Assignment(new_variable, Constant(2, Integer.int32_t()))]

    assert isinstance(loop := loop_seq.children[1], WhileLoopNode) and loop.is_endless_loop
    assert isinstance(loop_body := loop.body, SeqNode) and len(loop_body.children) == 2
    assert isinstance(switch2 := loop_body.children[0], SwitchNode)
    assert isinstance(loop_body.children[1], CodeNode) and loop_body.children[1].instructions == vertices[9].instructions + [new_assignment]

    assert switch2.expression == new_variable and len(switch2.children) == 2
    assert (
        isinstance(case2_1 := switch2.cases[0], CaseNode)
        and case2_1.constant == Constant(0, Integer(32, True))
        and case2_1.break_case is False
    )
    assert (
        isinstance(case2_2 := switch2.cases[1], CaseNode)
        and case2_2.constant == Constant(1, Integer(32, True))
        and case2_2.break_case is True
    )
    assert isinstance(case2_1.child, CodeNode) and case2_1.child.instructions == vertices[3].instructions
    assert isinstance(case2_2.child, CodeNode) and case2_2.child.instructions == vertices[5].instructions + [new_assignment]

    # return condition
    assert return_cond.condition.is_disjunction and len(operands := return_cond.condition.operands) == 5
    assert {task._ast.condition_map[cond] for cond in operands} == {
        Condition(OperationType.equal, [var_0, Constant(const, Integer(32))]) for const in {0, 4, 5, 6}
    } | {Condition(OperationType.greater_us, [var_0, Constant(7, Integer(32, True))])}
    assert return_cond.false_branch is None and isinstance(return_cond.true_branch_child, CodeNode)
    assert return_cond.true_branch_child.instructions == vertices[-1].instructions


def test_switch_with_loop2(task):
    """
      test_switch test17 -> Here we need the Case-Constant "add_to_previous_case

              +----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
              |                                                                                                                                                                                                          |
              |                                                                                                                                     +------------------+                                                 |
              |                                                                                                                                     |        8.        |                                                 |
    +---------+------------------------------------------------------------------------------------------------------------------------------------ | printf("Friday") |                                                 |
    |         |                                                                                                                                     +------------------+                                                 |
    |         |                                                                                                                                       ^                                                                  |
    |    +----+------------------------------------------------------------------------------------------------------------+                          |                                                                  |
    |    |    v                                                                                                            |                          |                                                                  |
    |    |  +----------------------------------------------------------------+     +------------------------------------+  |  +--------------------+  |                 +--------------------+                           |
    |    |  |                                                                |     |                 0.                 |  |  |                    |  |                 |                    |                           |
    |    |  |                               3.                               |     | printf("Enter week number(1-7): ") |  |  |         5.         |  |                 |         7.         |                           |
    |    |  | printf("Invalid input! Please enter week number between 1-7.") |     |          var_1 = &(var_0)          |  |  | printf("Tuesday")  |  |                 | printf("Thursday") |                           |
    |    |  |                                                                |     | __isoc99_scanf(0x134524965, var_1) |  |  |                    |  |                 |                    |                           |
    |    |  |                                                                | <-- |          if(var_0 u> 0x7)          |  +- |                    |  |                 |                    | ---------------------+    |
    |    |  +----------------------------------------------------------------+     +------------------------------------+     +--------------------+  |                 +--------------------+                      |    |
    |    |    |                                                                      |                                          ^                     |                   ^                                         |    |
    |    |    |                                                                      |                                          |                     |                   |                                         |    |
    |    |    |                                                                      v                                          |                     |                   |                                         |    |
    |    |    |                                                                    +---------------------------------------------------------------------------------------------------------+     +-------------+  |    |
    |    |    |                                                                    |                                                                                                         |     |     16.     |  |    |
    |    |    |                                                                    |                                                                                                         | --> | var_2 = 0x0 |  |    |
    |    |    |                                                                    |                                                                                                         |     +-------------+  |    |
    |    |    |                                                                    |                                                   2.                                                    |       |              |    |
    |    |    |                                                                    |                                                jmp var_0                                                |       |              |    |
    |    |    |                                                                    |                                                                                                         |       |              |    |
    |    |    |                                                                    |                                                                                                         |       |              |    |
    |    |    |                                                                    |                                                                                                         | ------+--------------+----+
    |    |    |                                                                    +---------------------------------------------------------------------------------------------------------+       |              |
    |    |    |                                                                      |                                          |                                         |                          |              |
    |    |    |                                                                      |                                          |                                         |                          |              |
    |    |    |                                                                      v                                          v                                         v                          |              |
    |    |    |                                                                    +------------------------------------+     +--------------------+                    +--------------------+       |              |
    |    |    |                                                                    |                14.                 |     |         9.         |                    |        15.         |       |              |
    |    |    |                                                                    |            var_2 = 0x0             |     | printf("Saturday") |                    |    var_2 = 0x0     |       |              |
    |    |    |                                                                    +------------------------------------+     +--------------------+                    +--------------------+       |              |
    |    |    |                                                                      |                                          |                                         |                          |              |
    |    |    |                                                                      |                                          |                                         |                          |              |
    |    |    |                                                                      v                                          |                                         |                          |              |
    |    |    |                                                                    +------------------------------------+       |                                         |                          |              |
    |    |    |                                                                    |                 4.                 |       |                                         |                          |              |
    |    |    |                                                                    |          printf("Monday")          | <+    |                                         |                          |              |
    |    |    |                                                                    +------------------------------------+  |    |                                         |                          |              |
    |    |    |                                                                      |                                     |    |                                         |                          |              |
    |    |    |                                                                      |                                     |    |                                         |                          |              |
    |    |    |                                                                      v                                     |    |                                         |                          |              |
    |    |    |                                                                    +------------------------------------+  |    |                                         |                          |              |
    |    |    |                                                                    |                 6.                 |  |    |                                         |                          |              |
    |    |    |                                                                    |        printf("Wednesday")         | <+----+-----------------------------------------+                          |              |
    |    |    |                                                                    +------------------------------------+  |    |                                                                    |              |
    |    |    |                                                                      |                                     |    |                                                                    |              |
    |    |    |                                                                      |                                     |    |                                                                    |              |
    |    |    |                                                                      v                                     |    |                                                                    |              |
    |    |    |                                                                    +------------------------------------+  |    |                                                                    |              |
    |    |    |                                                                    |                10.                 |  |    |                                                                    |              |
    |    |    |                                                                    |          printf("Sunday")          |  |    |                                                                    |              |
    |    |    |                                                                 +- |          if(var_2 > 0x4)           | <+----+--------------------------------------------------------------------+              |
    |    |    |                                                                 |  +------------------------------------+  |    |                                                                                   |
    |    |    |                                                                 |    |                                     |    |                                                                                   |
    |    |    |                                                                 |    |                                     |    |                                                                                   |
    |    |    |                                                                 |    v                                     |    |                                                                                   |
    |    |    |                                                                 |  +------------------------------------+  |    |                                                                                   |
    |    |    |                                                                 |  |                13.                 |  |    |                                                                                   |
    |    |    |                                                                 |  |        var_2 = var_2 + 0x1         | -+    |                                                                                   |
    |    |    |                                                                 |  +------------------------------------+       |                                                                                   |
    |    |    |                                                                 |                                               |                                                                                   |
    |    |    |                                                                 |                                               |                                                                                   |
    |    |    v                                                                 v                                               |                                                                                   |
    |    |  +-----------------------------------------------------------------------------------------------------------+       |                                                                                   |
    |    +> |                                                                                                           | <-----+                                                                                   |
    |       |                                                                                                           |                                                                                           |
    |       |                                                    11.                                                    |                                                                                           |
    +-----> |                                                return 0x0                                                 |                                                                                           |
            |                                                                                                           |                                                                                           |
            |                                                                                                           |                                                                                           |
            |                                                                                                           | <-----------------------------------------------------------------------------------------+
            +-----------------------------------------------------------------------------------------------------------+
    """
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_14", Integer(32, True), 0, True, None))
    var_2_2 = Variable("var_2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 2, False, None))
    var_2_3 = Variable("var_2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 3, False, None))
    var_2_4 = Variable("var_2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 4, False, None))
    var_2_5 = Variable("var_2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 5, False, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 0x134524965, 2)),
                    Branch(Condition(OperationType.greater_us, [var_0, Constant(7, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(var_0)]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 13))]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("Monday", 4))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("Tuesday", 5))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Wednesday", 7))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Thursday", 8))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Friday", 9))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Saturday", 10))]),
            BasicBlock(
                10,
                [
                    Assignment(ListOperation([]), print_call("Sunday", 12)),
                    Branch(Condition(OperationType.greater, [var_2_4, Constant(4, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(11, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(
                13, [Assignment(var_2_5, BinaryOperation(OperationType.plus, [var_2_4, Constant(1, Integer(32, True))], Integer(32, True)))]
            ),
            BasicBlock(14, [Assignment(var_2_2, Constant(0, Integer(32, True)))]),
            BasicBlock(15, [Assignment(var_2_3, Constant(0, Integer(32, True)))]),
            BasicBlock(16, [Assignment(var_2_4, Constant(0, Integer(32, True)))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            SwitchCase(vertices[1], vertices[2], [Constant(0, Integer(32))]),
            SwitchCase(vertices[1], vertices[4], [Constant(2, Integer(32))]),
            SwitchCase(vertices[1], vertices[6], [Constant(4, Integer(32))]),
            SwitchCase(vertices[1], vertices[7], [Constant(5, Integer(32))]),
            SwitchCase(vertices[1], vertices[8], [Constant(6, Integer(32))]),
            SwitchCase(vertices[1], vertices[12], [Constant(1, Integer(32))]),
            SwitchCase(vertices[1], vertices[13], [Constant(3, Integer(32))]),
            SwitchCase(vertices[1], vertices[14], [Constant(7, Integer(32))]),
            UnconditionalEdge(vertices[2], vertices[10]),
            UnconditionalEdge(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[10]),
            UnconditionalEdge(vertices[5], vertices[9]),
            UnconditionalEdge(vertices[6], vertices[10]),
            UnconditionalEdge(vertices[7], vertices[10]),
            UnconditionalEdge(vertices[8], vertices[10]),
            FalseCase(vertices[9], vertices[11]),
            TrueCase(vertices[9], vertices[10]),
            UnconditionalEdge(vertices[11], vertices[3]),
            UnconditionalEdge(vertices[12], vertices[3]),
            UnconditionalEdge(vertices[13], vertices[5]),
            UnconditionalEdge(vertices[14], vertices[9]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[10].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32)) and case1.break_case is False
    assert isinstance(case3 := switch.cases[1], CaseNode) and case3.constant == Constant(3, Integer(32)) and case3.break_case is False
    assert isinstance(case7 := switch.cases[2], CaseNode) and case7.constant == Constant(7, Integer(32)) and case7.break_case is True
    assert isinstance(case2 := switch.cases[3], CaseNode) and case2.constant == Constant(2, Integer(32)) and case2.break_case is True
    assert isinstance(case4 := switch.cases[4], CaseNode) and case4.constant == Constant(4, Integer(32)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[5], CaseNode) and case5.constant == Constant(5, Integer(32)) and case5.break_case is True
    assert isinstance(case6 := switch.cases[6], CaseNode) and case6.constant == Constant(6, Integer(32)) and case6.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    new_variable = case1.child.instructions[1].definitions[0]
    new_assignment = Assignment(new_variable, Constant(0, Integer.int32_t()))
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[12].instructions + [new_assignment]
    assert isinstance(cn3 := case3.child, ConditionNode) and cn3.false_branch is None
    assert task._ast.condition_map[~cn3.condition] == Condition(OperationType.equal, [var_0, Constant(1, Integer(32))])
    assert cn3.true_branch_child.instructions == vertices[13].instructions + [Assignment(new_variable, Constant(1, Integer.int32_t()))]
    assert isinstance(loop_seq := case7.child, SeqNode) and len(loop_seq.children) == 2
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[4].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[6].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[7].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[8].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[2].instructions

    # loop sequence:
    assert isinstance(last_entry := loop_seq.children[0], ConditionNode)
    assert last_entry.condition.is_conjunction and len(operands := last_entry.condition.operands) == 2
    assert {task._ast.condition_map[~cond] for cond in operands} == {
        Condition(OperationType.equal, [var_0, Constant(const, Integer(32))]) for const in {1, 3}
    }
    assert last_entry.false_branch is None and isinstance(last_entry.true_branch_child, CodeNode)
    assert last_entry.true_branch_child.instructions == vertices[14].instructions + [
        Assignment(new_variable, Constant(2, Integer.int32_t()))
    ]

    assert isinstance(loop := loop_seq.children[1], WhileLoopNode) and loop.is_endless_loop
    assert isinstance(loop_body := loop.body, SeqNode) and len(loop_body.children) == 4
    assert isinstance(switch2 := loop_body.children[0], SwitchNode)
    assert isinstance(loop_body.children[1], CodeNode) and loop_body.children[1].instructions == [
        vertices[9].instructions[0],
        new_assignment,
    ]
    assert isinstance(exit := loop_body.children[2], ConditionNode)
    assert isinstance(loop_body.children[3], CodeNode) and loop_body.children[3].instructions == vertices[11].instructions

    assert switch2.expression == new_variable and len(switch2.children) == 2
    assert (
        isinstance(case2_1 := switch2.cases[0], CaseNode)
        and case2_1.constant == Constant(0, Integer(32, True))
        and case2_1.break_case is False
    )
    assert (
        isinstance(case2_2 := switch2.cases[1], CaseNode)
        and case2_2.constant == Constant(1, Integer(32, True))
        and case2_2.break_case is True
    )
    assert isinstance(case2_1.child, CodeNode) and case2_1.child.instructions == vertices[3].instructions
    assert isinstance(case2_2.child, CodeNode) and case2_2.child.instructions == vertices[5].instructions + [new_assignment]

    if exit.true_branch_child is None:
        assert task._ast.condition_map[~exit.condition] == vertices[9].instructions[-1].condition
        assert isinstance(exit.false_branch, CodeNode) and exit.false_branch.instructions == [Break()]
    else:
        assert task._ast.condition_map[exit.condition] == vertices[9].instructions[-1].condition
        assert (
            isinstance(exit.true_branch_child, CodeNode) and exit.true_branch_child.instructions == [Break()] and exit.false_branch is None
        )


def test_too_nested(task):
    """
      The cases are too nested, so we remove them, test14 ubuntu 32/s
    +-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                                                                                   |
    |  +----------------------------------------------------------------+     +------------------------------------------------------+  |  +-------------------+
    |  |                                                                |     |                          0.                          |  |  |                   |
    |  |                                                                |     |               __x86.get_pc_thunk.bx()                |  |  |                   |
    |  |                               1.                               |     |          printf("Enter week number(1-7): ")          |  |  |        5.         |
    |  | var_5 = "Invalid input! Please enter week number between 1-7." |     |                   var_3 = &(var_0)                   |  |  | var_5 = "Tuesday" |
    |  |                         var_2 = var_1                          |     |         var_2 = __isoc99_scanf("%d", var_3)          |  |  |                   |
    |  |                                                                |     |                 var_1 = var_0 - 0x1                  |  |  |                   |
    |  |                                                                | <-- |                   if(var_1 u> 0x6)                   |  +- |                   |
    |  +----------------------------------------------------------------+     +------------------------------------------------------+     +-------------------+
    |    |                                                                      |                                                            ^
    |    |                                                                      |                                                            |
    |    |                                                                      v                                                            |
    |    |                                                                    +--------------------------------------------------------------------------------+     +---------------+     +-----------------------------------------------------+
    |    |                                                                    |                                                                                |     |      15.      |     |                         7.                          |
    |    |                                                                    |                                                                                | --> | var_1 = var_2 |  +> | var_1 = __printf_chk(0x1, "Thursday", var_1, var_1) |
    |    |                                                                    |                                                                                |     +---------------+  |  +-----------------------------------------------------+
    |    |                                                                    |                                       2.                                       |       |                |    |
    |    |                                                                    |         var_4 = (*((0x15fd0 + (var_1 << 0x2)) + 0xffffd710)) + 0x15fd0         |       |                |    |
    |    |                                                                    |                                   jmp var_1                                    |       |                |    v
    |    |                                                                    |                                                                                |       |                |  +-----------------------------------------------------+
    |    |                                                                    |                                                                                |       |                |  |                         8.                          |
    |    |                                                                    |                                                                                |       |                |  |                  var_5 = "Friday"                   |
    |    |                                                                 +- |                                                                                | ------+----------------+  |                    var_2 = var_1                    | <+
    |    |                                                                 |  +--------------------------------------------------------------------------------+       |                   +-----------------------------------------------------+  |
    |    |                                                                 |    |                                                       |    |                         |                     |                                                      |
    |    |                                                                 |    |                                                       |    |                         |                     |                                                      |
    |    |                                                                 |    v                                                       |    |                         |                     |                                                      |
    |    |                                                                 |  +------------------------------------------------------+  |    |                         |                     |                                                      |
    |    |                                                                 |  |                          4.                          |  |    |                         |                     |                                                      |
    |    |                                                                 |  |                   var_5 = "Monday"                   |  |    |                         |                     |                                                      |
    |    |                                                                 |  +------------------------------------------------------+  |    |                         |                     |                                                      |
    |    |                                                                 |    |                                                       |    |                         |                     |                                                      |
    |    |                                                                 |    |                                                       |    +-------------------------+---------------------+------------------------------------------------------+
    |    |                                                                 |    v                                                       |                              |                     |
    |    |                                                                 |  +------------------------------------------------------+  |                              |                     |
    |    |                                                                 |  |                         11.                          |  |                              |                     |
    +----+-----------------------------------------------------------------+> |    var_1 = __printf_chk(0x1, var_5, var_1, var_1)    |  |                              |                     |
         |                                                                 |  +------------------------------------------------------+  |                              |                     |
         |                                                                 |    |                                                       |                              |                     |
         |                                                                 |    |                                                       |                              |                     |
         |                                                                 |    v                                                       |                              |                     |
         |                                                                 |  +------------------------------------------------------+  |                              |                     |
         |                                                                 |  |                          6.                          |  |                              |                     |
         |                                                                 |  | var_4 = __printf_chk(0x1, "Wednesday", var_1, var_1) | <+                              |                     |
         |                                                                 |  +------------------------------------------------------+                                 |                     |
         |                                                                 |    |                                                                                      |                     |
         |                                                                 |    |                                                                                      |                     |
         |                                                                 |    v                                                                                      |                     |
         |                                                                 |  +------------------------------------------------------+                                 |                     |
         |                                                                 |  |                          9.                          |                                 |                     |
         |                                                                 +> |  var_1 = __printf_chk(0x1, "Sunday", var_4, var_4)   |                                 |                     |
         |                                                                    +------------------------------------------------------+                                 |                     |
         |                                                                      |                                                                                      |                     |
         |                                                                      |                                                                                      |                     |
         |                                                                      v                                                                                      |                     |
         |                                                                    +------------------------------------------------------+                                 |                     |
         |                                                                    |                         10.                          |                                 |                     |
         |                                                                    |                  var_5 = "Saturday"                  |                                 |                     |
         |                                                                    |                    var_2 = var_1                     | <-------------------------------+                     |
         |                                                                    +------------------------------------------------------+                                                       |
         |                                                                      |                                                                                                            |
         |                                                                      |                                                                                                            |
         |                                                                      v                                                                                                            |
         |                                                                    +------------------------------------------------------+                                                       |
         |                                                                    |                          3.                          |                                                       |
         |                                                                    |        __printf_chk(0x1, var_5, var_1, var_2)        |                                                       |
         +------------------------------------------------------------------> |                      return 0x0                      | <-----------------------------------------------------+
                                                                              +------------------------------------------------------+
    """
    int_pointer8 = Pointer(Integer(8, True), 32)
    int_pointer32 = Pointer(Integer(32, True), 32)
    void_pointer = Pointer(CustomType("void", 0), 32)
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_1_1 = Variable("var_1", Integer(32, True), None, False, Variable("c0", Integer(32, True), 0, False, None))
    var_1_2 = Variable("var_1", Integer(32, True), None, False, Variable("var_24_4", Integer(32, True), 14, False, None))
    var_1_3 = Variable("var_1", Integer(32, True), None, False, Variable("eax_1", Integer(32, True), 6, False, None))
    var_1_4 = Variable("var_1", Integer(32, True), None, False, Variable("eax_1", Integer(32, True), 7, False, None))
    var_1_5 = Variable("var_1", Integer(32, True), None, False, Variable("ecx_1", Integer(32, True), 4, False, None))
    var_1_6 = Variable("var_1", Integer(32, True), None, False, Variable("eax_1", Integer(32, True), 14, False, None))
    var_1_7 = Variable("var_1", Integer(32, True), None, False, Variable("ecx_1", Integer(32, True), 3, False, None))
    var_1_8 = Variable("var_1", Integer(32, True), None, False, Variable("eax_1", Integer(32, True), 8, False, None))
    var_2_1 = Variable("var_2", Integer(32, True), None, False, Variable("ecx_1", Integer(32, True), 2, False, None))
    var_2_2 = Variable("var_2", Integer(32, True), None, False, Variable("var_20_4", Integer(32, True), 14, False, None))
    var_3 = Variable("var_3", int_pointer32, None, False, Variable("var_28", int_pointer32, 1, False, None))
    var_4_1 = Variable("var_4", void_pointer, None, False, Variable("edx_2", void_pointer, 3, False, None))
    var_4_2 = Variable("var_4", void_pointer, None, False, Variable("edx_2", void_pointer, 4, False, None))
    var_4_3 = Variable("var_4", void_pointer, None, False, Variable("edx_2", void_pointer, 5, False, None))
    var_5_1 = Variable("var_5", int_pointer8, None, False, Variable("eax_3", int_pointer8, 15, False, None))
    var_5_2 = Variable("var_5", int_pointer8, None, False, Variable("eax_2", int_pointer8, 13, False, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], void_pointer, 1)),
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 2)),
                    Assignment(var_3, UnaryOperation(OperationType.address, [var_0], int_pointer32, None, False)),
                    Assignment(ListOperation([var_2_1]), scanf_call(var_3, "%d", 3)),
                    Assignment(var_1_1, BinaryOperation(OperationType.minus, [var_0, Constant(1, Integer(32, True))], Integer(32, True))),
                    Branch(Condition(OperationType.greater_us, [var_1_1, Constant(6, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(
                1,
                [
                    Assignment(var_5_1, Constant("Invalid input! Please enter week number between 1-7.", Pointer(Integer(8, False), 32))),
                    Assignment(var_2_2, var_1_1),
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(
                        var_4_1,
                        BinaryOperation(
                            OperationType.plus,
                            [
                                UnaryOperation(
                                    OperationType.dereference,
                                    [
                                        BinaryOperation(
                                            OperationType.plus,
                                            [
                                                BinaryOperation(
                                                    OperationType.plus,
                                                    [
                                                        Constant(90064, void_pointer),
                                                        BinaryOperation(
                                                            OperationType.left_shift,
                                                            [var_1_1, Constant(2, Integer(8, True))],
                                                            Integer(32, True),
                                                        ),
                                                    ],
                                                    void_pointer,
                                                ),
                                                Constant(4294956816, Integer(32, True)),
                                            ],
                                            void_pointer,
                                        )
                                    ],
                                    Integer(32, True),
                                    None,
                                    False,
                                ),
                                Constant(90064, void_pointer),
                            ],
                            void_pointer,
                        ),
                    ),
                    IndirectBranch(var_1_1),
                ],
            ),
            BasicBlock(
                3,
                [
                    Assignment(ListOperation([]), printf_chk_call(var_5_1, var_1_2, var_2_2, 13)),
                    Return(ListOperation([Constant(0, Integer(32, True))])),
                ],
            ),
            BasicBlock(4, [Assignment(var_5_2, Constant("Monday", Pointer(Integer(8, False), 32)))]),
            BasicBlock(5, [Assignment(var_5_2, Constant("Tuesday", Pointer(Integer(8, False), 32)))]),
            BasicBlock(6, [Assignment(ListOperation([var_4_2]), printf_chk_call("Wednesday", var_1_3, var_1_3, 5))]),
            BasicBlock(7, [Assignment(ListOperation([var_1_4]), printf_chk_call("Thursday", var_1_1, var_1_1, 6))]),
            BasicBlock(8, [Assignment(var_5_1, Constant("Friday", Pointer(Integer(8, False), 32))), Assignment(var_2_2, var_1_8)]),
            BasicBlock(
                9,
                [Assignment(ListOperation([var_1_7]), printf_chk_call("Sunday", var_4_3, var_4_3, 9))],
            ),
            BasicBlock(10, [Assignment(var_5_1, Constant("Saturday", Pointer(Integer(8, False), 32))), Assignment(var_2_2, var_1_5)]),
            BasicBlock(11, [Assignment(ListOperation([var_1_6]), printf_chk_call(var_5_2, var_1_1, var_1_1, 11))]),
            BasicBlock(15, [Assignment(var_1_5, var_2_1)]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            SwitchCase(vertices[2], vertices[4], [Constant(0, Integer(32, True))]),
            SwitchCase(vertices[2], vertices[5], [Constant(1, Integer(32, True))]),
            SwitchCase(vertices[2], vertices[7], [Constant(3, Integer(32, True))]),
            SwitchCase(vertices[2], vertices[12], [Constant(5, Integer(32, True))]),
            SwitchCase(vertices[2], vertices[6], [Constant(2, Integer(32, True))]),
            SwitchCase(vertices[2], vertices[8], [Constant(4, Integer(32, True))]),
            SwitchCase(vertices[2], vertices[9], [Constant(6, Integer(32, True))]),
            UnconditionalEdge(vertices[4], vertices[11]),
            UnconditionalEdge(vertices[5], vertices[11]),
            UnconditionalEdge(vertices[6], vertices[9]),
            UnconditionalEdge(vertices[7], vertices[8]),
            UnconditionalEdge(vertices[8], vertices[3]),
            UnconditionalEdge(vertices[9], vertices[10]),
            UnconditionalEdge(vertices[10], vertices[3]),
            UnconditionalEdge(vertices[11], vertices[6]),
            UnconditionalEdge(vertices[12], vertices[10]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    # initial part
    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 12
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(cond_node := seq_node.children[1], ConditionNode)
    assert all(
        isinstance(child, ConditionNode) and child.false_branch is None and isinstance(child.true_branch_child, CodeNode)
        for child in seq_node.children[2:11]
    )
    assert isinstance(seq_node.children[11], CodeNode) and seq_node.children[11].instructions == vertices[3].instructions

    # condition node
    if (cond := cond_node.condition).is_symbol:
        default_branch = cond_node.true_branch_child
        switch_branch = cond_node.false_branch_child
        assert task._ast.condition_map[cond] == vertices[0].instructions[-1].condition
    else:
        default_branch = cond_node.false_branch_child
        switch_branch = cond_node.true_branch_child
        assert task._ast.condition_map[~cond] == vertices[0].instructions[-1].condition

    # default branch
    assert isinstance(default_branch, CodeNode) and default_branch.instructions == vertices[1].instructions
    # before_switch branch
    assert isinstance(switch_branch, CodeNode) and switch_branch.instructions == vertices[2].instructions[:-1]

    # all switch-cases
    assert seq_node.children[2].true_branch_child.instructions == vertices[4].instructions
    assert task._ast.condition_map[seq_node.children[2].condition] == Condition(
        OperationType.equal, [var_1_1, Constant(0, Integer(32, True))]
    )
    assert seq_node.children[3].true_branch_child.instructions == vertices[5].instructions
    assert task._ast.condition_map[seq_node.children[3].condition] == Condition(
        OperationType.equal, [var_1_1, Constant(1, Integer(32, True))]
    )
    assert seq_node.children[4].true_branch_child.instructions == vertices[12].instructions
    assert task._ast.condition_map[seq_node.children[4].condition] == Condition(
        OperationType.equal, [var_1_1, Constant(5, Integer(32, True))]
    )
    assert seq_node.children[5].true_branch_child.instructions == vertices[7].instructions
    assert task._ast.condition_map[seq_node.children[5].condition] == Condition(
        OperationType.equal, [var_1_1, Constant(3, Integer(32, True))]
    )
    assert seq_node.children[6].true_branch_child.instructions == vertices[11].instructions
    assert seq_node.children[6].condition.is_disjunction and len(arguments := seq_node.children[6].condition.operands) == 2
    assert {task._ast.condition_map[arg] for arg in arguments} == {
        Condition(OperationType.equal, [var_1_1, Constant(0, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(1, Integer(32, True))]),
    }
    assert seq_node.children[7].true_branch_child.instructions == vertices[8].instructions
    assert seq_node.children[7].condition.is_disjunction and len(arguments := seq_node.children[7].condition.operands) == 2
    assert {task._ast.condition_map[arg] for arg in arguments} == {
        Condition(OperationType.equal, [var_1_1, Constant(3, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(4, Integer(32, True))]),
    }
    assert seq_node.children[8].true_branch_child.instructions == vertices[6].instructions
    assert seq_node.children[8].condition.is_disjunction and len(arguments := seq_node.children[8].condition.operands) == 3
    assert {task._ast.condition_map[arg] for arg in arguments} == {
        Condition(OperationType.equal, [var_1_1, Constant(0, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(1, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(2, Integer(32, True))]),
    }
    assert seq_node.children[9].true_branch_child.instructions == vertices[9].instructions
    assert seq_node.children[9].condition.is_disjunction and len(arguments := seq_node.children[9].condition.operands) == 4
    assert {task._ast.condition_map[arg] for arg in arguments} == {
        Condition(OperationType.equal, [var_1_1, Constant(0, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(1, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(2, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(6, Integer(32, True))]),
    }
    assert seq_node.children[10].true_branch_child.instructions == vertices[10].instructions
    assert seq_node.children[10].condition.is_disjunction and len(arguments := seq_node.children[10].condition.operands) == 5
    assert {task._ast.condition_map[arg] for arg in arguments} == {
        Condition(OperationType.equal, [var_1_1, Constant(0, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(1, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(2, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(5, Integer(32, True))]),
        Condition(OperationType.equal, [var_1_1, Constant(6, Integer(32, True))]),
    }


def test_combine_switch_nodes(task):
    """test to check that we combine switch nodes if possible and does not insert empty sequence node when removing."""

    def non_branch_assignments(old_var: str, mem1: int, mem2: int) -> List[Assignment]:
        var_2 = Variable(
            "var_2", Pointer(Integer(32, True), 32), None, False, Variable(old_var, Pointer(Integer(32, True), 32), mem1, False, None)
        )
        return [
            Assignment(
                var_2,
                UnaryOperation(
                    OperationType.address,
                    [Variable("var_20", Integer(32, True), None, True, Variable("var_85", Integer(32, True), 4, True, None))],
                    Pointer(Integer(32, True), 32),
                    None,
                    False,
                ),
            ),
            Assignment(
                ListOperation([]),
                Call(
                    imp_function_symbol("__strcat_chk"),
                    [var_2, Constant("0123456789ABCDE", Pointer(Integer(8, False), 32)), Constant(65, Integer(32, True))],
                    Pointer(CustomType("void", 0), 32),
                    mem2,
                ),
            ),
        ]

    switch_var = Variable("var_12", Integer(32, False), None, False, Variable("eax_10", Integer(32, False), 12, False, None))

    def branch_condition(constant: int) -> Branch:
        """returns branch condition"""
        return Branch(Condition(OperationType.not_equal, [switch_var, Constant(constant, Integer(32, True))], CustomType("bool", 1)))

    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [Branch(Condition(OperationType.less_or_equal, [switch_var, Constant(1100, Integer(32, True))], CustomType("bool", 1)))],
            ),
            BasicBlock(1, [branch_condition(1010)]),
            BasicBlock(2, [branch_condition(1110)]),
            BasicBlock(3, non_branch_assignments("var_bc_18", 8, 17)),
            BasicBlock(4, [branch_condition(1011)]),
            BasicBlock(5, non_branch_assignments("var_bc_20", 11, 20)),
            BasicBlock(6, [branch_condition(1111)]),
            BasicBlock(7, [branch_condition(1001)]),
            BasicBlock(8, non_branch_assignments("var_bc_7", 10, 19)),
            BasicBlock(9, [branch_condition(1101)]),
            BasicBlock(10, non_branch_assignments("var_bc_6", 13, 2)),
            BasicBlock(11, non_branch_assignments("var_bc_8", 9, 18)),
            BasicBlock(12, non_branch_assignments("var_bc_9", 12, 21)),
            BasicBlock(13, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(
                14, [Branch(Condition(OperationType.less_or_equal, [switch_var, Constant(1111, Integer(32, True))], CustomType("bool", 1)))]
            ),
            BasicBlock(15, non_branch_assignments("var_bc_4", 34, 54)),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[14], vertices[0]),
            FalseCase(vertices[14], vertices[15]),
            UnconditionalEdge(vertices[15], vertices[13]),
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            TrueCase(vertices[1], vertices[4]),
            FalseCase(vertices[2], vertices[5]),
            TrueCase(vertices[2], vertices[6]),
            UnconditionalEdge(vertices[3], vertices[13]),
            TrueCase(vertices[4], vertices[7]),
            FalseCase(vertices[4], vertices[8]),
            UnconditionalEdge(vertices[5], vertices[13]),
            TrueCase(vertices[6], vertices[9]),
            FalseCase(vertices[6], vertices[10]),
            FalseCase(vertices[7], vertices[11]),
            TrueCase(vertices[7], vertices[13]),
            UnconditionalEdge(vertices[8], vertices[13]),
            FalseCase(vertices[9], vertices[12]),
            TrueCase(vertices[9], vertices[13]),
            UnconditionalEdge(vertices[10], vertices[13]),
            UnconditionalEdge(vertices[11], vertices[13]),
            UnconditionalEdge(vertices[12], vertices[13]),
        ]
    )
    task.graph.root = vertices[14]

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    if isinstance(switch := seq_node.children[0], SwitchNode):
        assert isinstance(cn := seq_node.children[1], ConditionNode)
    else:
        isinstance(switch := seq_node.children[1], SwitchNode)
        assert isinstance(cn := seq_node.children[0], ConditionNode)
    assert isinstance(child := cn.true_branch_child, CodeNode) and child.instructions == vertices[15].instructions
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[13].instructions

    # switch node:
    assert switch.expression == switch_var and len(switch.children) == 6
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1001, Integer(32, True)) and case1.break_case
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(1010, Integer(32, True)) and case2.break_case
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(1011, Integer(32, True)) and case3.break_case
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(1101, Integer(32, True)) and case4.break_case
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(1110, Integer(32, True)) and case5.break_case
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(1111, Integer(32, True)) and case6.break_case

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[11].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[3].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[8].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[12].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[5].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[10].instructions


def test_can_not_combine_switch_placement(task):
    """test to check that we do not combine switch nodes when we can not place the new one (test_switch test 27)."""

    def print_call_binary_op(var: Variable, const: int, address: int, memory: int) -> Call:
        return Call(
            imp_function_symbol("printf"),
            [
                Constant(address, Integer(32, True)),
                BinaryOperation(OperationType.plus, [var, Constant(const, Integer(32, True))], Integer(32, True)),
            ],
            Pointer(CustomType("void", 0), 32),
            memory,
        )

    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_1 = Variable("var_1", Integer(32, True), None, True, Variable("arg_4", Integer(32, True), 0, True, None))
    var_1_1 = Variable("var_1", Integer(32, True), None, True, Variable("arg_4", Integer(32, True), 6, True, None))
    var_2 = Variable(
        "var_2", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    var_2_1 = Variable(
        "var_2", Pointer(Integer(32, True), 32), None, False, Variable("var_28_4", Pointer(Integer(32, True), 32), 6, False, None)
    )
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_2, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_2, 134529061, 2)),
                    Branch(Condition(OperationType.equal, [var_0, Constant(5, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Assignment(ListOperation([]), print_call_binary_op(var_1, 3, 134529061, 3))]),
            BasicBlock(2, [Branch(Condition(OperationType.greater, [var_0, Constant(5, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                3,
                [
                    Assignment(var_2_1, UnaryOperation(OperationType.address, [var_1_1], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_2_1, 134529061, 7)),
                    Branch(Condition(OperationType.equal, [var_0, Constant(6, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(4, [Branch(Condition(OperationType.equal, [var_0, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call_binary_op(var_1_1, 3, 134529061, 8))]),
            BasicBlock(6, [Branch(Condition(OperationType.greater, [var_0, Constant(6, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call_binary_op(var_1, 1, 134529061, 4))]),
            BasicBlock(8, [Branch(Condition(OperationType.equal, [var_0, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(9, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(10, [Branch(Condition(OperationType.equal, [var_0, Constant(2, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(11, [Assignment(ListOperation([]), print_call_binary_op(var_1, 2, 134529061, 5))]),
            BasicBlock(12, [Assignment(ListOperation([]), print_call_binary_op(var_1_1, 1, 134529061, 9))]),
            BasicBlock(13, [Branch(Condition(OperationType.equal, [var_0, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(14, [Assignment(ListOperation([]), print_call_binary_op(var_1_1, 2, 134529061, 10))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            FalseCase(vertices[2], vertices[4]),
            TrueCase(vertices[2], vertices[3]),
            TrueCase(vertices[3], vertices[5]),
            FalseCase(vertices[3], vertices[6]),
            TrueCase(vertices[4], vertices[7]),
            FalseCase(vertices[4], vertices[8]),
            UnconditionalEdge(vertices[5], vertices[9]),
            FalseCase(vertices[6], vertices[10]),
            TrueCase(vertices[6], vertices[9]),
            UnconditionalEdge(vertices[7], vertices[3]),
            TrueCase(vertices[8], vertices[11]),
            FalseCase(vertices[8], vertices[3]),
            TrueCase(vertices[10], vertices[12]),
            FalseCase(vertices[10], vertices[13]),
            UnconditionalEdge(vertices[11], vertices[3]),
            UnconditionalEdge(vertices[12], vertices[9]),
            TrueCase(vertices[13], vertices[14]),
            FalseCase(vertices[13], vertices[9]),
            UnconditionalEdge(vertices[14], vertices[9]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 5
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch1 := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[3].instructions[:-1]
    assert isinstance(switch2 := seq_node.children[3], SwitchNode)
    assert isinstance(seq_node.children[4], CodeNode) and seq_node.children[4].instructions == vertices[9].instructions

    # switch node 1:
    assert switch1.expression == var_0 and len(switch1.children) == 3
    assert isinstance(case1 := switch1.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32, True)) and case1.break_case
    assert isinstance(case2 := switch1.cases[1], CaseNode) and case2.constant == Constant(3, Integer(32, True)) and case2.break_case
    assert isinstance(case3 := switch1.cases[2], CaseNode) and case3.constant == Constant(5, Integer(32, True)) and case3.break_case

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[7].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[11].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[1].instructions

    # switch node 2:
    assert switch2.expression == var_0 and len(switch1.children) == 3
    assert isinstance(case1 := switch2.cases[0], CaseNode) and case1.constant == Constant(2, Integer(32, True)) and case1.break_case
    assert isinstance(case2 := switch2.cases[1], CaseNode) and case2.constant == Constant(4, Integer(32, True)) and case2.break_case
    assert isinstance(case3 := switch2.cases[2], CaseNode) and case3.constant == Constant(6, Integer(32, True)) and case3.break_case

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[12].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[14].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[5].instructions


def test_can_not_combine_not_same_expression(task):
    """test to check that we do not combine switch nodes when they have the same-expression in non-SSA but not SSA (test_switch test 28)."""
    arg_1_0 = Variable("arg1", Integer(32, True), None, False, Variable("arg1", Integer(32, True), 0, False, None))
    arg_1_1 = Variable("arg1", Integer(32, True), None, False, Variable("c0", Integer(32, True), 0, False, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, [Branch(Condition(OperationType.equal, [arg_1_0, Constant(5, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(1, [Assignment(ListOperation([]), print_call("Wednesday", 1))]),
            BasicBlock(2, [Branch(Condition(OperationType.greater, [arg_1_0, Constant(5, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                3,
                [
                    Assignment(arg_1_1, BinaryOperation(OperationType.plus, [arg_1_0, Constant(2, Integer(32, True))], Integer(32, True))),
                    Branch(Condition(OperationType.equal, [arg_1_1, Constant(6, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(4, [Branch(Condition(OperationType.equal, [arg_1_0, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("Saturday", 5))]),
            BasicBlock(6, [Branch(Condition(OperationType.greater, [arg_1_1, Constant(6, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Monday", 2))]),
            BasicBlock(8, [Branch(Condition(OperationType.equal, [arg_1_0, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(9, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(10, [Branch(Condition(OperationType.equal, [arg_1_1, Constant(2, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(11, [Assignment(ListOperation([]), print_call("Tuesday", 3))]),
            BasicBlock(12, [Assignment(ListOperation([]), print_call("Thursday", 6))]),
            BasicBlock(13, [Branch(Condition(OperationType.equal, [arg_1_1, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(14, [Assignment(ListOperation([]), print_call("Friday", 7))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            FalseCase(vertices[2], vertices[4]),
            TrueCase(vertices[2], vertices[3]),
            TrueCase(vertices[3], vertices[5]),
            FalseCase(vertices[3], vertices[6]),
            TrueCase(vertices[4], vertices[7]),
            FalseCase(vertices[4], vertices[8]),
            UnconditionalEdge(vertices[5], vertices[9]),
            FalseCase(vertices[6], vertices[10]),
            TrueCase(vertices[6], vertices[9]),
            UnconditionalEdge(vertices[7], vertices[3]),
            TrueCase(vertices[8], vertices[11]),
            FalseCase(vertices[8], vertices[3]),
            TrueCase(vertices[10], vertices[12]),
            FalseCase(vertices[10], vertices[13]),
            UnconditionalEdge(vertices[11], vertices[3]),
            UnconditionalEdge(vertices[12], vertices[9]),
            TrueCase(vertices[13], vertices[14]),
            FalseCase(vertices[13], vertices[9]),
            UnconditionalEdge(vertices[14], vertices[9]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 4
    assert isinstance(switch1 := seq_node.children[0], SwitchNode)
    assert isinstance(seq_node.children[1], CodeNode) and seq_node.children[1].instructions == vertices[3].instructions[:-1]
    assert isinstance(switch2 := seq_node.children[2], SwitchNode)
    assert isinstance(seq_node.children[3], CodeNode) and seq_node.children[3].instructions == vertices[9].instructions

    # switch node 1:
    assert switch1.expression == arg_1_0 and len(switch1.children) == 3
    assert isinstance(case1 := switch1.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32, True)) and case1.break_case
    assert isinstance(case2 := switch1.cases[1], CaseNode) and case2.constant == Constant(3, Integer(32, True)) and case2.break_case
    assert isinstance(case3 := switch1.cases[2], CaseNode) and case3.constant == Constant(5, Integer(32, True)) and case3.break_case

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[7].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[11].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[1].instructions

    # switch node 2:
    assert switch2.expression == arg_1_1 and len(switch1.children) == 3
    assert isinstance(case1 := switch2.cases[0], CaseNode) and case1.constant == Constant(2, Integer(32, True)) and case1.break_case
    assert isinstance(case2 := switch2.cases[1], CaseNode) and case2.constant == Constant(4, Integer(32, True)) and case2.break_case
    assert isinstance(case3 := switch2.cases[2], CaseNode) and case3.constant == Constant(6, Integer(32, True)) and case3.break_case

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[12].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[14].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[5].instructions


def test_find_default_if_edge_exists(task):
    """test switch test7 -> compiled on 64bit architecture and with optimization level 3."""
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_c", Integer(32, True), 0, True, None))
    var_1 = Variable("var_1", Pointer(Integer(32, True), 64), None, False, Variable("rsi", Pointer(Integer(32, True), 64), 1, False, None))
    var_0_1 = Variable("var_0", Integer(32, True), None, True, Variable("var_c", Integer(32, True), 2, True, None))
    task._cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call64(4199931, 4210704, 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 64), None, False)),
                    Assignment(ListOperation([]), scanf_call64(var_1, 4211523, 2)),
                    Branch(Condition(OperationType.greater, [var_0_1, Constant(40, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.not_equal, [var_0_1, Constant(500, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                2, [Branch(Condition(OperationType.less_or_equal, [var_0_1, Constant(0, Integer(32, True))], CustomType("bool", 1)))]
            ),
            BasicBlock(3, []),
            BasicBlock(
                4,
                [Assignment(ListOperation([]), print_call64(4199998, 4210763, 3)), Return(ListOperation([Constant(0, Integer(64, True))]))],
            ),
            BasicBlock(5, []),
            BasicBlock(6, [Branch(Condition(OperationType.greater_us, [var_0_1, Constant(40, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                7,
                [
                    Assignment(ListOperation([]), print_call64(4200023, 4211792, 10)),
                    Return(ListOperation([Constant(0, Integer(64, True))])),
                ],
            ),
            BasicBlock(8, []),
            BasicBlock(9, [IndirectBranch(var_0_1)]),
            BasicBlock(
                10,
                [Assignment(ListOperation([]), print_call64(4200047, 4210729, 4)), Return(ListOperation([Constant(0, Integer(64, True))]))],
            ),
            BasicBlock(
                11,
                [Assignment(ListOperation([]), print_call64(4200071, 4210770, 5)), Return(ListOperation([Constant(0, Integer(64, True))]))],
            ),
            BasicBlock(
                12,
                [Assignment(ListOperation([]), print_call64(4200095, 4210779, 6)), Return(ListOperation([Constant(0, Integer(64, True))]))],
            ),
            BasicBlock(
                13,
                [Assignment(ListOperation([]), print_call64(4200119, 4210736, 7)), Return(ListOperation([Constant(0, Integer(64, True))]))],
            ),
            BasicBlock(
                14,
                [Assignment(ListOperation([]), print_call64(4200143, 4210744, 8)), Return(ListOperation([Constant(0, Integer(64, True))]))],
            ),
            BasicBlock(
                15,
                [Assignment(ListOperation([]), print_call64(4200167, 4210754, 9)), Return(ListOperation([Constant(0, Integer(64, True))]))],
            ),
        ]
    )
    task._cfg.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[1], vertices[4]),
            TrueCase(vertices[2], vertices[5]),
            FalseCase(vertices[2], vertices[6]),
            UnconditionalEdge(vertices[3], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[7]),
            TrueCase(vertices[6], vertices[8]),
            FalseCase(vertices[6], vertices[9]),
            UnconditionalEdge(vertices[8], vertices[7]),
            SwitchCase(vertices[9], vertices[7], [Constant(i, UnknownType()) for i in range(2, 40) if i not in {6, 9, 12, 34}]),
            SwitchCase(vertices[9], vertices[10], [Constant(1, UnknownType())]),
            SwitchCase(vertices[9], vertices[11], [Constant(6, UnknownType())]),
            SwitchCase(vertices[9], vertices[12], [Constant(9, UnknownType())]),
            SwitchCase(vertices[9], vertices[13], [Constant(12, UnknownType())]),
            SwitchCase(vertices[9], vertices[14], [Constant(34, UnknownType())]),
            SwitchCase(vertices[9], vertices[15], [Constant(40, UnknownType())]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 2
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, UnknownType()) and case1.break_case is False
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(6, UnknownType()) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(9, UnknownType()) and case3.break_case is False
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(12, UnknownType()) and case4.break_case is False
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(34, UnknownType()) and case5.break_case is False
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(40, UnknownType()) and case6.break_case is False
    assert (
        isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(500, Integer(32, True)) and case7.break_case is False
    )
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[10].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[11].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[12].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[13].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[14].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[15].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[4].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[7].instructions


def test_fallthrough_reaching_problem(task):
    """
    Make sure that adding reachability for fallthrough-cases does not lead to cyclic code node reachability
    sample structure from: coreutils/dircolors append_quoted
    """
    var_2 = Variable("var_2", Integer(64, False), None, False, Variable("rax_5", Integer(64, False), 1, False, None))
    var_2_2 = Variable("var_2", Integer(64, False), None, False, Variable("rax_5", Integer(64, False), 2, False, None))
    cast_var_2 = UnaryOperation(OperationType.cast, [var_2_2], Integer(8, False))

    arg_1 = Variable("arg1", Pointer(Integer(8, True), 64), None, False, Variable("arg1", Pointer(Integer(8, True), 64), 0))
    var_0 = Variable("var_0", Pointer(Integer(8, True), 64), None, False, Variable("rbp", Pointer(Integer(8, True), 64), 3, False, None))
    var_3 = Variable("var_3", Integer(32, True), None, False, Variable("rbx", Integer(32, True), 2, False, None))
    var_4 = Variable("var_4", Integer(64, True), None, False, Variable("rcx_1", Integer(64, True), 2, False, None))
    var_5 = Variable("var_5", Integer(64, True), None, False, Variable("rdx_1", Integer(64, True), 2, False, None))
    var_6 = Variable("var_6", Integer(64, True), None, False, Variable("rax_1", Integer(64, True), 2, False, None))
    task._cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(var_4, Constant(49440, Integer(64, True))),
                    Branch(Condition(OperationType.equal, [cast_var_2, Constant(61, Integer(8, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.greater, [cast_var_2, Constant(61, Integer(8, True))], CustomType("bool", 1)))]),
            BasicBlock(2, [Branch(Condition(OperationType.equal, [var_3, Constant(0, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                3,
                [
                    Assignment(var_3, BinaryOperation(OperationType.plus, [var_3, Constant(1, Integer(32, True))], Integer(32, True))),
                    Branch(Condition(OperationType.not_equal, [cast_var_2, Constant(92, Integer(8, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(4, [Branch(Condition(OperationType.equal, [cast_var_2, Constant(39, Integer(8, True))], CustomType("bool", 1)))]),
            BasicBlock(5, [Branch(Condition(OperationType.equal, [var_3, var_4], CustomType("bool", 1)))]),
            BasicBlock(6, [Assignment(var_3, Constant(1, Integer(32, True)))]),
            BasicBlock(7, [Branch(Condition(OperationType.equal, [var_3, var_4], CustomType("bool", 1)))]),
            BasicBlock(
                8, [Branch(Condition(OperationType.not_equal, [cast_var_2, Constant(58, Integer(8, True))], CustomType("bool", 1)))]
            ),
            BasicBlock(9, [Assignment(var_3, Constant(1, Integer(32, True)))]),
            BasicBlock(10, [Assignment(var_5, Constant(25632, Integer(64, True)))]),
            BasicBlock(11, [Assignment(var_5, Constant(49432, Integer(64, True)))]),
            BasicBlock(12, [Branch(Condition(OperationType.equal, [var_4, var_5], CustomType("bool", 1)))]),
            BasicBlock(
                13,
                [
                    Assignment(var_5, Constant(49432, Integer(64, True))),
                    Branch(Condition(OperationType.not_equal, [var_3, var_4], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(
                14,
                [
                    Assignment(var_4, Constant(49432, Integer(64, True))),
                    Branch(Condition(OperationType.equal, [var_3, var_4], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(15, [Assignment(var_4, Constant(49432, Integer(64, True)))]),
            BasicBlock(16, [Assignment(var_5, Constant(49432, Integer(64, True)))]),
            BasicBlock(17, [Return(ListOperation([var_6]))]),
            BasicBlock(
                18,
                [
                    Assignment(var_4, Constant(49432, Integer(64, True))),
                    Branch(Condition(OperationType.equal, [var_3, var_4], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(19, [Assignment(var_4, Constant(49432, Integer(64, True)))]),
            BasicBlock(20, [Assignment(var_3, Constant(1, Integer(32, True)))]),
        ]
    )
    task._cfg.add_edges_from(
        [
            TrueCase(vertices[0], vertices[2]),
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[1], vertices[4]),
            FalseCase(vertices[2], vertices[5]),
            TrueCase(vertices[2], vertices[9]),
            TrueCase(vertices[3], vertices[6]),
            FalseCase(vertices[3], vertices[12]),
            TrueCase(vertices[4], vertices[7]),
            FalseCase(vertices[4], vertices[8]),
            TrueCase(vertices[5], vertices[10]),
            FalseCase(vertices[5], vertices[13]),
            UnconditionalEdge(vertices[6], vertices[12]),
            TrueCase(vertices[7], vertices[11]),
            FalseCase(vertices[7], vertices[14]),
            TrueCase(vertices[8], vertices[9]),
            FalseCase(vertices[8], vertices[2]),
            UnconditionalEdge(vertices[9], vertices[12]),
            UnconditionalEdge(vertices[10], vertices[13]),
            UnconditionalEdge(vertices[11], vertices[14]),
            TrueCase(vertices[12], vertices[16]),
            FalseCase(vertices[12], vertices[17]),
            TrueCase(vertices[13], vertices[17]),
            FalseCase(vertices[13], vertices[16]),
            TrueCase(vertices[14], vertices[15]),
            FalseCase(vertices[14], vertices[18]),
            UnconditionalEdge(vertices[15], vertices[18]),
            UnconditionalEdge(vertices[16], vertices[17]),
            TrueCase(vertices[18], vertices[19]),
            FalseCase(vertices[18], vertices[20]),
            UnconditionalEdge(vertices[19], vertices[20]),
            UnconditionalEdge(vertices[20], vertices[12]),
        ]
    )

    PatternIndependentRestructuring().run(task)
    condition_map = task.syntax_tree.condition_map

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 5
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(cond := seq_node.children[1], ConditionNode)
    assert isinstance(switch := seq_node.children[2], SwitchNode)
    assert isinstance(cond_16 := seq_node.children[3], ConditionNode)
    assert isinstance(seq_node.children[4], CodeNode) and seq_node.children[4].instructions == vertices[17].instructions

    # reconstruct first condition node
    if cond.condition.is_negation:
        cond.switch_branches()
    assert cond.condition.is_symbol and condition_map[cond.condition] == vertices[1].instructions[-1].condition
    assert isinstance(true_branch := cond.true_branch_child, SeqNode) and isinstance(false_branch := cond.false_branch_child, ConditionNode)
    # True Branch
    assert len(true_branch.children) == 2
    assert isinstance(true_branch.children[0], CodeNode) and true_branch.children[0].instructions == vertices[3].instructions[:-1]
    assert (
        isinstance(true_branch.children[1], ConditionNode)
        and condition_map[true_branch.children[1].condition] == vertices[3].instructions[-1].condition
    )
    assert (
        true_branch.children[1].false_branch is None
        and isinstance(true_branch.children[1].true_branch_child, CodeNode)
        and true_branch.children[1].true_branch_child.instructions == vertices[6].instructions
    )
    # False Branch
    assert isinstance(false_branch, ConditionNode) and false_branch.false_branch is None
    assert isinstance(false_branch.true_branch_child, CodeNode) and false_branch.true_branch_child.instructions == vertices[9].instructions

    # switch node:
    assert switch.expression == cast_var_2.copy() and len(switch.children) == 3
    assert (
        isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(0x27, Integer(8, True)) and case1.break_case is True
    )
    assert (
        isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(0x3A, Integer(8, True)) and case2.break_case is False
    )
    assert (
        isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(0x3D, Integer(8, True)) and case3.break_case is True
    )
    # case 1
    assert isinstance(seq_1 := case1.child, SeqNode) and len(seq_1.children) == 6
    assert isinstance(cond := seq_1.children[0], ConditionNode) and condition_map[cond.condition] == vertices[7].instructions[-1].condition
    assert cond.false_branch is None and cond.true_branch_child.instructions == vertices[11].instructions
    assert isinstance(seq_1.children[1], CodeNode) and seq_1.children[1].instructions == vertices[14].instructions[:-1]
    assert isinstance(cond := seq_1.children[2], ConditionNode) and condition_map[cond.condition] == vertices[14].instructions[-1].condition
    assert cond.false_branch is None and cond.true_branch_child.instructions == vertices[15].instructions
    assert isinstance(seq_1.children[3], CodeNode) and seq_1.children[3].instructions == vertices[18].instructions[:-1]
    assert isinstance(cond := seq_1.children[4], ConditionNode) and condition_map[cond.condition] == vertices[18].instructions[-1].condition
    assert cond.false_branch is None and cond.true_branch_child.instructions == vertices[19].instructions
    assert isinstance(seq_1.children[5], CodeNode) and seq_1.children[5].instructions == vertices[20].instructions
    # case 2
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == []
    # case 3
    assert isinstance(cond_3 := case3.child, ConditionNode) and condition_map[~cond_3.condition] == vertices[2].instructions[-1].condition
    assert cond_3.false_branch is None and isinstance(cond_3_seq := cond_3.true_branch_child, SeqNode) and len(cond_3_seq.children) == 2
    assert (
        isinstance(nest_cond := cond_3_seq.children[0], ConditionNode)
        and condition_map[nest_cond.condition] == vertices[5].instructions[-1].condition
    )
    assert (
        nest_cond.false_branch is None
        and isinstance(nest_cond.true_branch_child, CodeNode)
        and nest_cond.true_branch_child.instructions == vertices[10].instructions
    )
    assert isinstance(cond_3_seq.children[1], CodeNode) and cond_3_seq.children[1].instructions == vertices[13].instructions[:-1]

    # reconstruct second condition
    assert (
        cond_16.false_branch is None
        and isinstance(cn := cond_16.true_branch_child, CodeNode)
        and cn.instructions == vertices[16].instructions
    )


def test_only_one_occurrence_of_each_case(task):
    """Insert cases that already occur."""
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    arg1 = Variable("arg1", Integer(32, True), None, True, Variable("arg1", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(var_1, UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.not_equal, [var_0, Constant(1, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.not_equal, [arg1, Constant(7, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(2, [Branch(Condition(OperationType.not_equal, [var_0, Constant(2, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                3,
                [Assignment(ListOperation([]), print_call("The Input is 7 and you choose week number %d", 2)), Assignment(var_1, var_0)],
            ),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("Tuesday", 3))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("common case", 4))]),
            BasicBlock(6, [Branch(Condition(OperationType.not_equal, [var_0, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Wednesday", 5))]),
            BasicBlock(8, [Branch(Condition(OperationType.not_equal, [var_0, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Thursday", 6))]),
            BasicBlock(10, [Branch(Condition(OperationType.not_equal, [var_0, Constant(5, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(11, [Assignment(ListOperation([]), print_call("Friday", 7))]),
            BasicBlock(12, [Branch(Condition(OperationType.not_equal, [var_0, Constant(6, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(13, [Assignment(ListOperation([]), print_call("Saturday", 8))]),
            BasicBlock(14, [Branch(Condition(OperationType.not_equal, [var_0, Constant(7, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(15, [Assignment(ListOperation([]), print_call("Sunday", 9))]),
            BasicBlock(16, [Branch(Condition(OperationType.not_equal, [var_0, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(17, [Assignment(ListOperation([]), print_call("Monday", 10))]),
            BasicBlock(18, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[3], vertices[5]),
            FalseCase(vertices[2], vertices[4]),
            TrueCase(vertices[2], vertices[6]),
            UnconditionalEdge(vertices[4], vertices[6]),
            FalseCase(vertices[6], vertices[7]),
            TrueCase(vertices[6], vertices[8]),
            UnconditionalEdge(vertices[7], vertices[8]),
            FalseCase(vertices[8], vertices[9]),
            TrueCase(vertices[8], vertices[10]),
            UnconditionalEdge(vertices[9], vertices[10]),
            FalseCase(vertices[10], vertices[11]),
            TrueCase(vertices[10], vertices[12]),
            UnconditionalEdge(vertices[11], vertices[12]),
            FalseCase(vertices[12], vertices[13]),
            TrueCase(vertices[12], vertices[14]),
            UnconditionalEdge(vertices[13], vertices[14]),
            FalseCase(vertices[14], vertices[15]),
            TrueCase(vertices[14], vertices[16]),
            UnconditionalEdge(vertices[15], vertices[16]),
            TrueCase(vertices[16], vertices[18]),
            FalseCase(vertices[16], vertices[17]),
            UnconditionalEdge(vertices[17], vertices[5]),
            UnconditionalEdge(vertices[5], vertices[18]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode) and len(switch.cases) == 7
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant.value == 1 and isinstance(case1_seq := case1.child, SeqNode)
    assert all(case1.constant != case2.constant for case1, case2 in combinations(switch.cases, 2))
    assert len(case1_seq.children) == 3
    assert isinstance(cn := case1_seq.children[0], ConditionNode) and cn.false_branch is None
    assert isinstance(tb := cn.true_branch_child, CodeNode) and tb.instructions == vertices[3].instructions
    assert isinstance(cn := case1_seq.children[1], ConditionNode) and cn.false_branch is None
    assert isinstance(tb := cn.true_branch_child, CodeNode) and tb.instructions == vertices[17].instructions
    assert isinstance(cn := case1_seq.children[2], CodeNode) and cn.instructions == vertices[5].instructions
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[18].instructions


def test_case_0_different_condition(task):
    """
    Consideration of conditions as "a == b" as case 0 conditions for switch-statements with expressions a-b and b-a

    simplified version of test-samples/coreutils/shred main
    """
    argc = Variable("argc", Integer(32, True), None, False, Variable("argc", Integer(32, True), 0, False, None))
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_4 = Variable("arg1", Integer(32, True), None, True, Variable("eax", Integer(32, True), 1, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter any number: ", 1)),
                    Assignment(
                        ListOperation([]),
                        scanf_call(
                            UnaryOperation(OperationType.address, [var_4], Pointer(Integer(32, True), 32), None, False), 134524965, 2
                        ),
                    ),
                    Branch(Condition(OperationType.equal, [argc, var_4], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Assignment(var_4, BinaryOperation(OperationType.plus, [var_4, Constant(1, Integer(32, True))]))]),
            BasicBlock(
                2,
                [
                    Assignment(var_0, BinaryOperation(OperationType.left_shift, [var_4, Constant(3, Integer(32, True))])),
                    Branch(
                        Condition(
                            OperationType.not_equal,
                            [BinaryOperation(OperationType.minus, [argc, var_4]), Constant(1, Integer(32, True))],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(
                3,
                [Return(ListOperation([var_4]))],
            ),
            BasicBlock(
                4,
                [
                    Assignment(ListOperation([]), print_call("var_0", 3)),
                    Assignment(
                        ListOperation([]), Call(FunctionSymbol("usage", 10832), [Constant(1, Integer(32, True))], Integer(32, True), 11)
                    ),
                ],
            ),
            BasicBlock(5, [Assignment(var_4, BinaryOperation(OperationType.minus, [var_4, var_0]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            TrueCase(vertices[2], vertices[4]),
            FalseCase(vertices[2], vertices[5]),
            UnconditionalEdge(vertices[5], vertices[3]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    switch_nodes = list(task.syntax_tree.get_switch_nodes_post_order())
    assert len(switch_nodes) == 1
    assert len(switch_nodes[0].cases) == 2 and switch_nodes[0].default is not None
    assert vertices[0].instructions[-1].condition in task.syntax_tree.condition_map.values()


@pytest.mark.parametrize(
    "graph", [_basic_switch_cfg, _switch_empty_fallthrough, _switch_no_empty_fallthrough, _switch_in_switch, _switch_test_19]
)
def test_no_switch(graph, task):
    """Test construct no switch statement"""
    task.options.set("pattern-independent-restructuring.switch_reconstruction", False)
    graph(task)
    PatternIndependentRestructuring().run(task)

    assert len(list(task.syntax_tree.get_switch_nodes_post_order())) == 0


@pytest.mark.parametrize(
    "graph", [_basic_switch_cfg, _switch_empty_fallthrough, _switch_no_empty_fallthrough, _switch_in_switch, _switch_test_19]
)
def test_no_switch_in_switch(graph, task):
    """Test construct no switch-in-switch statement"""
    task.options.set("pattern-independent-restructuring.nested_switch_nodes", False)
    graph(task)
    PatternIndependentRestructuring().run(task)

    assert len(list(task.syntax_tree.get_switch_nodes_post_order())) == 1


@pytest.mark.parametrize(
    "graph", [_basic_switch_cfg, _switch_empty_fallthrough, _switch_no_empty_fallthrough, _switch_in_switch, _switch_test_19]
)
def test_min_bound_5(graph, task):
    """Test construct only a switch statement with at least 5 cases."""
    task.options.set("pattern-independent-restructuring.min_switch_case_number", 5)
    graph(task)
    PatternIndependentRestructuring().run(task)

    assert len(list(task.syntax_tree.get_switch_nodes_post_order())) == 1


def test_lower_bound_basic_switch(task):
    """Have 7 cases and a default, but the lower bound is 8."""
    task.options.set("pattern-independent-restructuring.min_switch_case_number", 8)
    switch_variable, vertices = _basic_switch_cfg(task)
    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task.syntax_tree.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(cond_node := seq_node.children[1], ConditionNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    current_condition_node: ConditionNode = cond_node
    for case_const in range(1, 8):
        assert isinstance(current_condition_node, ConditionNode)
        assert task.syntax_tree.condition_map[current_condition_node.condition] == Condition(
            OperationType.equal, [switch_variable, Constant(case_const, Integer(32, signed=True))]
        )
        assert (
            isinstance(tb := current_condition_node.true_branch_child, CodeNode)
            and tb.instructions == vertices[case_const + 2].instructions
        )
        current_condition_node = current_condition_node.false_branch_child
    assert isinstance(current_condition_node, CodeNode) and current_condition_node.instructions == vertices[2].instructions


def test_switch_empty_fallthrough(task):
    """Have 12 cases and a default, but the lower bound is 13, with empty fallthrough cases."""
    task.options.set("pattern-independent-restructuring.min_switch_case_number", 13)
    switch_variable, vertices = _switch_empty_fallthrough(task)
    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task.syntax_tree.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(cond_31_days := seq_node.children[1], ConditionNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    # 31 days
    assert cond_31_days.condition.is_disjunction
    assert {task.syntax_tree.condition_map[op] for op in cond_31_days.condition.operands} == {
        Condition(OperationType.equal, [switch_variable, Constant(c, Integer.int32_t())]) for c in [1, 3, 5, 7, 8, 10, 12]
    }
    assert isinstance(cond_31_days.true_branch_child, CodeNode) and cond_31_days.true_branch_child.instructions == vertices[3].instructions
    # 28 days:
    assert isinstance(cond_28_days := cond_31_days.false_branch_child, ConditionNode)
    assert task.syntax_tree.condition_map[cond_28_days.condition] == Condition(
        OperationType.equal, [switch_variable, Constant(2, Integer.int32_t())]
    )
    assert isinstance(cond_28_days.true_branch_child, CodeNode) and cond_28_days.true_branch_child.instructions == vertices[5].instructions
    # 30 days:
    assert isinstance(cond_30_days := cond_28_days.false_branch_child, ConditionNode) and cond_30_days.condition.is_disjunction
    assert {task.syntax_tree.condition_map[op] for op in cond_30_days.condition.operands} == {
        Condition(OperationType.equal, [switch_variable, Constant(c, Integer.int32_t())]) for c in [4, 6, 9, 11]
    }
    assert isinstance(cond_30_days.true_branch_child, CodeNode) and cond_30_days.true_branch_child.instructions == vertices[4].instructions
    # # default case:
    assert isinstance(else_case := cond_30_days.false_branch_child, CodeNode) and else_case.instructions == vertices[2].instructions


def test_switch_no_empty_fallthough(task):
    """Have 10 cases and a default, but the lower bound is 13, with non-empty fallthrough cases."""
    task.options.set("pattern-independent-restructuring.min_switch_case_number", 11)
    switch_variable, vertices = _switch_no_empty_fallthrough(task)
    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task.syntax_tree.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(current_cond := seq_node.children[1], ConditionNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[3].instructions

    # switch node:
    for constants in [[0, 1], [2, 3, 4], [5, 6, 7, 8, 9]]:
        assert isinstance(current_cond, ConditionNode) and current_cond.condition.is_disjunction
        assert {task.syntax_tree.condition_map[op] for op in current_cond.condition.operands} == {
            Condition(OperationType.equal, [switch_variable, Constant(c, Integer(32))]) for c in constants
        }
        assert isinstance(fallthrough := current_cond.true_branch_child, SeqNode) and len(fallthrough.children) == len(constants)
        or_cases = []
        for child, const in zip(fallthrough.children[:-1], constants):
            or_cases.append(const)
            assert isinstance(child, ConditionNode) and child.false_branch is None
            assert (len(or_cases) > 1 and child.condition.is_disjunction) or (len(or_cases) == 1 and child.condition.is_symbol)
            operands = child.condition.operands if len(or_cases) > 1 else [child.condition]
            assert {task.syntax_tree.condition_map[op] for op in operands} == {
                Condition(OperationType.equal, [switch_variable, Constant(c, Integer(32))]) for c in or_cases
            }
            assert (
                isinstance(child.true_branch_child, CodeNode) and child.true_branch_child.instructions == vertices[const + 4].instructions
            )
        assert (
            isinstance(fallthrough.children[-1], CodeNode)
            and fallthrough.children[-1].instructions == vertices[constants[-1] + 4].instructions
        )
        current_cond = current_cond.false_branch_child

    # default case:
    assert isinstance(current_cond, CodeNode) and current_cond.instructions == vertices[1].instructions


def test_switch_test_no_default(task):
    """Test with no default value."""
    var_1 = Variable(
        "var_1", Pointer(Integer(32, True), 32), None, False, Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    )
    switch_variable = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(
                        var_1, UnaryOperation(OperationType.address, [switch_variable], Pointer(Integer(32, True), 32), None, False)
                    ),
                    Assignment(ListOperation([]), scanf_call(var_1, 134524965, 2)),
                    Branch(Condition(OperationType.greater_us, [switch_variable, Constant(7, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [IndirectBranch(switch_variable)]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("Monday", 3))]),
            BasicBlock(5, [Assignment(ListOperation([]), print_call("Tuesday", 4))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Wednesday", 5))]),
            BasicBlock(11, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[5]),
            SwitchCase(vertices[1], vertices[5], [Constant(0, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[2], [Constant(1, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[3], [Constant(2, Integer(32, signed=True))]),
            SwitchCase(vertices[1], vertices[4], [Constant(3, Integer(32, signed=True))]),
            UnconditionalEdge(vertices[2], vertices[5]),
            UnconditionalEdge(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[5]),
        ]
    )
    task.options.set("pattern-independent-restructuring.min_switch_case_number", 4)
    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task.syntax_tree.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(cond_node := seq_node.children[1], ConditionNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[-1].instructions

    # switch node:
    current_condition_node: ConditionNode = cond_node
    for case_const in range(1, 4):
        assert isinstance(current_condition_node, ConditionNode)
        assert task.syntax_tree.condition_map[current_condition_node.condition] == Condition(
            OperationType.equal, [switch_variable, Constant(case_const, Integer(32, signed=True))]
        )
        assert (
            isinstance(tb := current_condition_node.true_branch_child, CodeNode)
            and tb.instructions == vertices[case_const + 1].instructions
        )
        current_condition_node = current_condition_node.false_branch_child
    assert current_condition_node is None


def test_default_disjunction_is_not_true(task):
    """test_condition 32/3 test6"""
    var_0_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_0_2 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 2, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    ),
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(
                        ListOperation([]),
                        scanf_call(
                            UnaryOperation(OperationType.address, [var_0_0], Pointer(Integer(32, True), 32), None, False), 134524965, 2
                        ),
                    ),
                    Branch(Condition(OperationType.equal, [var_0_2, Constant(1, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(
                1, [Assignment(ListOperation([]), print_call("Monday", 3)), Return(ListOperation([Constant(0, Integer(32, True))]))]
            ),
            BasicBlock(2, [Branch(Condition(OperationType.greater_us, [var_0_2, Constant(7, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(4, [IndirectBranch(var_0_2)]),
            BasicBlock(
                5,
                [
                    Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 14)),
                    Return(ListOperation([Constant(0, Integer(32, True))])),
                ],
            ),
            BasicBlock(
                6, [Assignment(ListOperation([]), print_call("Sunday", 13)), Return(ListOperation([Constant(0, Integer(32, True))]))]
            ),
            BasicBlock(
                7, [Assignment(ListOperation([]), print_call("Tuesday", 5)), Return(ListOperation([Constant(0, Integer(32, True))]))]
            ),
            BasicBlock(
                8, [Assignment(ListOperation([]), print_call("Wednesday", 6)), Return(ListOperation([Constant(0, Integer(32, True))]))]
            ),
            BasicBlock(
                9, [Assignment(ListOperation([]), print_call("Thursday", 8)), Return(ListOperation([Constant(0, Integer(32, True))]))]
            ),
            BasicBlock(
                10, [Assignment(ListOperation([]), print_call("Friday", 9)), Return(ListOperation([Constant(0, Integer(32, True))]))]
            ),
            BasicBlock(
                11, [Assignment(ListOperation([]), print_call("Saturday", 11)), Return(ListOperation([Constant(0, Integer(32, True))]))]
            ),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[2], vertices[4]),
            FalseCase(vertices[2], vertices[3]),
            SwitchCase(vertices[3], vertices[5], [Constant(7)]),
            SwitchCase(vertices[3], vertices[6], [Constant(2)]),
            SwitchCase(vertices[3], vertices[7], [Constant(3)]),
            SwitchCase(vertices[3], vertices[8], [Constant(4)]),
            SwitchCase(vertices[3], vertices[9], [Constant(5)]),
            SwitchCase(vertices[3], vertices[10], [Constant(6)]),
            SwitchCase(vertices[3], vertices[4], [Constant(0)]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 2
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)

    # switch node:
    assert switch.expression == var_0_2 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer.int32_t()) and case1.break_case is False
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(3) and case3.break_case is False
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(4) and case4.break_case is False
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(5) and case5.break_case is False
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(6) and case6.break_case is False
    assert isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(7) and case7.break_case is False
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[1].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[6].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[7].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[8].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[9].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[10].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[5].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[4].instructions


def test_break_contained_in_switch_initial(task):
    """
      Check that we check for breaks when constructing the initial switch node:
                                                                                 +----------------------------------------+
                                                                                 |                   0.                   |
                                                                                 |              var_0 = arg2              |
                                                                                 |               arg2 = 0x0               |
                                                                                 +----------------------------------------+
                                                                                   |
                                                                                   |
                                                                                   v
                                            +------------------------------+     +----------------------------------------+
                                            |              4.              |     |                   1.                   |
                                            | printf("return final value") |     |            if(arg2 <= 0x9)             |
    +-------------------------------------> |         return var_0         | <-- |                                        | <----------+
    |                                       +------------------------------+     +----------------------------------------+            |
    |                                                                              |                                                   |
    |                                                                              |                                                   |
    |                                                                              v                                                   |
    |                                                                            +----------------------------------------+            |
    |                                                                            |                   2.                   |            |
    |         +-------------------------------+                               +- |            if(arg1 u> 0x5)             |  +---------+--------------------------------------+
    |         |                               |                               |  +----------------------------------------+  |         |                                      |
    |         |                               |                               |    |                                         |         |                                      |
    |    +----+--------------------------+    |                               |    |                                         |    +----+---------+                            |
    |    |    v                          |    |                               |    v                                         |    |    |         v                            |
    |    |  +-------------------------+  |    |                               |  +--------------------------------------------------+  |       +---------------------------+  |
    |    |  |           9.            |  |    |                               |  |                                                  |  |       |            6.             |  |
    +----+- |    if(var_0 == 0x5)     |  +----+-------------------------------+- |                                                  |  |       | printf("You chose the 1") |  |
         |  +-------------------------+       |                               |  |                                                  |  |       +---------------------------+  |
         |    |                               |                               |  |                        3.                        |  |         |                            |
         |    |                               +-------------------------------+- |                     jmp arg1                     |  |         |                            |
         |    v                                                               |  |                                                  |  |         |                            |
         |  +-------------------------+                                       |  |                                                  |  |         |                            |
         |  |           10.           |                                       |  |                                                  |  |         |                            |
         |  | printf("Another prime") | <-------------------------------------+- |                                                  |  |         |                            |
         |  +-------------------------+                                       |  +--------------------------------------------------+  |         |                            |
         |    |                                                               |    |                                                   |         |                            |
         |    |                                                               |    |                                         +---------+         |                            |
         |    |                                                               |    v                                         |                   |                            |
         |    |                                                               |  +----------------------------------------+  |                   |                            |
         |    |                                                               |  |                   5.                   |  |                   |                            |
         |    |                                                               |  |  printf("Number not between 1 and 5")  |  |                   |                            |
         |    |                                                               +> |            if(arg1 <= 0x5)             | -+--------------+    |                            |
         |    |                                                                  +----------------------------------------+  |              |    |                            |
         |    |                                                                    |                                         |              |    |                            |
         |    |                                                                    |                                         |              |    |                            |
         |    |                                                                    v                                         |              |    |                            |
         |    |                                                                  +----------------------------------------+  |              |    |                            |
         |    |                                                                  |                  11.                   |  |              |    |                            |
         |    |                                                                  |           arg1 = arg1 + 0x5            |  |              |    |                            |
         |    |                                                                  +----------------------------------------+  |              |    |                            |
         |    |                                                                    |                                         |              |    |                            |
         |    |                                                                    |                                         |              |    |                            |
         |    |                                                                    v                                         |              |    |                            |
         |    |                                                                  +--------------------------------------------------+       |    |                            |
         |    |                                                                  |                       13.                        |       |    |                            |
         |    |                                                                  |               var_0 = var_0 + arg2               |       |    |                            |
         |    +----------------------------------------------------------------> |                arg2 = arg2 + 0x0                 | <-----+----+                            |
         |                                                                       +--------------------------------------------------+       |                                 |
         |                                                                         ^                                         ^              |                                 |
         |                                    +------------------------------------+                                         |              |                                 |
         |                                    |                                                                              |              |                                 |
         |                                    |                                  +----------------------------------------+  |              |                                 |
         |                                    |                                  |                   7.                   |  |              |                                 |
         |                                    |                                  | printf("You chose the prime number 2") | <+--------------+---------------------------------+
         |                                    |                                  +----------------------------------------+  |              |
         |                                    |                                    |                                         |              |
         |                                    |                                    |                                         |              |
         |                                    |                                    v                                         |              |
         |                                    |                                  +----------------------------------------+  |              |
         |                                    |                                  |                   8.                   |  |              |
         +------------------------------------+--------------------------------> |   printf("You chose an even number")   | -+              |
                                              |                                  +----------------------------------------+                 |
                                              |                                  +----------------------------------------+                 |
                                              |                                  |                  12.                   |                 |
                                              +--------------------------------- |           arg1 = arg1 - 0x5            | <---------------+
                                                                                 +----------------------------------------+
    """
    arg1_1 = Variable("arg1", Integer(32, True), None, False, Variable("arg1", Integer(32, True), 1, False, None))
    arg1_2 = Variable("arg1", Integer(32, True), None, False, Variable("arg1", Integer(32, True), 2, False, None))
    arg1_3 = Variable("arg1", Integer(32, True), None, False, Variable("arg1", Integer(32, True), 2, False, None))
    arg2 = Variable("arg2", Integer(32, True), None, False, Variable("arg2", Integer(32, True), 0, False, None))
    arg2_2 = Variable("arg2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 2, False, None))
    arg2_3 = Variable("arg2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 3, False, None))
    var_0_1 = Variable("var_0", Integer(32, True), None, True, Variable("arg2", Integer(32, True), 1, True, None))
    var_0_2 = Variable("var_0", Integer(32, True), None, True, Variable("arg2", Integer(32, True), 2, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, [Assignment(var_0_1, arg2), Assignment(arg2_2, Constant(0, Integer.int32_t()))]),
            BasicBlock(
                1, [Branch(Condition(OperationType.less_or_equal, [arg2_2, Constant(9, Integer.int32_t())], CustomType("bool", 1)))]
            ),
            BasicBlock(2, [Branch(Condition(OperationType.greater_us, [arg1_1, Constant(5, Integer.int32_t())], CustomType("bool", 1)))]),
            BasicBlock(3, [IndirectBranch(arg1_1)]),  # 5
            BasicBlock(4, [Assignment(ListOperation([]), print_call("return final value", 3)), Return(ListOperation([var_0_1]))]),
            BasicBlock(
                5,
                [
                    Assignment(ListOperation([]), print_call("Number not between 1 and 5", 10)),
                    Branch(Condition(OperationType.less_or_equal, [arg1_1, Constant(5, Integer.int32_t())], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("You chose the 1", 3))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("You chose the prime number 2", 4))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("You chose an even number", 5))]),
            BasicBlock(9, [Branch(Condition(OperationType.equal, [var_0_1, Constant(5, Integer.int32_t())], CustomType("bool", 1)))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Another prime", 7))]),
            BasicBlock(11, [Assignment(arg1_2, BinaryOperation(OperationType.plus, [arg1_1, Constant(5, Integer.int32_t())]))]),
            BasicBlock(12, [Assignment(arg1_3, BinaryOperation(OperationType.minus, [arg1_1, Constant(5, Integer.int32_t())]))]),
            BasicBlock(
                13,
                [
                    Assignment(var_0_2, BinaryOperation(OperationType.plus, [var_0_1, arg2_2])),
                    Assignment(arg2_3, BinaryOperation(OperationType.plus, [arg2_2, Constant(0, Integer.int32_t())])),
                ],
            ),
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[4]),
            FalseCase(vertices[2], vertices[3]),
            TrueCase(vertices[2], vertices[5]),
            SwitchCase(vertices[3], vertices[5], [Constant(0, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[6], [Constant(1, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[7], [Constant(2, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[8], [Constant(4, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[9], [Constant(5, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[10], [Constant(3, Integer(32, signed=True))]),
            TrueCase(vertices[5], vertices[11]),
            FalseCase(vertices[5], vertices[12]),
            UnconditionalEdge(vertices[6], vertices[13]),
            UnconditionalEdge(vertices[7], vertices[8]),
            UnconditionalEdge(vertices[8], vertices[13]),
            TrueCase(vertices[9], vertices[4]),
            FalseCase(vertices[9], vertices[10]),
            UnconditionalEdge(vertices[10], vertices[13]),
            UnconditionalEdge(vertices[11], vertices[13]),
            UnconditionalEdge(vertices[12], vertices[13]),
            UnconditionalEdge(vertices[13], vertices[1]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task.syntax_tree.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions
    assert isinstance(loop_node := seq_node.children[1], WhileLoopNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[4].instructions

    # Loop:
    assert isinstance(body := loop_node.body, SeqNode) and len(body.children) == 2
    assert loop_node.condition.is_conjunction and len(operands := loop_node.condition.operands) == 2
    for op in operands:
        if op.is_symbol:
            assert task.syntax_tree.condition_map[op] == vertices[1].instructions[0].condition
        else:
            assert op.is_disjunction and len(op.operands) == 2
            assert all(literal.is_negation and literal.operands[0].is_symbol for literal in op.operands)
            assert {task.syntax_tree.condition_map[symbol] for symbol in op.get_symbols()} == {
                vertices[9].instructions[0].condition,
                Condition(OperationType.equal, [arg1_1, Constant(5, arg1_1.type)]),
            }
    assert isinstance(switch := body.children[0], SwitchNode)
    assert isinstance(body.children[1], CodeNode) and body.children[1].instructions == vertices[13].instructions

    # switch:
    assert switch.expression == arg1_1 and len(switch.children) == 6
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer.int32_t()) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer.int32_t()) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(4, Integer.int32_t()) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(3, Integer.int32_t()) and case4.break_case is False
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(5, Integer.int32_t()) and case5.break_case is True
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[6].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[7].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[8].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == []
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[10].instructions
    assert isinstance(default_case := default.child, SeqNode) and len(default_case.children) == 2

    assert isinstance(df_code := default_case.children[0], CodeNode) and df_code.instructions == vertices[5].instructions[:-1]
    assert (
        isinstance(df_cond := default_case.children[1], ConditionNode)
        and isinstance(df_cond.true_branch_child, CodeNode)
        and isinstance(df_cond.false_branch_child, CodeNode)
    )
    if df_cond.true_branch_child.instructions != vertices[11].instructions:
        df_cond.switch_branches()
    if df_cond.condition.is_symbol:
        assert task.syntax_tree.condition_map[df_cond.condition] == vertices[5].instructions[-1].condition
    else:
        assert task.syntax_tree.condition_map[~df_cond.condition] == vertices[5].instructions[-1].condition.negate()
    assert (
        df_cond.true_branch_child.instructions == vertices[11].instructions
        and df_cond.false_branch_child.instructions == vertices[12].instructions
    )


def __graph_loop_break_in_switch(task):
    """
    test_switch test_0
    Check that we check for breaks when adding case nodes to the switch node:
     +-------------------------------------------------------------------------------------------------------------------+
      |                                                                                                                   |
      |                                  +----------------------------------------+                                       |
      |                                  |                   0.                   |                                       |
      |                                  |              var_0 = arg2              |                                       |
      |                                  |               arg2 = 0x0               |                                       |
      |                                  +----------------------------------------+                                       |
      |                                    |                                                                              |
      |                                    |                                                                              |
      |                                    v                                                                              |
      |                                  +----------------------------------------+     +------------------------------+  |
      |                                  |                   1.                   |     |              4.              |  |
      |                                  |            if(arg2 <= 0x9)             |     | printf("return final value") |  |
      |                          +-----> |                                        | --> |         return var_0         |  |
      |                          |       +----------------------------------------+     +------------------------------+  |
      |                          |         |                                              ^                               |
      |                          |         |                                         +----+-------------------------------+
      |                          |         v                                         |    |
      |                          |       +----------------------------------------+  |  +------------------------------+     +------------------------------+
      |                          |       |                   2.                   |  |  |              8.              |     |             11.              |
      |                          |    +- |            if(arg1 u> 0x5)             |  |  |       if(var_0 == 0x5)       | --> | printf("both numbers are 5") |
      |                          |    |  +----------------------------------------+  |  +------------------------------+     +------------------------------+
      |                          |    |    |                                         |    ^                                    |
      |                          |    |    |                                         |    |                                    +-------------------------------+
      v                          |    |    v                                         |    |                                                                    |
    +-------------------------+  |    |  +-----------------------------------------------------------------------------+     +------------------------------+  |
    |           9.            |  |    |  |                                                                             |     |              5.              |  |
    | printf("Another prime") |  |    |  |                                     3.                                      | --> |  printf("You chose the 1")   |  |
    +-------------------------+  |    |  |                                  jmp arg1                                   |     +------------------------------+  |
      |                          |    |  |                                                                             |       |                               |
      |                          |    |  |                                                                             |       |                               |
      |                          |    |  +-----------------------------------------------------------------------------+       |                               |
      |                          |    |    |                                         |    |                                    |                               |
      |                          |    |    |                                         |    |                                    |                               |
      |                          |    |    v                                         |    |                                    |                               |
      |                          |    |  +----------------------------------------+  |    |                                    |                               |
      |                          |    |  |                   6.                   |  |    |                                    |                               |
      |                          |    |  | printf("You chose the prime number 2") |  |    |                                    |                               |
      |                          |    |  +----------------------------------------+  |    |                                    |                               |
      |                          |    |    |                                         |    |                                    |                               |
      |                          |    |    |                                         |    |                                    |                               |
      |                          |    |    v                                         |    |                                    |                               |
      |                          |    |  +----------------------------------------+  |    |                                    |                               |
      |                          |    |  |                   7.                   |  |    |                                    |                               |
      |                          |    |  |   printf("You chose an even number")   | <+    |                                    |                               |
      |                          |    |  +----------------------------------------+       |                                    |                               |
      |                          |    |    |                                              |                                    |                               |
      |                          |    |    |                                              |                                    |                               |
      |                          |    |    v                                              v                                    |                               |
      |                          |    |  +-----------------------------------------------------------------------------+       |                               |
      |                          |    +> |                                                                             | <-----+                               |
      |                          |       |                                                                             |                                       |
      |                          |       |                                     10.                                     |                                       |
      |                          +------ |                            var_0 = var_0 + arg2                             | <-------------------------------------+
      |                                  |                              arg2 = arg2 + 0x0                              |
      |                                  |                                                                             |
      +--------------------------------> |                                                                             |
                                         +-----------------------------------------------------------------------------+
    """
    arg1_1 = Variable("arg1", Integer(32, True), None, False, Variable("arg1", Integer(32, True), 1, False, None))
    arg2 = Variable("arg2", Integer(32, True), None, False, Variable("arg2", Integer(32, True), 0, False, None))
    arg2_2 = Variable("arg2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 2, False, None))
    arg2_3 = Variable("arg2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 3, False, None))
    var_0_1 = Variable("var_0", Integer(32, True), None, True, Variable("arg2", Integer(32, True), 1, True, None))
    var_0_2 = Variable("var_0", Integer(32, True), None, True, Variable("arg2", Integer(32, True), 2, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, [Assignment(var_0_1, arg2), Assignment(arg2_2, Constant(0, Integer.int32_t()))]),
            BasicBlock(
                1, [Branch(Condition(OperationType.less_or_equal, [arg2_2, Constant(9, Integer.int32_t())], CustomType("bool", 1)))]
            ),
            BasicBlock(2, [Branch(Condition(OperationType.greater_us, [arg1_1, Constant(5, Integer.int32_t())], CustomType("bool", 1)))]),
            BasicBlock(3, [IndirectBranch(arg1_1)]),  # 5
            BasicBlock(4, [Assignment(ListOperation([]), print_call("return final value", 3)), Return(ListOperation([var_0_1]))]),  # 6
            BasicBlock(5, [Assignment(ListOperation([]), print_call("You chose the 1", 3))]),  # 8
            BasicBlock(6, [Assignment(ListOperation([]), print_call("You chose the prime number 2", 4))]),  # 9
            BasicBlock(7, [Assignment(ListOperation([]), print_call("You chose an even number", 5))]),  # 10
            BasicBlock(8, [Branch(Condition(OperationType.equal, [var_0_1, Constant(5, Integer.int32_t())], CustomType("bool", 1)))]),  # 11
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Another prime", 7))]),  # 12
            BasicBlock(
                10,
                [
                    Assignment(var_0_2, BinaryOperation(OperationType.plus, [var_0_1, arg2_2])),
                    Assignment(arg2_3, BinaryOperation(OperationType.plus, [arg2_2, Constant(0, Integer.int32_t())])),
                ],
            ),  # 15
            BasicBlock(11, [Assignment(ListOperation([]), print_call("both numbers are 5", 9))]),  # 17
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[4]),
            FalseCase(vertices[2], vertices[3]),
            TrueCase(vertices[2], vertices[10]),
            SwitchCase(vertices[3], vertices[10], [Constant(0, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[5], [Constant(1, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[6], [Constant(2, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[7], [Constant(4, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[8], [Constant(5, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[9], [Constant(3, Integer(32, signed=True))]),
            UnconditionalEdge(vertices[5], vertices[10]),
            UnconditionalEdge(vertices[6], vertices[7]),
            UnconditionalEdge(vertices[7], vertices[10]),
            TrueCase(vertices[8], vertices[4]),
            FalseCase(vertices[8], vertices[11]),
            UnconditionalEdge(vertices[9], vertices[10]),
            UnconditionalEdge(vertices[10], vertices[1]),
            UnconditionalEdge(vertices[11], vertices[10]),
        ]
    )
    return arg1_1, vertices


def test_break_contained_in_switch_add_case_default(task):
    """Test with not adding the case"""
    arg1_1, vertices = __graph_loop_break_in_switch(task)
    task.options = Options()
    task.options.update({"pattern-independent-restructuring.loop_break_switch": "None"})
    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task.syntax_tree.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions
    assert isinstance(loop_node := seq_node.children[1], WhileLoopNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[4].instructions

    # Loop:
    assert isinstance(body := loop_node.body, SeqNode) and len(body.children) == 3
    assert loop_node.condition.is_literal
    if loop_node.condition.is_symbol:
        assert task.syntax_tree.condition_map[loop_node.condition] == vertices[1].instructions[0].condition
    else:
        assert task.syntax_tree.condition_map[~loop_node.condition] == vertices[1].instructions[0].condition.negate()

    assert isinstance(case_5 := body.children[0], ConditionNode) and case_5.false_branch is None and case_5.condition.is_literal
    assert isinstance(switch := body.children[1], SwitchNode)
    assert isinstance(body.children[2], CodeNode) and body.children[2].instructions == vertices[10].instructions

    # second break
    if case_5.condition.is_symbol:
        assert task.syntax_tree.condition_map[case_5.condition] == Condition(OperationType.equal, [arg1_1, Constant(5, arg1_1.type)])
    else:
        assert task.syntax_tree.condition_map[~case_5.condition] == Condition(OperationType.not_equal, [arg1_1, Constant(5, arg1_1.type)])

    assert isinstance(case_seq := case_5.true_branch_child, SeqNode) and len(case_seq.children) == 2
    assert isinstance(break_cond := case_seq.children[0], ConditionNode) and break_cond.false_branch is None
    assert isinstance(cn_5 := case_seq.children[1], CodeNode) and cn_5.instructions == vertices[11].instructions

    assert task.syntax_tree.condition_map[break_cond.condition] == vertices[8].instructions[0].condition
    assert isinstance(break_node := break_cond.true_branch_child, CodeNode) and break_node.instructions == [Break()]

    # switch:
    assert switch.expression == arg1_1 and len(switch.children) == 4
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer.int32_t()) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer.int32_t()) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(4, Integer.int32_t()) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(3, Integer.int32_t()) and case4.break_case is True

    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[5].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[6].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[7].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[9].instructions


def test_break_contained_in_switch_add_case_structural_variable(task):
    """Test with adding the case and using a structural variable."""
    arg1_1, vertices = __graph_loop_break_in_switch(task)
    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task.syntax_tree.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions
    assert isinstance(loop_node := seq_node.children[1], WhileLoopNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[4].instructions

    # Loop:
    assert isinstance(body := loop_node.body, SeqNode) and len(body.children) == 4
    assert loop_node.condition.is_literal
    if loop_node.condition.is_symbol:
        assert task.syntax_tree.condition_map[loop_node.condition] == vertices[1].instructions[0].condition
    else:
        assert task.syntax_tree.condition_map[~loop_node.condition] == vertices[1].instructions[0].condition.negate()

    break_variable = Variable("loop_break", Integer.int32_t())
    assert isinstance(loop_break_init := body.children[0], CodeNode) and loop_break_init.instructions == [
        Assignment(break_variable, Constant(0, Integer.int32_t()))
    ]
    assert isinstance(switch := body.children[1], SwitchNode)
    assert isinstance(loop_break_cond := body.children[2], ConditionNode) and loop_break_cond.false_branch is None
    assert isinstance(body.children[3], CodeNode) and body.children[3].instructions == vertices[10].instructions

    # switch:
    assert switch.expression == arg1_1 and len(switch.children) == 5
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer.int32_t()) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer.int32_t()) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(4, Integer.int32_t()) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(3, Integer.int32_t()) and case4.break_case is True
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(5, Integer.int32_t()) and case5.break_case is True

    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[5].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[6].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[7].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[9].instructions
    assert isinstance(case_seq := case5.child, SeqNode) and len(case_seq.children) == 2

    # case 5
    assert isinstance(break_cond := case_seq.children[0], ConditionNode) and break_cond.false_branch is None
    assert isinstance(cn_5 := case_seq.children[1], CodeNode) and cn_5.instructions == vertices[11].instructions
    assert task.syntax_tree.condition_map[break_cond.condition] == vertices[8].instructions[0].condition
    assert isinstance(break_node := break_cond.true_branch_child, CodeNode) and break_node.instructions == [
        Assignment(break_variable, Constant(1, Integer.int32_t())),
        Break(),
    ]

    # break-condition:
    assert task.syntax_tree.condition_map[loop_break_cond.condition] == Condition(
        OperationType.equal, [break_variable, Constant(1, Integer.int32_t())]
    )
    assert isinstance(break_node := loop_break_cond.true_branch_child, CodeNode) and break_node.instructions == [Break()]


def test_break_contained_in_switch_structural_variable(task):
    """
    test_switch test0_b
    """
    arg1_1 = Variable("arg1", Integer(32, True), None, False, Variable("arg1", Integer(32, True), 1, False, None))
    arg2 = Variable("arg2", Integer(32, True), None, False, Variable("arg2", Integer(32, True), 0, False, None))
    arg2_2 = Variable("arg2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 2, False, None))
    arg2_3 = Variable("arg2", Integer(32, True), None, False, Variable("var_10", Integer(32, True), 3, False, None))
    var_0_1 = Variable("var_0", Integer(32, True), None, True, Variable("arg2", Integer(32, True), 1, True, None))
    var_0_2 = Variable("var_0", Integer(32, True), None, True, Variable("arg2", Integer(32, True), 2, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(0, [Assignment(var_0_1, arg2), Assignment(arg2_2, Constant(0, Integer.int32_t()))]),
            BasicBlock(
                1, [Branch(Condition(OperationType.less_or_equal, [arg2_2, Constant(9, Integer.int32_t())], CustomType("bool", 1)))]
            ),
            BasicBlock(2, [Branch(Condition(OperationType.greater_us, [arg1_1, Constant(7, Integer.int32_t())], CustomType("bool", 1)))]),
            BasicBlock(3, [IndirectBranch(arg1_1)]),  # 5
            BasicBlock(4, [Assignment(ListOperation([]), print_call("return final value", 3)), Return(ListOperation([var_0_1]))]),  # 6
            BasicBlock(
                5,
                [
                    Assignment(ListOperation([]), print_call("Number not between 1 and 5", 5)),
                    Branch(Condition(OperationType.less_or_equal, [arg1_1, Constant(5, Integer.int32_t())], CustomType("bool", 1))),
                ],
            ),  # 7
            BasicBlock(6, [Assignment(ListOperation([]), print_call("You chose the 1", 3))]),  # 8
            BasicBlock(7, [Assignment(ListOperation([]), print_call("You chose the prime number 2", 4))]),  # 9
            BasicBlock(8, [Assignment(ListOperation([]), print_call("You chose an even number", 5))]),  # 10
            BasicBlock(9, [Assignment(ListOperation([]), print_call("both numbers are 5", 9))]),  # 11
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Another prime", 7))]),  # 12
            BasicBlock(11, [Assignment(ListOperation([]), print_call("The 7 is a prime", 7))]),  # 13
            BasicBlock(12, [Assignment(arg1_1, BinaryOperation(OperationType.plus, [arg1_1, Constant(0, Integer.int32_t())]))]),  # 14
            BasicBlock(13, [Assignment(arg1_1, BinaryOperation(OperationType.minus, [arg1_1, Constant(0, Integer.int32_t())]))]),  # 15
            BasicBlock(
                14,
                [
                    Assignment(var_0_2, BinaryOperation(OperationType.plus, [var_0_1, arg2_2])),
                    Assignment(arg2_3, BinaryOperation(OperationType.plus, [arg2_2, Constant(0, Integer.int32_t())])),
                ],
            ),  # 16
        ]
    )
    task.graph.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[4]),
            FalseCase(vertices[2], vertices[3]),
            TrueCase(vertices[2], vertices[5]),
            SwitchCase(vertices[3], vertices[5], [Constant(0, Integer(32, signed=True)), Constant(6, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[6], [Constant(1, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[7], [Constant(2, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[8], [Constant(4, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[9], [Constant(5, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[10], [Constant(3, Integer(32, signed=True))]),
            SwitchCase(vertices[3], vertices[11], [Constant(7, Integer(32, signed=True))]),
            TrueCase(vertices[5], vertices[12]),
            FalseCase(vertices[5], vertices[13]),
            UnconditionalEdge(vertices[6], vertices[14]),
            UnconditionalEdge(vertices[7], vertices[8]),
            UnconditionalEdge(vertices[8], vertices[14]),
            UnconditionalEdge(vertices[9], vertices[4]),
            UnconditionalEdge(vertices[10], vertices[14]),
            UnconditionalEdge(vertices[11], vertices[4]),
            UnconditionalEdge(vertices[12], vertices[14]),
            UnconditionalEdge(vertices[13], vertices[14]),
            UnconditionalEdge(vertices[14], vertices[1]),
        ]
    )
    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task.syntax_tree.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions
    assert isinstance(loop_node := seq_node.children[1], WhileLoopNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[4].instructions

    # Loop:
    assert isinstance(body := loop_node.body, SeqNode) and len(body.children) == 4
    assert loop_node.condition.is_literal
    if loop_node.condition.is_symbol:
        assert task.syntax_tree.condition_map[loop_node.condition] == vertices[1].instructions[0].condition
    else:
        assert task.syntax_tree.condition_map[~loop_node.condition] == vertices[1].instructions[0].condition.negate()

    break_variable = Variable("loop_break", Integer.int32_t())
    assert isinstance(loop_break_init := body.children[0], CodeNode) and loop_break_init.instructions == [
        Assignment(break_variable, Constant(0, Integer.int32_t()))
    ]
    assert isinstance(switch := body.children[1], SwitchNode)
    assert isinstance(loop_break_cond := body.children[2], ConditionNode) and loop_break_cond.false_branch is None
    assert isinstance(continue_cond := body.children[3], ConditionNode) and continue_cond.false_branch is None
    assert isinstance(code_14 := continue_cond.true_branch_child, CodeNode) and code_14.instructions == vertices[14].instructions + [
        Continue()
    ]

    # switch:
    assert switch.expression == arg1_1 and len(switch.children) == 7
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer.int32_t()) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(2, Integer.int32_t()) and case2.break_case is False
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(4, Integer.int32_t()) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(3, Integer.int32_t()) and case4.break_case is True
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(5, Integer.int32_t()) and case5.break_case is True
    assert isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(7, Integer.int32_t()) and case5.break_case is True
    assert isinstance(default := switch.default, CaseNode) and isinstance(default.child, SeqNode)

    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[6].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[7].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[8].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[10].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[9].instructions + [
        Assignment(break_variable, Constant(1, Integer.int32_t()))
    ]
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[11].instructions + [
        Assignment(break_variable, Constant(1, Integer.int32_t()))
    ]

    # break-condition:
    assert task.syntax_tree.condition_map[loop_break_cond.condition] == Condition(
        OperationType.equal, [break_variable, Constant(1, Integer.int32_t())]
    )
    assert isinstance(break_node := loop_break_cond.true_branch_child, CodeNode) and break_node.instructions == [Break()]


def test_insert_before_existing_case(task):
    """
      Test 7_b
                                       +------------------------------------+
                                       |                 0.                 |
                                       | printf("Enter week number(1-7): ") |
                                       |   __isoc99_scanf("%d", &(var_0))   |
                                    +- |         if(var_0 == 0x1f4)         |
                                    |  +------------------------------------+
                                    |    |
                                    |    |
                                    |    v
                                    |  +------------------------------------+
                                    |  |                 2.                 |
                                    |  |         if(var_0 > 0x1f4)          | -------------------------------------------------------------------+
                                    |  +------------------------------------+                                                                    |
                                    |    |                                                                                                       |
                                    |    |                                                                                                       |
                                    |    v                                                                                                       |
            +--------------------+  |  +------------------------------------+                                                                    |
            |         8.         |  |  |                 5.                 |                                                                    |
         +- | if(var_0 == 0x190) | <+- |          if(var_0 > 0x22)          |                                                                    |
         |  +--------------------+  |  +------------------------------------+                                                                    |
         |    |                     |    |                                                                                                       |
         |    |                     |    |                                                                                                       |
         |    v                     |    v                                                                                                       |
         |  +--------------------+  |  +------------------------------------+      +--------------------+                                        |
         |  |        10.         |  |  |                 9.                 |      |        20.         |                                        |
         |  | printf("Thursday") |  |  |          if(var_0 < 0x0)           |  +-> |  printf("Sunday")  | ----------------------------------+    |
         |  +--------------------+  |  +------------------------------------+  |   +--------------------+                                   |    |
         |    |                     |    |                                     |                                                            |    |
         |    |                     |    |                                     |                                                            |    |
         |    v                     |    v                                     |                                                            |    |
         |  +--------------------+  |  +------------------------------------+  |   +--------------------+                                   |    |
         |  |         3.         |  |  |                13.                 |  |   |        19.         |                                   |    |
         |  |  printf("Friday")  | <+  |         if(var_0 u> 0x22)          |  |   | printf("Saturday") | -----------------------------+    |    |
         |  +--------------------+     +------------------------------------+  |   +--------------------+                              |    |    |
         |    |                          |                                     |     ^                                                 |    |    |
         |    |                          |                                     |     |                                                 |    |    |
         |    |                          v                                     |     |                                                 |    |    |
         |    |                        +----------------------------------------------------------------+     +---------------------+  |    |    |
         |    |                        |                                                                |     |         18.         |  |    |    |
         |    |                        |                                                                | --> | printf("Wednesday") |  |    |    |
         |    |                        |                                                                |     +---------------------+  |    |    |
         |    |                        |                              15.                               |       |                      |    |    |
         |    |                        |                           jmp var_0                            |       |                      |    |    |
         |    |                        |                                                                |       |                      |    |    |
         |    |                        |                                                                |       |                      |    |    |
         |    |                     +- |                                                                |       |                      |    |    |
         |    |                     |  +----------------------------------------------------------------+       |                      |    |    |
         |    |                     |    |                                           |                          |                      |    |    |
         |    |                     |    |                                           |                          |                      |    |    |
         |    |                     |    v                                           v                          |                      |    |    |
         |    |                     |  +------------------------------------+      +--------------------+       |                      |    |    |
         |    |                     |  |                16.                 |      |        17.         |       |                      |    |    |
         |    |                     |  |          printf("Monday")          |      | printf("Tuesday")  |       |                      |    |    |
         |    |                     |  +------------------------------------+      +--------------------+       |                      |    |    |
         |    |                     |    |                                           |                          |                      |    |    |
    +----+----+---------------------+    |                                           |                          |                      |    |    |
    |    |    |                          v                                           v                          v                      |    |    |
    |    |    |                        +--------------------------------------------------------------------------------------------+  |    |    |
    |    |    +----------------------> |                                                                                            | <+    |    |
    |    |                             |                                             6.                                             |       |    |
    |    |                             |                                         return 0x0                                         |       |    |
    |    |                             |                                                                                            | <-----+    |
    |    |                             +--------------------------------------------------------------------------------------------+            |
    |    |                               ^                                                                                                       |
    |    |                               |                                                                                                       |
    |    |                               |                                                                                                       |
    |    |                             +----------------------------------------------------------------+                                        |
    |    |                             |                               7.                               |                                        |
    |    +---------------------------> | printf("Invalid input! Please enter week number between 1-7.") | <--------------------------------------+
    |                                  +----------------------------------------------------------------+
    |                                    ^
    +------------------------------------+
    """
    var_0_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_0_2 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 2, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(
                        ListOperation([]),
                        scanf_call(
                            UnaryOperation(OperationType.address, [var_0_0], Pointer(Integer(32, True), 32), None, False), 134524965, 2
                        ),
                    ),
                    Branch(Condition(OperationType.equal, [var_0_2, Constant(500, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, [Branch(Condition(OperationType.greater, [var_0_2, Constant(500, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Friday", 3))]),
            BasicBlock(5, [Branch(Condition(OperationType.greater, [var_0_2, Constant(34, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(6, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(7, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 11))]),
            BasicBlock(8, [Branch(Condition(OperationType.equal, [var_0_2, Constant(400, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(9, [Branch(Condition(OperationType.less, [var_0_2, Constant(0, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Thursday", 7))]),
            BasicBlock(
                13, [Branch(Condition(OperationType.greater_us, [var_0_2, Constant(34, Integer(32, True))], CustomType("bool", 1)))]
            ),
            BasicBlock(15, [IndirectBranch(var_0_2)]),
            BasicBlock(16, [Assignment(ListOperation([]), print_call("Monday", 4))]),
            BasicBlock(17, [Assignment(ListOperation([]), print_call("Tuesday", 5))]),
            BasicBlock(18, [Assignment(ListOperation([]), print_call("Wednesday", 6))]),
            BasicBlock(19, [Assignment(ListOperation([]), print_call("Saturday", 8))]),
            BasicBlock(20, [Assignment(ListOperation([]), print_call("Sunday", 9))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[2]),
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[5]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[4]),
            TrueCase(vertices[3], vertices[6]),
            FalseCase(vertices[3], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[4]),
            TrueCase(vertices[6], vertices[8]),
            FalseCase(vertices[6], vertices[5]),
            TrueCase(vertices[7], vertices[5]),
            FalseCase(vertices[7], vertices[9]),
            UnconditionalEdge(vertices[8], vertices[2]),
            TrueCase(vertices[9], vertices[5]),
            FalseCase(vertices[9], vertices[10]),
            SwitchCase(vertices[10], vertices[5], [Constant(i) for i in range(1, 34) if i not in {6, 9, 12}]),
            SwitchCase(vertices[10], vertices[11], [Constant(0, Integer(32, True))]),
            SwitchCase(vertices[10], vertices[12], [Constant(12, Integer(32, True))]),
            SwitchCase(vertices[10], vertices[13], [Constant(34, Integer(32, True))]),
            SwitchCase(vertices[10], vertices[14], [Constant(6, Integer(32, True))]),
            SwitchCase(vertices[10], vertices[15], [Constant(9, Integer(32, True))]),
            UnconditionalEdge(vertices[11], vertices[4]),
            UnconditionalEdge(vertices[12], vertices[4]),
            UnconditionalEdge(vertices[13], vertices[4]),
            UnconditionalEdge(vertices[14], vertices[4]),
            UnconditionalEdge(vertices[15], vertices[4]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[4].instructions

    # switch node:
    assert switch.expression == var_0_2 and len(switch.children) == 8
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(0, Integer(32, True)) and case1.break_case is True
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(6, Integer(32, True)) and case2.break_case is True
    assert isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(9, Integer(32, True)) and case3.break_case is True
    assert isinstance(case4 := switch.cases[3], CaseNode) and case4.constant == Constant(12, Integer(32, True)) and case4.break_case is True
    assert isinstance(case5 := switch.cases[4], CaseNode) and case5.constant == Constant(34, Integer(32, True)) and case5.break_case is True
    assert (
        isinstance(case6 := switch.cases[5], CaseNode) and case6.constant == Constant(400, Integer(32, True)) and case6.break_case is False
    )
    assert (
        isinstance(case7 := switch.cases[6], CaseNode) and case7.constant == Constant(500, Integer(32, True)) and case7.break_case is True
    )
    assert isinstance(default := switch.default, CaseNode) and default.constant == "default" and default.break_case is False

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[11].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[14].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[15].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[12].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[13].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[8].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[2].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[5].instructions


def test_insert_after_existing_case(task):
    """
          test_18
                                                                           +-----------------------------------------------+
                                                                           |                                               |
       +----------------------------------------------------------------+  |  +------------------------------------+       |
       |                                                                |  |  |                 0.                 |       |
       |                               1.                               |  |  | printf("Enter week number(1-7): ") |       |
       |                        printf("Friday")                        |  |  |   __isoc99_scanf("%d", &(var_0))   |       |
       |                                                                | <+- |         if(var_0 == 0x1f4)         |       |
       +----------------------------------------------------------------+  |  +------------------------------------+       |
         |                                                                 |    |                                          |
         |                                                                 |    |                                          |
         v                                                                 |    v                                          |
       +----------------------------------------------------------------+  |  +------------------------------------+       |
       |                               3.                               |  |  |                 2.                 |       |
    +> | printf("Invalid input! Please enter week number between 1-7.") | <+  |         if(var_0 > 0x1f4)          | -+    |
    |  +----------------------------------------------------------------+     +------------------------------------+  |    |
    |    |                                                                      |                                     |    |
    |    |                                                                      |                                     |    |
    |    |                                                                      v                                     |    |
    |    |                                                                    +------------------------------------+  |  +------------------+
    |    |                                                                    |                 5.                 |  |  |        8.        |
    |    |                                                                    |          if(var_0 == 0x1)          | -+> | if(var_0 == 0xc) |
    |    |                                                                    +------------------------------------+  |  +------------------+
    |    |                                                                      |                                     |    |
    |    |                                                                      |                                     |    |
    |    |                                                                      v                                     |    |
    |    |                                                                    +------------------------------------+  |    |
    |    |                                                                    |                 7.                 |  |    |
    |    |                                                                    |          printf("Monday")          |  |    |
    |    |                                                                    |       var_0 = var_0 + 0x1f4        |  |    |
    |    |                                                                    +------------------------------------+  |    |
    |    |                                                                      |                                     |    |
    |    |                                                                      |                                     |    |
    |    |                                                                      v                                     |    |
    |    |                                                                    +------------------------------------+  |    |
    |    |                                                                    |                 9.                 |  |    |
    |    |                                                                    |         printf("Tuesday")          | <+----+
    |    |                                                                    +------------------------------------+  |
    |    |                                                                      |                                     |
    |    |                                                                      |                                     |
    |    |                                                                      v                                     |
    |    |                                                                    +------------------------------------+  |
    |    |                                                                    |                 6.                 |  |
    |    |                                                                    | printf("the number is %d", var_0)  |  |
    |    +------------------------------------------------------------------> |             return 0x0             |  |
    |                                                                         +------------------------------------+  |
    |                                                                                                                 |
    +-----------------------------------------------------------------------------------------------------------------+
    """
    var_0_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_0_2 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 2, True, None))
    var_0_5 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 5, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(
                        ListOperation([]),
                        scanf_call(
                            UnaryOperation(OperationType.address, [var_0_0], Pointer(Integer(32, True), 32), None, False), 134524965, 2
                        ),
                    ),
                    Branch(Condition(OperationType.equal, [var_0_2, Constant(500, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Assignment(ListOperation([]), print_call("Friday", 3))]),
            BasicBlock(2, [Branch(Condition(OperationType.greater, [var_0_2, Constant(500, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(3, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 11))]),
            BasicBlock(5, [Branch(Condition(OperationType.equal, [var_0_2, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(6, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(
                7,
                [
                    Assignment(ListOperation([]), print_call("Monday", 4)),
                    Assignment(
                        var_0_5, BinaryOperation(OperationType.plus, [var_0_2, Constant(500, Integer(32, True))], Integer(32, True))
                    ),
                ],
            ),
            BasicBlock(8, [Branch(Condition(OperationType.equal, [var_0_2, Constant(12, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Tuesday", 5))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            TrueCase(vertices[2], vertices[3]),
            FalseCase(vertices[2], vertices[4]),
            UnconditionalEdge(vertices[3], vertices[5]),
            TrueCase(vertices[4], vertices[6]),
            FalseCase(vertices[4], vertices[7]),
            UnconditionalEdge(vertices[6], vertices[8]),
            TrueCase(vertices[7], vertices[8]),
            FalseCase(vertices[7], vertices[3]),
            UnconditionalEdge(vertices[8], vertices[5]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 4
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(cond := seq_node.children[2], ConditionNode) and cond.false_branch is None
    assert isinstance(seq_node.children[3], CodeNode) and seq_node.children[3].instructions == vertices[5].instructions

    # switch node:
    assert switch.expression == var_0_2 and len(switch.children) == 3
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32, True)) and case1.break_case is False
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(12, Integer(32, True)) and case2.break_case is True
    assert (
        isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(500, Integer(32, True)) and case3.break_case is True
    )

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[6].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[8].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[1].instructions

    # condition node
    assert cond.condition.is_conjunction and len(operands := cond.condition.operands) == 2
    for op in operands:
        assert (
            op.is_negation
            and op.operands[0].is_symbol
            and task.syntax_tree.condition_map[op.operands[0]]
            in {vertices[4].instructions[-1].condition, vertices[7].instructions[-1].condition}
        )
    assert isinstance(cn := cond.true_branch_child, CodeNode) and cn.instructions == vertices[3].instructions


def test_nested_cases_unnecessary_condition_all_irrelevant(task):
    """Test switch test 18_b"""
    var_0_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 0, True, None))
    var_0_2 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 2, True, None))
    var_0_5 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 5, True, None))
    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(
                        ListOperation([]),
                        scanf_call(
                            UnaryOperation(OperationType.address, [var_0_0], Pointer(Integer(32, True), 32), None, False), 134524965, 2
                        ),
                    ),
                    Branch(Condition(OperationType.equal, [var_0_2, Constant(500, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Assignment(ListOperation([]), print_call("Friday", 3))]),
            BasicBlock(2, [Branch(Condition(OperationType.greater, [var_0_2, Constant(500, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(3, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(5, [Branch(Condition(OperationType.equal, [var_0_2, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(6, [Assignment(ListOperation([]), print_call("Invalid input! Please enter week number between 1-7.", 11))]),
            BasicBlock(
                7,
                [
                    Assignment(ListOperation([]), print_call("Monday", 4)),
                    Assignment(
                        var_0_5, BinaryOperation(OperationType.plus, [var_0_2, Constant(500, Integer(32, True))], Integer(32, True))
                    ),
                ],
            ),
            BasicBlock(8, [Branch(Condition(OperationType.equal, [var_0_2, Constant(12, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(9, [Assignment(ListOperation([]), print_call("Tuesday", 5))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            TrueCase(vertices[2], vertices[5]),
            FalseCase(vertices[2], vertices[4]),
            TrueCase(vertices[4], vertices[6]),
            FalseCase(vertices[4], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[3]),
            UnconditionalEdge(vertices[6], vertices[8]),
            TrueCase(vertices[7], vertices[8]),
            FalseCase(vertices[7], vertices[5]),
            UnconditionalEdge(vertices[8], vertices[3]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 3
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(switch := seq_node.children[1], SwitchNode)
    assert isinstance(seq_node.children[2], CodeNode) and seq_node.children[2].instructions == vertices[3].instructions

    # switch node:
    assert switch.expression == var_0_2 and len(switch.children) == 4
    assert isinstance(case1 := switch.cases[0], CaseNode) and case1.constant == Constant(1, Integer(32, True)) and case1.break_case is False
    assert isinstance(case2 := switch.cases[1], CaseNode) and case2.constant == Constant(12, Integer(32, True)) and case2.break_case is True
    assert (
        isinstance(case3 := switch.cases[2], CaseNode) and case3.constant == Constant(500, Integer(32, True)) and case3.break_case is True
    )
    assert isinstance(default := switch.default, CaseNode)

    # children of cases
    assert isinstance(case1.child, CodeNode) and case1.child.instructions == vertices[6].instructions
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[8].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[1].instructions
    assert isinstance(default.child, CodeNode) and default.child.instructions == vertices[5].instructions


def test_nested_cases_unnecessary_condition_not_all_irrelevant_2(task):
    """Test condition test 17"""
    var_0 = Variable("var_0", Integer(32, True), None, True, Variable("var_10", Integer(32, True), 3, True, None))
    arg1 = Variable("arg1", Integer(32, True), None, True, Variable("arg1", Integer(32, True), 0, True, None))
    arg1_3 = Variable("arg1", Integer(32, True), None, True, Variable("eax", Integer(32, True), 3, True, None))
    arg1_15 = Variable("arg1", Integer(32, True), None, True, Variable("var_24_1", Integer(32, True), 15, True, None))
    arg1_8 = Variable("arg1", Integer(32, True), None, True, Variable("eax", Integer(32, True), 8, True, None))
    var_1_15 = Variable("var_1", Integer(32, True), None, False, Variable("var_20_1", Integer(32, True), 15, False, None))
    var_2_1 = Variable("var_2", Integer(32, True), None, False, Variable("edx", Integer(32, True), 1, False, None))
    var_2_13 = Variable("var_2", Integer(32, True), None, False, Variable("edx", Integer(32, True), 13, False, None))
    var_3_12 = Variable("var_3", Integer(32, True), None, False, Variable("eax_1", Integer(32, True), 12, False, None))

    task.graph.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(ListOperation([]), print_call("Enter week number(1-7): ", 1)),
                    Assignment(
                        ListOperation([]),
                        scanf_call(
                            UnaryOperation(OperationType.address, [var_0], Pointer(Integer(32, True), 32), None, False), 0x134524965, 2
                        ),
                    ),
                    Branch(Condition(OperationType.not_equal, [var_0, Constant(1, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.not_equal, [var_0, Constant(2, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(2, [Branch(Condition(OperationType.not_equal, [arg1, Constant(7, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(3, [Assignment(arg1_3, var_0)]),
            BasicBlock(4, [Assignment(ListOperation([]), print_call("Tuesday", 5))]),
            BasicBlock(5, [Assignment(arg1_8, var_0)]),
            BasicBlock(
                6,
                [
                    Assignment(var_1_15, var_2_1),
                    Assignment(arg1_15, Constant(1, Integer.int32_t())),
                    Assignment(
                        var_3_12, StringSymbol("The Input is 7 and you choose week number %d", 8949, Pointer(Integer.int32_t(), 32))
                    ),
                ],
            ),
            BasicBlock(7, [Branch(Condition(OperationType.not_equal, [var_0, Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(8, [Assignment(ListOperation([]), print_call("Wednesday", 7))]),
            BasicBlock(9, [Branch(Condition(OperationType.not_equal, [var_0, Constant(4, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(10, [Assignment(ListOperation([]), print_call("Thursday", 8))]),
            BasicBlock(11, [Branch(Condition(OperationType.not_equal, [var_0, Constant(5, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(12, [Assignment(ListOperation([]), print_call("Friday", 9))]),
            BasicBlock(13, [Branch(Condition(OperationType.not_equal, [var_0, Constant(6, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(14, [Assignment(ListOperation([]), print_call("Saturday", 10))]),
            BasicBlock(15, [Branch(Condition(OperationType.not_equal, [var_0, Constant(7, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(16, [Assignment(ListOperation([]), print_call("Sunday", 12))]),
            BasicBlock(17, [Branch(Condition(OperationType.not_equal, [var_0, Constant(1, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                18,
                [
                    Assignment(var_1_15, var_2_13),
                    Assignment(arg1_15, var_2_13),
                    Assignment(var_3_12, StringSymbol("Monday", 8521, Pointer(Integer.int32_t(), 32))),
                ],
            ),
            BasicBlock(19, [Assignment(ListOperation([]), print_call("common case", 13))]),
            BasicBlock(20, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    task.graph.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[3]),
            FalseCase(vertices[1], vertices[4]),
            TrueCase(vertices[2], vertices[5]),
            FalseCase(vertices[2], vertices[6]),
            UnconditionalEdge(vertices[3], vertices[7]),
            UnconditionalEdge(vertices[4], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[11]),
            UnconditionalEdge(vertices[6], vertices[19]),
            TrueCase(vertices[7], vertices[9]),
            FalseCase(vertices[7], vertices[8]),
            UnconditionalEdge(vertices[8], vertices[9]),
            TrueCase(vertices[9], vertices[11]),
            FalseCase(vertices[9], vertices[10]),
            UnconditionalEdge(vertices[10], vertices[11]),
            TrueCase(vertices[11], vertices[13]),
            FalseCase(vertices[11], vertices[12]),
            UnconditionalEdge(vertices[12], vertices[13]),
            TrueCase(vertices[13], vertices[15]),
            FalseCase(vertices[13], vertices[14]),
            UnconditionalEdge(vertices[14], vertices[15]),
            TrueCase(vertices[15], vertices[17]),
            FalseCase(vertices[15], vertices[16]),
            UnconditionalEdge(vertices[16], vertices[17]),
            TrueCase(vertices[17], vertices[20]),
            FalseCase(vertices[17], vertices[18]),
            UnconditionalEdge(vertices[18], vertices[19]),
            UnconditionalEdge(vertices[19], vertices[20]),
        ]
    )

    PatternIndependentRestructuring().run(task)

    assert isinstance(seq_node := task._ast.root, SeqNode) and len(seq_node.children) == 4
    assert isinstance(seq_node.children[0], CodeNode) and seq_node.children[0].instructions == vertices[0].instructions[:-1]
    assert isinstance(cond := seq_node.children[1], ConditionNode)
    assert isinstance(switch := seq_node.children[2], SwitchNode)
    assert isinstance(seq_node.children[3], CodeNode) and seq_node.children[3].instructions == vertices[20].instructions

    # condition node:
    assert cond.condition.is_conjunction and {task._ast.condition_map[l] for l in cond.condition.operands} == {
        vertices[0].instructions[-1].condition,
        vertices[1].instructions[0].condition,
    }
    assert cond.false_branch is None and isinstance(cn := cond.true_branch_child, CodeNode) and cn.instructions == vertices[3].instructions

    # switch node:
    assert switch.expression == var_0 and len(switch.children) == 7
    assert (
        isinstance(case1 := switch.cases[0], CaseNode)
        and case1.constant == Constant(1, Integer(32, signed=True))
        and case1.break_case is True
    )
    assert (
        isinstance(case2 := switch.cases[1], CaseNode)
        and case2.constant == Constant(2, Integer(32, signed=True))
        and case2.break_case is True
    )
    assert (
        isinstance(case3 := switch.cases[2], CaseNode)
        and case3.constant == Constant(3, Integer(32, signed=True))
        and case3.break_case is True
    )
    assert (
        isinstance(case4 := switch.cases[3], CaseNode)
        and case4.constant == Constant(4, Integer(32, signed=True))
        and case4.break_case is True
    )
    assert (
        isinstance(case5 := switch.cases[4], CaseNode)
        and case5.constant == Constant(5, Integer(32, signed=True))
        and case5.break_case is True
    )
    assert (
        isinstance(case6 := switch.cases[5], CaseNode)
        and case6.constant == Constant(6, Integer(32, signed=True))
        and case6.break_case is True
    )
    assert (
        isinstance(case7 := switch.cases[6], CaseNode)
        and case7.constant == Constant(7, Integer(32, signed=True))
        and case7.break_case is True
    )

    # children of cases
    assert isinstance(case1.child, SeqNode)
    assert isinstance(case2.child, CodeNode) and case2.child.instructions == vertices[4].instructions
    assert isinstance(case3.child, CodeNode) and case3.child.instructions == vertices[8].instructions
    assert isinstance(case4.child, CodeNode) and case4.child.instructions == vertices[10].instructions
    assert isinstance(case5.child, CodeNode) and case5.child.instructions == vertices[12].instructions
    assert isinstance(case6.child, CodeNode) and case6.child.instructions == vertices[14].instructions
    assert isinstance(case7.child, CodeNode) and case7.child.instructions == vertices[16].instructions
