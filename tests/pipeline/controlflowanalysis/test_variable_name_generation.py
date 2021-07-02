from typing import List

from dewolf.backend.codegenerator import CodeGenerator
from dewolf.pipeline.controlflowanalysis import VariableNameGeneration
from dewolf.structures.pseudo import Assignment, Constant, CustomType, Float, Integer, Pointer, Variable
from dewolf.structures.syntaxtree import AbstractSyntaxTree, CodeNode
from dewolf.task import DecompilerTask
from dewolf.util.decoration import DecoratedCode
from dewolf.util.options import Options

PIPELINE_NAME = VariableNameGeneration.name

I8 = Integer.int8_t()
I16 = Integer.int16_t()
I32 = Integer.int32_t()
I64 = Integer.int64_t()
I128 = Integer.int128_t()
UI8 = Integer.uint8_t()
UI16 = Integer.uint16_t()
UI32 = Integer.uint32_t()
UI64 = Integer.uint64_t()
UI128 = Integer.uint128_t()
HALF = Float(16)
FLOAT = Float.float()
DOUBLE = Float.double()
LONG_DOUBLE = Float(80)
QUADRUPLE = Float(128)
OCTUPLE = Float(256)
BOOL = CustomType.bool()
VOID = CustomType.void()

ALL_TYPES = [I8, I16, I32, I64, I128, UI8, UI16, UI32, UI64, UI128, HALF, FLOAT, DOUBLE, LONG_DOUBLE, QUADRUPLE, OCTUPLE, BOOL, VOID]


def _generate_all_type_assignments() -> List[Assignment]:
    assignments: List[Assignment] = []
    for index, var_type in enumerate(ALL_TYPES):
        assignments.append(Assignment(Variable(f"var_{index}", var_type), Constant(0)))
        assignments.append(Assignment(Variable(f"var_p_{index}", Pointer(var_type)), Constant(0)))
    return assignments


def _generate_options(notation: str = "system_hungarian", pointer_base: bool = True, type_sep: str = "", counter_sep: str = "") -> Options:
    options = Options()
    options.set(f"{PIPELINE_NAME}.notation", notation)
    options.set(f"{PIPELINE_NAME}.pointer_base", pointer_base)
    options.set(f"{PIPELINE_NAME}.type_separator", type_sep)
    options.set(f"{PIPELINE_NAME}.counter_separator", counter_sep)
    return options


def _run_vng(ast: AbstractSyntaxTree, options: Options = _generate_options()):
    task = DecompilerTask("variable_name_generation", None, ast, options, VOID)
    VariableNameGeneration().run(task)
    DecoratedCode.print_code(CodeGenerator().from_task(task))


def test_hungarian_notation_0():
    ast = AbstractSyntaxTree(CodeNode(_generate_all_type_assignments()), {})
    _run_vng(ast, _generate_options(type_sep="_", counter_sep="_"))


def test_hungarian_notation_1():
    ast = AbstractSyntaxTree(CodeNode(Assignment(Variable("var_0", I32), Constant(0))), {})
    _run_vng(ast, _generate_options(notation="default"))
