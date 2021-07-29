from typing import List

import pytest
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
    options.set(f"code-generator.max_complexity", 100)
    options.set("code-generator.use_increment_int", False)
    options.set("code-generator.use_increment_float", False)
    options.set("code-generator.use_compound_assignment", True)
    return options


def _run_vng(ast: AbstractSyntaxTree, options: Options = _generate_options()):
    task = DecompilerTask("variable_name_generation", None, ast, options, VOID)
    VariableNameGeneration().run(task)
    DecoratedCode.print_code(CodeGenerator().from_task(task))


def test_default_notation_1():
    ast = AbstractSyntaxTree(CodeNode(Assignment(var := Variable("var_0", I32), Constant(0))), {})
    _run_vng(ast, _generate_options(notation="default"))
    assert var.name == "var_0"


class TestHungarianNotation:
    def test_hungarian_notation_all_types(self):
        ast = AbstractSyntaxTree(cn := CodeNode(_generate_all_type_assignments()), {})
        _run_vng(ast)
        assert [str(_) for _ in cn.stmts] == [
            "chVar0 = 0x0",
            "chpVar0 = 0x0",
            "sVar1 = 0x0",
            "spVar1 = 0x0",
            "iVar2 = 0x0",
            "ipVar2 = 0x0",
            "lVar3 = 0x0",
            "lpVar3 = 0x0",
            "i128Var4 = 0x0",
            "ip128Var4 = 0x0",
            "uchVar5 = 0x0",
            "uchpVar5 = 0x0",
            "usVar6 = 0x0",
            "uspVar6 = 0x0",
            "uiVar7 = 0x0",
            "uipVar7 = 0x0",
            "ulVar8 = 0x0",
            "ulpVar8 = 0x0",
            "ui128Var9 = 0x0",
            "uip128Var9 = 0x0",
            "hVar10 = 0x0",
            "hpVar10 = 0x0",
            "fVar11 = 0x0",
            "fpVar11 = 0x0",
            "dVar12 = 0x0",
            "dpVar12 = 0x0",
            "ldVar13 = 0x0",
            "ldpVar13 = 0x0",
            "qVar14 = 0x0",
            "qpVar14 = 0x0",
            "oVar15 = 0x0",
            "opVar15 = 0x0",
            "bVar16 = 0x0",
            "bpVar16 = 0x0",
            "vVar17 = 0x0",
            "vpVar17 = 0x0",
        ]

    @pytest.mark.parametrize("type_sep, counter_sep", [("", ""), ("_", "_")])
    def test_hungarian_notation_separators(self, type_sep: str, counter_sep: str):
        ast = AbstractSyntaxTree(CodeNode(Assignment(var := Variable("var_0", I32), Constant(0))), {})
        _run_vng(ast, _generate_options(type_sep=type_sep, counter_sep=counter_sep))
        assert var.name == f"i{type_sep}Var{counter_sep}0"
