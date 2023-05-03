from math import inf, nan

import pytest
from decompiler.structures.pseudo import OperationType, UnaryOperation
from decompiler.structures.pseudo.expressions import (
    Constant,
    ExternConstant,
    ExternFunctionPointer,
    FunctionSymbol,
    GlobalVariable,
    ImportedFunctionSymbol,
    NotUseableConstant,
    RegisterPair,
    Symbol,
    Variable,
)
from decompiler.structures.pseudo.typing import Float, Integer, Pointer, UnknownType

# placeholders for type. When type system is implemented, one won't need to change types overall in the tests
i32 = Integer.int32_t()
i64 = Integer.int64_t()
no_type = UnknownType()


class TestVariable:
    def test_requirements(self):
        v = Variable("v", no_type, 0)
        assert v.requirements == [v]

    def test_complexity(self):
        assert Variable("v1", no_type, 0).complexity == 1

    def test_str(self):
        assert str(Variable("v1", no_type, 0)) == "v1#0"
        assert str(Variable("v2", i32, 0)) == "v2#0"
        assert str(Variable("v3", i32, 3)) == "v3#3"
        assert str(Variable("v4", i32, None)) == "v4"

    def test_repr(self):
        v = Variable("v", no_type, 0)
        assert repr(v) == f"v#0 (type: {no_type} aliased: False)"
        v.unsubscript()
        assert repr(v) == f"v#None (type: {no_type} aliased: False)"
        v.ssa_label = 3
        v.is_aliased = True
        assert repr(v) == f"v#3 (type: {no_type} aliased: True)"
        v2 = Variable("v", i32, 7)
        assert repr(v2) == f"v#7 (type: {i32} aliased: False)"

    def test_unsubscript(self):
        v = Variable("v", no_type, 0)
        assert str(v) == "v#0"
        v.unsubscript()
        assert str(v) == "v"
        v.ssa_label = 9
        assert v.ssa_label == 9
        v.unsubscript()
        assert v.ssa_label is None
        v.unsubscript()
        assert v.ssa_label is None

    def test_equal(self):
        v = Variable("v", i32, 0)
        assert v != Variable("v1", i32, 0)
        assert v != Variable("v", i32, 7)
        assert v != Variable("v", i64, 0)
        assert v != Variable("v", no_type, 0)
        v.is_aliased = True
        assert v != Variable("v", i32, 0)
        v.is_aliased = False
        assert v == Variable("v", i32, 0)

    def test_substitute(self):
        """Substitute shall have no effect when called directly on variables."""
        v = Variable("v", i32, 0)
        v.substitute(v, Variable("x", i32, 1))
        assert v == Variable("v", i32, 0)

    def test_iter(self):
        """Iterating a non compound expression should always yield nothing."""
        assert list(Variable("v1", i32, 0)) == []
        assert list(Variable("v", no_type, 0)) == []
        assert list(Variable("x", i32, 5, is_aliased=True)) == []


class TestGlobalVariable:
    def test_initial_value(self):
        assert GlobalVariable("var_1", initial_value=42).initial_value == 42

    def test_defaults(self):
        global_var = GlobalVariable("var_1", Integer.char())
        assert global_var.initial_value is None
        assert global_var.ssa_label is None
        assert global_var.is_aliased is True

    def test_copy(self):
        original = GlobalVariable("var_1", Integer.char(), ssa_label=3, initial_value=42)
        copy = original.copy()
        assert isinstance(copy, GlobalVariable)
        assert id(original) != id(copy) and original == copy
        assert copy.type == Integer.char()
        assert copy.ssa_label == original.ssa_label == 3
        assert copy.initial_value == original.initial_value == 42
        assert copy.is_aliased and original.is_aliased

    def test_copy_with_replacement(self):
        original = GlobalVariable("var_1", Integer.char(), ssa_label=3, initial_value=42)
        copy = original.copy(ssa_label=4)
        assert isinstance(copy, GlobalVariable)
        assert id(original) != id(copy) and original != copy
        assert copy.type == Integer.char()
        assert copy.ssa_label == 4
        assert copy.initial_value == original.initial_value == 42
        assert copy.is_aliased and original.is_aliased

    def test_initial_value_is_copied_correctly(self):
        g1 = GlobalVariable("g1", Integer.char(), ssa_label=3, initial_value=42)
        g1_copy = g1.copy()
        assert g1_copy.initial_value == g1.initial_value == 42
        g1_copy_with_replacement = g1.copy(initial_value=84)
        assert g1_copy_with_replacement.initial_value == 84
        some_glob = GlobalVariable("g", Integer.char())
        g2 = GlobalVariable("g2", Integer.char(), ssa_label=3, initial_value=some_glob)
        g2_copy = g2.copy()
        assert g2.initial_value == g2_copy.initial_value == some_glob
        assert id(g2.initial_value) != id(g2_copy.initial_value)
        addr_glob = UnaryOperation(OperationType.address, [some_glob])
        g2_copy_with_replacement = g2.copy(initial_value=addr_glob)
        assert g2_copy_with_replacement.initial_value == addr_glob
        assert id(addr_glob) != id(g2_copy_with_replacement.initial_value)


class TestConstant:
    def test_str(self):
        assert str(Constant(0x42)) == "0x42"
        assert str(Constant("0x24")) == '"0x24"'
        assert str(Constant(10)) == "0xa"
        assert str(Constant(0x4F56FFFF)) == "0x4f56ffff"
        assert str(Constant("something")) == '"something"'
        assert str(Constant("")) == '""'
        assert str(Constant(0x10000, pointee=Constant("Hello, World!"))) == '"Hello, World!"'

    def test_requirements(self):
        assert Constant(0x42).requirements == []

    def test_complexity(self):
        assert Constant(0x42).complexity == 1
        assert Constant(0, i32, Constant("c", Integer.char())).complexity == 1

    def test_equal(self):
        const = Constant(0, Pointer(i32), pointee=Constant("a", Integer.char()))
        assert const == Constant(0, Pointer(i32), pointee=Constant("a", Integer.char()))
        assert const != Constant(0, Pointer(i32), pointee=Constant("b", Integer.char()))
        assert Constant(0x42) != Constant("0x42")
        assert Constant(0, i32) != Constant(0, i64)

    def test_repr(self):
        assert repr(Constant(0x42, i32)) == "66 type: int"
        assert repr(Constant(8799946, i64)) == "8799946 type: long"
        assert repr(Constant(4.2, Float.float())) == "4.2 type: float"
        assert repr(Constant("0x42", Integer.char())) == '"0x42" type: char'
        assert repr(Constant("%d\n", Pointer(Integer.char()))) == '"%d\\n" type: char *'
        assert repr(Constant(0, Pointer(i32), pointee=Constant("a", Integer.char()))) == '0 type: int *, pointee: "a" type: char'

    def test_substitute(self):
        """Substitute shall have no effect when called directly on a variable."""
        v = Constant(0)
        v.substitute(v, Constant(1))
        assert v == Constant(0)

    def test_iter(self):
        """Iterating a Constant should yield nothing."""
        assert list(Constant(0x42, i32)) == []
        assert list(Constant("0x42", i32)) == []
        assert list(Constant(2, i32, pointee=Constant("a", Integer.char()))) == []

    def test_copy(self):
        """Copying constants should be unproblematic."""
        original = Constant(1, i32)
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        original = Constant(1, Pointer(i32), pointee=Constant("a", Integer.char()))
        copy = original.copy()
        assert id(original) != id(copy) and original == copy


class TestNotUseableConstant:
    def test_str(self):
        assert str(NotUseableConstant(str(inf))) == "inf"
        assert str(NotUseableConstant(str(-inf))) == "-inf"
        assert str(NotUseableConstant(str(nan))) == "nan"

    def test_requirements(self):
        "Should not have requirements"
        assert NotUseableConstant(str(inf)).requirements == []

    def test_complexity(self):
        "Should have a complexity of 1"
        assert NotUseableConstant(str(inf)).complexity == 1

    def test_equal(self):
        "Should at least compare the id of the objects (inf == inf)"
        assert NotUseableConstant(str(inf)) != NotUseableConstant(str(-inf))
        assert NotUseableConstant(str(inf)) == NotUseableConstant(str(inf))

    def test_repr(self):
        assert repr(NotUseableConstant(str(inf))) == "inf type: not-usable-constant"
        assert repr(NotUseableConstant(str(-inf))) == "-inf type: not-usable-constant"
        assert repr(NotUseableConstant(str(nan))) == "nan type: not-usable-constant"

    def test_substitute(self):
        """Substitute shall have no effect when called directly on a variable."""
        v = NotUseableConstant(str(inf))
        v.substitute(v, NotUseableConstant(str(-inf)))
        assert v == NotUseableConstant(str(inf))

    def test_iter(self):
        assert list(NotUseableConstant(str(inf))) == []
        assert list(NotUseableConstant(str(inf))) == []
        assert list(NotUseableConstant(str(inf))) == []

    def test_copy(self):
        original = NotUseableConstant(str(inf))
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        

class TestExternConstant:
    def test_copy(self):
        original = ExternConstant("v1")
        copy = original.copy()
        assert isinstance(copy, ExternConstant)
        assert id(original) != id(copy) and original == copy


class TestExternFunctionPointer:
    def test_copy(self):
        original = ExternFunctionPointer("MyFunction")
        copy = original.copy()
        assert isinstance(copy, ExternFunctionPointer)
        assert id(original) != id(copy) and original == copy


class TestRegisterPair:
    reg_pair = RegisterPair(Variable("v1", i32, 3), Variable("v2", i32, 4), i64)

    def test_equal(self):
        assert self.reg_pair != RegisterPair(Variable("v1", i32, 3), Variable("v2", i64, 4), "")

    def test_str(self):
        assert str(self.reg_pair) == "(v1#3:v2#4)"

    def test_repr(self):
        assert repr(self.reg_pair) == "v1#3 (type: int aliased: False):v2#4 (type: int aliased: False) type: long"

    def test_requirements(self):
        assert set(self.reg_pair.requirements) == {Variable("v1", i32, 3), Variable("v2", i32, 4), self.reg_pair}

    def test_complexity(self):
        assert self.reg_pair.complexity == 2

    def test_order_in_pair(self):
        assert self.reg_pair.low == Variable("v2", i32, 4)
        assert self.reg_pair.high == Variable("v1", i32, 3)

    def test_substitute(self):
        """Substitute should affect both registers of the pair."""
        a = Variable("a", i32, 0)
        b = Variable("b", i32, 0)
        pair = RegisterPair(a, b, i64)
        pair.substitute(a, b)
        assert pair == RegisterPair(b, b, i64)
        pair.substitute(a, b)
        assert pair == RegisterPair(b, b, i64)
        pair = RegisterPair(a, a, i64)
        pair.substitute(a, b)
        assert pair == RegisterPair(b, b, i64)

    def test_iter(self):
        """Iterating a RegisterPair should yield both parts of the pair."""
        a = Variable("a", i32, 0)
        b = Variable("b", i32, 0)
        pair = RegisterPair(a, b, i64)
        assert list(pair) == [b, a]

    def test_copy(self):
        """Test correct copy of all nested expressions in a RegisterPair."""
        original = RegisterPair(Variable("a", i32, 0), Variable("b", i32, 0), i64)
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.low) != id(copy.low) and original.low == copy.low
        assert id(original.high) != id(copy.high) and original.high == copy.high


class TestSymbol:
    def test_str(self):
        assert str(Symbol("foo", 0x42)) == "foo"

    def test_repr(self):
        assert repr(Symbol("foo", 0x42)) == "symbol 'foo' at 0x42"

    def test_requirements(self):
        assert Symbol("foo", 0x42).requirements == []

    def test_complexity(self):
        assert Symbol("foo", 0x42).complexity == 1

    def test_equal(self):
        assert Symbol("foo", 0x42) == Symbol("foo", 0x42)
        assert Symbol("foo", 0x42) != Symbol("foo", 0x41)
        assert Symbol("foo", 0x42) != Symbol("foo2", 0x42)

    def test_iter(self):
        """Iterating should yield nothing."""
        assert list(Symbol("foo", 0x42)) == []

    def test_copy(self):
        original = Symbol("foo", 0x42)
        copy = original.copy()
        assert id(original) != id(copy) and original == copy


class TestFunctionSymbol:
    def test_str(self):
        assert str(FunctionSymbol("foo", 0x42)) == "foo"

    def test_repr(self):
        assert repr(FunctionSymbol("foo", 0x42)) == "symbol 'foo' at 0x42"

    def test_requirements(self):
        assert FunctionSymbol("foo", 0x42).requirements == []

    def test_complexity(self):
        assert FunctionSymbol("foo", 0x42).complexity == 1

    def test_equal(self):
        assert FunctionSymbol("foo", 0x42) == FunctionSymbol("foo", 0x42)
        assert FunctionSymbol("foo", 0x42) != FunctionSymbol("foo", 0x41)
        assert FunctionSymbol("foo", 0x42) != FunctionSymbol("foo2", 0x42)

    def test_iter(self):
        """Iterating should yield nothing."""
        assert list(FunctionSymbol("foo", 0x42)) == []

    def test_copy(self):
        original = FunctionSymbol("foo", 0x42)
        copy = original.copy()
        assert id(original) != id(copy) and original == copy


class TestImportedFunctionSymbol:
    def test_str(self):
        assert str(ImportedFunctionSymbol("foo", 0x42)) == "foo"

    def test_repr(self):
        assert repr(ImportedFunctionSymbol("foo", 0x42)) == "symbol 'foo' at 0x42"

    def test_requirements(self):
        assert ImportedFunctionSymbol("foo", 0x42).requirements == []

    def test_complexity(self):
        assert ImportedFunctionSymbol("foo", 0x42).complexity == 1

    def test_equal(self):
        assert ImportedFunctionSymbol("foo", 0x42) == ImportedFunctionSymbol("foo", 0x42)
        assert ImportedFunctionSymbol("foo", 0x42) != ImportedFunctionSymbol("foo", 0x41)
        assert ImportedFunctionSymbol("foo", 0x42) != ImportedFunctionSymbol("foo2", 0x42)

    def test_iter(self):
        """Iterating should yield nothing."""
        assert list(ImportedFunctionSymbol("foo", 0x42)) == []

    def test_copy(self):
        original = ImportedFunctionSymbol("foo", 0x42)
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
