from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import (
    Assignment,
    Branch,
    Break,
    Comment,
    Continue,
    IndirectBranch,
    MemPhi,
    Phi,
    Relation,
    Return,
)
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer

a = Variable("a", Integer.int32_t(), 0)
b = Variable("b", Integer.int32_t(), 1)
c = Variable("c", Integer.int32_t(), 2)
d = Variable("d", Integer.int32_t(), 3)

neg = OperationType.negate
mul = OperationType.multiply
lte = OperationType.less_or_equal
eq = OperationType.equal
neq = OperationType.not_equal
lnot = OperationType.logical_not
xor = OperationType.bitwise_xor
deref = OperationType.dereference


class TestComment:
    def test_repr(self):
        comment = Comment("test comment", comment_style="debug")
        assert str(comment) == "## test comment ##"
        assert repr(comment) == "## test comment ##"
        c_comment = Comment("test comment", comment_style="C")
        assert str(c_comment) == "/* test comment */"
        assert repr(c_comment) == "/* test comment */"
        html_comment = Comment("test comment", comment_style="html")
        assert str(html_comment) == "todo test comment todo"
        assert repr(html_comment) == "todo test comment todo"

    def test_complexity(self):
        assert Comment("test comment").complexity == 0

    def test_requirements(self):
        assert Comment("test comment").requirements == []

    def test_iter(self):
        assert list(Comment("test comment")) == []

    def test_copy(self):
        original = Comment("test")
        copy = original.copy()
        assert id(original) != id(copy) and original == copy


class TestAssignment:
    def test_requirements(self):
        assert Assignment(a, Constant(8)).requirements == []
        assert Assignment(a, b).requirements == [b]
        assert set(Assignment(a, BinaryOperation(xor, [b, c])).requirements) == {b, c}
        assert set(Assignment(UnaryOperation(deref, [a]), b).requirements) == {a, b}
        assert set(Assignment(ListOperation([a, b]), Call(d, [c])).requirements) == {d, c}
        assert set(Assignment(UnaryOperation(OperationType.cast, [a], contraction=True), b).requirements) == {b}

    def test_definitions(self):
        assert Assignment(a, Constant(8)).definitions == [a]
        assert Assignment(a, b).definitions == [a]
        assert set(Assignment(a, BinaryOperation(xor, [b, c])).definitions) == {a}
        assert Assignment(UnaryOperation(deref, [a]), b).definitions == []
        assert set(Assignment(ListOperation([a, b]), Call(d, [c])).definitions) == {a, b}
        assert set(Assignment(UnaryOperation(OperationType.cast, [a], contraction=True), b).definitions) == {a}

    def test_substitute(self):
        i = Assignment(a, b)
        i.substitute(b, c)
        assert str(i) == "a#0 = c#2"
        i.substitute(c, BinaryOperation(mul, [b, d]))
        assert str(i) == "a#0 = b#1 * d#3"
        i.substitute(d, c)
        assert str(i) == "a#0 = b#1 * c#2"
        i.substitute(c, BinaryOperation(mul, [UnaryOperation(neg, [b]), b]))
        assert str(i) == "a#0 = b#1 * ((-(b#1)) * b#1)"
        i.substitute(b, c)
        assert str(i) == "a#0 = c#2 * ((-(c#2)) * c#2)"
        i.substitute(UnaryOperation(neg, [c]), b)
        assert str(i) == "a#0 = c#2 * (b#1 * c#2)"

    def test_substitute_in_call_assignment(self):
        i = Assignment(ListOperation([a, b]), Call(d, [c]))
        i.substitute(d, a)
        # function in call is substituted
        assert str(i) == "a#0,b#1 = a#0(c#2)"
        i.substitute(c, a)
        # call parameters are substituted
        assert str(i) == "a#0,b#1 = a#0(a#0)"
        i = Assignment(ListOperation([]), Call(FunctionSymbol("print", 0x42), [a, b, c]))
        i.substitute(a, d)
        assert str(i) == "print(d#3, b#1, c#2)"
        i.substitute(b, UnaryOperation(neg, [a]))
        assert str(i) == "print(d#3, -(a#0), c#2)"

    def test_substitute_in_dereference_assignment(self):
        i = Assignment(UnaryOperation(deref, [a]), b)
        i.substitute(a, d)
        assert str(i) == "*(d#3) = b#1"
        i = Assignment(UnaryOperation(deref, [a]), BinaryOperation(xor, [a, Constant(1)]))
        # is it legal????
        i.substitute(a, b)
        assert str(i) == "*(b#1) = b#1 ^ 0x1"

    def test_complexity(self):
        assert Assignment(a, Constant(8)).complexity == 2
        assert Assignment(a, b).complexity == 2
        assert Assignment(a, BinaryOperation(xor, [b, c])).complexity == 3
        assert Assignment(UnaryOperation(deref, [a]), b).complexity == 2
        assert Assignment(ListOperation([a, b]), Call(d, [c])).complexity == 3

    def test_iter(self):
        """Test if the iter function of Assignments return both sides."""
        assert list(Assignment(a, b)) == [a, b]
        assert list(Assignment(a, BinaryOperation(xor, [b, c]))) == [a, BinaryOperation(xor, [b, c])]

    def test_copy(self):
        """Check if the assignment and its components are copied correctly and not be reference only."""
        original = Assignment(a, Constant(8))
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.destination) != id(copy.destination) and original.destination == copy.destination
        assert id(original.value) != id(copy.value) and original.value == copy.value
        assert original.writes_memory == copy.writes_memory


class TestRelation:
    def test_requirements(self):
        assert Relation(a, b).requirements == [b]

    def test_definitions(self):
        assert Relation(a, b).definitions == [a]

    def test_string(self):
        assert str(Relation(a, b)) == "a#0 -> b#1"

    def test_substitute(self):
        i = Relation(a, b)
        i.substitute(b, c)
        assert str(i) == "a#0 -> b#1"
        i.substitute(b, Variable("b", Integer.int32_t(), 0))
        assert str(i) == "a#0 -> b#0"
        i.substitute(c, BinaryOperation(mul, [b, d]))
        assert str(i) == "a#0 -> b#0"
        i.substitute(d, b)
        assert str(i) == "a#0 -> b#0"
        i.substitute(a, b)
        assert str(i) == "a#0 -> b#0"

    def test_rename(self):
        i = Relation(a, b)
        i.rename(b, c)
        assert str(i) == "a#0 -> c#2"
        i.rename(d, b)
        assert str(i) == "a#0 -> c#2"
        i.rename(a, b)
        assert str(i) == "b#1 -> c#2"

    def test_complexity(self):
        assert Relation(a, b).complexity == 2

    def test_iter(self):
        """Test if the iter function of Relation return both sides."""
        assert list(Relation(a, b)) == [a, b]

    def test_copy(self):
        """Check if the Relation and its components are copied correctly and not be reference only."""
        original = Relation(a, b)
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.destination) != id(copy.destination) and original.destination == copy.destination
        assert id(original.value) != id(copy.value) and original.value == copy.value


class TestBranch:
    def test_requirements(self):
        assert set(Branch(Condition(lte, [a, b])).requirements) == {a, b}
        assert set(Branch(Condition(lte, [Call(a, [b]), Constant(0)])).requirements) == {a, b}

    def test_complexity(self):
        assert Branch(Condition(lte, [a, b])).complexity == 2
        assert Branch(Condition(lte, [a, Condition(lte, [b, c])])).complexity == 3
        assert Branch(Condition(lnot, [a])).complexity == 1

    def test_definitions(self):
        assert Branch(Condition(lte, [a, b])).definitions == []
        assert Branch(Condition(lnot, [a])).definitions == []

    def test_substitute_and_string(self):
        i = Branch(Condition(neq, [a, Constant(0)]))
        i.substitute(a, b)
        assert str(i) == "if(b#1 != 0x0)"
        i.substitute(b, Call(a, [b]))
        assert str(i) == "if((a#0(b#1)) != 0x0)"
        i.substitute(Call(a, [b]), BinaryOperation(xor, [a, b]))
        assert str(i) == "if((a#0 ^ b#1) != 0x0)"
        i.substitute(a, d)
        assert str(i) == "if((d#3 ^ b#1) != 0x0)"
        i.substitute(BinaryOperation(xor, [d, b]), Condition(eq, [a, b]))
        assert str(i) == "if(a#0 == b#1)"
        i.substitute(b, BinaryOperation(xor, [d, b]))
        assert str(i) == "if(a#0 == (d#3 ^ b#1))"
        i.substitute(b, BinaryOperation(xor, [a, c]))
        assert str(i) == "if(a#0 == (d#3 ^ (a#0 ^ c#2)))"
        i = Branch(Condition(neq, [a, Constant(0)]))
        i.substitute(a, BinaryOperation(lte, [b, c]))
        assert isinstance(i.condition, Condition) and str(i) == "if(b#1 <= c#2)"
        i = Branch(Condition(eq, [a, Constant(0)]))
        i.substitute(a, BinaryOperation(lte, [b, c]))
        assert isinstance(i.condition, Condition) and str(i) == "if(b#1 > c#2)"
        i = Branch(Condition(eq, [a, Constant(4)]))
        i.substitute(a, BinaryOperation(lte, [b, c]))
        assert isinstance(i.condition, Condition) and str(i) == "if((b#1 <= c#2) == 0x4)"

    def test_iter(self):
        """Check if iterating a Branch instruction only yields the condition value."""
        assert list(Branch(Condition(lte, [a, b]))) == [Condition(lte, [a, b])]

    def test_copy(self):
        """Test if the nested expressions of a branch instruction are copied correctly."""
        original = Branch(Condition(lte, [a, b]))
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.condition) != id(copy.condition) and original.condition == copy.condition


class TestIndirectBranch:
    def test_complexity(self):
        assert IndirectBranch(BinaryOperation(mul, [a, b])).complexity == 2
        assert IndirectBranch(BinaryOperation(mul, [a, BinaryOperation(mul, [c, d])])).complexity == 3
        assert IndirectBranch(BinaryOperation(mul, [Constant(4), b])).complexity == 2
        assert IndirectBranch(a).complexity == 1
        assert IndirectBranch(Constant(4)).complexity == 1

    def test_expression(self):
        assert IndirectBranch(BinaryOperation(mul, [a, b])).expression == BinaryOperation(mul, [a, b])
        assert IndirectBranch(a).expression == a
        assert IndirectBranch(Constant(42)).expression == Constant(42)

    def test_definitions(self):
        assert IndirectBranch(BinaryOperation(mul, [a, b])).definitions == []
        assert IndirectBranch(a).definitions == []
        assert IndirectBranch(Constant(42)).definitions == []

    def test_requirements(self):
        assert set(IndirectBranch(BinaryOperation(mul, [a, b])).requirements) == {a, b}
        assert set(IndirectBranch(BinaryOperation(mul, [a, Constant(2)])).requirements) == {a}
        assert set(IndirectBranch(a).requirements) == {a}
        assert IndirectBranch(Constant(42)).requirements == []

    def test_substitute_and_string(self):
        jump = IndirectBranch(BinaryOperation(mul, [a, b]))
        jump.substitute(a, d)
        assert str(jump) == "jmp d#3 * b#1"
        jump = IndirectBranch(a)
        jump.substitute(a, c)
        assert str(jump) == "jmp c#2"
        jump.substitute(c, Constant(0x42))
        assert str(jump) == "jmp 0x42"
        jump = IndirectBranch(BinaryOperation(neq, [a, Constant(0)]))
        jump.substitute(a, BinaryOperation(lte, [c, b]))
        assert str(jump) == "jmp (c#2 <= b#1) != 0x0"

    def test_iter(self):
        """Check if iterating a Branch instruction only yields the condition value."""
        assert list(IndirectBranch(a)) == [a]
        assert list(IndirectBranch(BinaryOperation(mul, [a, b]))) == [BinaryOperation(mul, [a, b])]
        assert list(Branch(Condition(lte, [a, b]))) == [Condition(lte, [a, b])]

    def test_copy(self):
        """Test if the nested expressions of a branch instruction are copied correctly."""
        original = Branch(Condition(lte, [a, b]))
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.condition) != id(copy.condition) and original.condition == copy.condition


class TestReturn:
    def test_requirements(self):
        assert Return([Constant(0)]).requirements == []
        assert Return([a]).requirements == [a]
        assert set(Return([a, b]).requirements) == {a, b}
        assert set(Return([a, BinaryOperation(mul, [c, b])]).requirements) == {a, b, c}

    def test_substitute_and_string(self):
        i = Return([Constant(0)])
        i.substitute(Constant(0), Constant(1))
        assert str(i) == "return 0x1"
        i = Return([a])
        i.substitute(a, b)
        assert str(i) == "return b#1"
        i.substitute(b, BinaryOperation(mul, [a, c]))
        assert str(i) == "return a#0 * c#2"
        i = Return([a, b])
        i.substitute(b, c)
        assert str(i) == "return a#0,c#2"

    def test_definitions(self):
        assert Return([Constant(0)]).definitions == []
        assert Return([a]).definitions == []
        assert Return([a, BinaryOperation(mul, [c, b])]).definitions == []

    def test_complexity(self):
        assert Return([Constant(0)]).complexity == 1
        assert Return([a]).complexity == 1
        assert Return([a, b]).complexity == 2
        assert Return([a, BinaryOperation(mul, [c, b])]).complexity == 3

    def test_iter(self):
        """Test if iterating a Return statements yields all returned expressions."""
        assert list(Return([Constant(0)])) == [Constant(0)]
        assert list(Return([a, BinaryOperation(mul, [c, b])])) == [a, BinaryOperation(mul, [c, b])]

    def test_copy(self):
        """Check whether the Return statement is copying with all nested expression values."""
        original = Return([a, Constant(1), BinaryOperation(mul, [a, b])])
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.values[0]) != id(copy.values[0]) and original.values[0] == copy.values[0]
        assert id(original.values[1]) != id(copy.values[1]) and original.values[1] == copy.values[1]
        assert id(original.values[2]) != id(copy.values[2]) and original.values[2] == copy.values[2]


class TestBreak:
    def test_definitions(self):
        assert Break().definitions == []

    def test_requirements(self):
        assert Break().requirements == []

    def test_complexity(self):
        assert Break().complexity == 0

    def test_str(self):
        assert str(Break()) == "break"

    def test_copy(self):
        b1 = Break()
        b2 = b1.copy()
        assert id(b1) != id(b2)
        assert b1 == b2

    def test_iter(self):
        assert list(Break()) == []


class TestContinue:
    def test_definitions(self):
        assert Continue().definitions == []

    def test_requirements(self):
        assert Continue().requirements == []

    def test_complexity(self):
        assert Continue().complexity == 0

    def test_str(self):
        assert str(Continue()) == "continue"

    def test_copy(self):
        c1 = Continue()
        c2 = c1.copy()
        assert id(c1) != id(c2)
        assert c1 == c2

    def test_iter(self):
        assert list(Continue()) == []


class MockBasicBlock:
    def __init__(self, name, instructions=None):
        self.name = name
        self.instructions = instructions

    def __repr__(self):
        return f"BasicBlock({self.name})"


v1 = MockBasicBlock(1)
v2 = MockBasicBlock(2)
v3 = MockBasicBlock(3)
v4 = MockBasicBlock(4)
variable_of_block = {v2: b, v3: c}
variable_of_block_redundant = {v2: b, v3: c, v4: d}


class TestPhi:
    def test_requirements(self):
        assert set(Phi(a, [b, b]).requirements) == {b}
        assert set(Phi(a, [Constant(1), b]).requirements) == {b}
        assert set(Phi(a, [b, c, d]).requirements) == {b, c, d}

    def test_complexity(self):
        assert Phi(a, [b, b]).complexity == 3
        assert Phi(a, [Constant(1), b]).complexity == 3
        assert Phi(a, [b, c, d]).complexity == 4

    def test_definitions(self):
        assert Phi(a, [b, b]).definitions == [a]

    def test_substitute_and_string(self):
        i = Phi(a, [b, c])
        i.substitute(c, d)
        assert str(i) == "a#0 = ϕ(b#1,d#3)"
        i.substitute(b, Constant(0))
        assert str(i) == "a#0 = ϕ(0x0,d#3)"

    def test_update_phi(self):
        i = Phi(a, [b, c])
        assert i.origin_block == dict()
        i.update_phi_function(variable_of_block)
        assert i.origin_block == {v2: b, v3: c}
        i2 = Phi(a, [b, c])
        i2.update_phi_function(variable_of_block_redundant)
        assert i2.origin_block == {v2: b, v3: c}

    def test_remove_from_origin_block(self):
        i = Phi(a, [b, c])
        assert i.origin_block == dict()
        i.update_phi_function(variable_of_block)
        assert i.origin_block == {v2: b, v3: c}
        i.remove_from_origin_block(v2)
        assert i.origin_block == {v3: c}

    def test_iter(self):
        """Check if all terms of a phi function are yielded during iteration."""
        assert list(Phi(a, [b, c, Constant(1)])) == [a, ListOperation([b, c, Constant(1)])]

    def test_copy(self):
        """Test if all nested expressions are copied when the Phi instruction is copied."""
        original = Phi(a, [b, c, Constant(1)])
        copy = original.copy()
        assert id(original) != id(copy) and original == copy
        assert id(original.destination) != id(copy.destination) and original.destination == copy.destination
        assert id(original.value[0]) != id(copy.value[0])
        assert id(original.value[0]) != id(copy.value[0]) and original.value[0] == copy.value[0]
        assert id(original.value[1]) != id(copy.value[1]) and original.value[1] == copy.value[1]
        assert id(original.value[2]) != id(copy.value[2]) and original.value[2] == copy.value[2]


mem6 = Variable("mem", "", 6)
mem3 = Variable("mem", "", 3)
mem4 = Variable("mem", "", 4)
mem5 = Variable("mem", "", 5)


class TestMemPhi:
    def test_string(self):
        i = MemPhi(mem6, [mem3, mem4, mem5])
        assert str(i) == "mem#6 = ϕ(mem#3,mem#4,mem#5)"

    def test_substitute_does_nothing(self):
        i = MemPhi(mem6, [mem3, mem4, mem5])
        i.substitute(mem3, a)
        assert str(i) == "mem#6 = ϕ(mem#3,mem#4,mem#5)"

    def test_create_phi_for_variables(self):
        # intersection of mem phi variables and variables set is not empty
        i = MemPhi(mem6, [mem3, mem4, mem5])
        phis = i.create_phi_functions_for_variables({a, b, c})
        ssa_labels = (6, 3, 4, 5)
        a6, a3, a4, a5 = (Variable(a.name, a.type, i, is_aliased=True) for i in ssa_labels)
        b6, b3, b4, b5 = (Variable(b.name, b.type, i, is_aliased=True) for i in ssa_labels)
        c6, c3, c4, c5 = (Variable(c.name, c.type, i, is_aliased=True) for i in ssa_labels)
        g6, g3, g4, g5 = (GlobalVariable("g", Integer.char(), i, initial_value=42) for i in ssa_labels)
        g6_loc, g3_loc, g4_loc, g5_loc = (Variable("g", Integer.char(), is_aliased=True) for i in ssa_labels)
        phi_a = Phi(a6, [a3, a4, a5])
        phi_b = Phi(b6, [b3, b4, b5])
        phi_c = Phi(c6, [c3, c4, c5])
        g = GlobalVariable("g", Integer.char(), initial_value=42)
        phi_g = Phi(g6, [g3, g4, g5])
        phi_g_loc = Phi(g6_loc, [g3_loc, g4_loc, g5_loc])
        assert set(phis) == {phi_a, phi_b, phi_c}
        # both mem phi variables and variables set are empty
        i2 = MemPhi(mem6, [mem3, mem4, mem5])
        phis = i2.create_phi_functions_for_variables(set())
        assert phis == []
        # mem phi variables are empty, variables set is not
        i3 = MemPhi(mem6, [mem3, mem4, mem5])
        phis = i3.create_phi_functions_for_variables({a, b})
        assert set(phis) == {phi_a, phi_b}
        # mem phi variables are not empty, but variables set is empty
        i4 = MemPhi(mem6, [mem3, mem4, mem5])
        phis = i4.create_phi_functions_for_variables(set())
        assert phis == []
        # mem phi contains more variables
        i4 = MemPhi(mem6, [mem3, mem4, mem5])
        phis = i4.create_phi_functions_for_variables({b, c})
        assert set(phis) == {phi_b, phi_c}
        # phis created for global variables contain also global, not local variables
        i5 = MemPhi(mem6, [mem3, mem4, mem5])
        phis = i5.create_phi_functions_for_variables({g})
        assert set(phis) == {phi_g}
        assert set(phis) != {phi_g_loc}
