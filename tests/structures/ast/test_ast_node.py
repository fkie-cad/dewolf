import pytest
from decompiler.structures.ast.ast_nodes import (
    CaseNode,
    CodeNode,
    ConditionNode,
    DoWhileLoopNode,
    ForLoopNode,
    SeqNode,
    SwitchNode,
    WhileLoopNode,
)
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Assignment, BinaryOperation, Break, Condition, Constant, ListOperation, OperationType, Variable


class TestEquality:
    """Test the equality operation for nodes."""

    def test_seq_node(self):
        context = LogicCondition.generate_new_context()
        true_condition = LogicCondition.initialize_true(context)
        assert SeqNode(true_condition.copy()) == SeqNode(true_condition.copy())
        assert SeqNode(LogicCondition.initialize_false(context)) == SeqNode(LogicCondition.initialize_false(context))
        assert SeqNode(LogicCondition.initialize_symbol("a", context)) == SeqNode(LogicCondition.initialize_symbol("a", context))
        assert SeqNode(LogicCondition.initialize_symbol("b", context)) != SeqNode(LogicCondition.initialize_symbol("a", context))

    def test_code_node(self):
        context = LogicCondition.generate_new_context()
        true_condition = LogicCondition.initialize_true(context)
        assert CodeNode([], true_condition.copy()) != SeqNode(true_condition.copy())
        assert CodeNode([], true_condition.copy()) == CodeNode([], true_condition.copy())
        assert CodeNode([Break()], true_condition.copy()) == CodeNode([Break()], true_condition.copy())
        assert CodeNode([Break()], true_condition.copy()) != CodeNode(
            [Break()], reaching_condition=LogicCondition.initialize_false(context)
        )

    def test_condition_node(self):
        context = LogicCondition.generate_new_context()
        true_condition = LogicCondition.initialize_true(context)
        assert ConditionNode(LogicCondition.initialize_true(context), true_condition.copy()) == ConditionNode(
            LogicCondition.initialize_true(context), true_condition.copy()
        )
        assert ConditionNode(LogicCondition.initialize_true(context), true_condition.copy()) != ConditionNode(
            LogicCondition.initialize_false(context), true_condition.copy()
        )
        assert ConditionNode(LogicCondition.initialize_true(context), true_condition.copy()) != ConditionNode(
            LogicCondition.initialize_true(context), reaching_condition=LogicCondition.initialize_false(context)
        )
        assert ConditionNode(
            LogicCondition.initialize_true(context), reaching_condition=LogicCondition.initialize_symbol("a", context)
        ) == ConditionNode(LogicCondition.initialize_true(context), reaching_condition=LogicCondition.initialize_symbol("a", context))
        assert ConditionNode(
            LogicCondition.initialize_symbol("a", context), reaching_condition=LogicCondition.initialize_symbol("b", context)
        ) != ConditionNode(
            LogicCondition.initialize_symbol("b", context), reaching_condition=LogicCondition.initialize_symbol("a", context)
        )
        assert ConditionNode(LogicCondition.initialize_symbol("a", context), true_condition.copy()) == ConditionNode(
            LogicCondition.initialize_symbol("a", context), true_condition.copy()
        )

    def test_loop_node(self):
        context = LogicCondition.generate_new_context()
        true_condition = LogicCondition.initialize_true(context)
        assert WhileLoopNode(LogicCondition.initialize_symbol("a", context), true_condition.copy()) != DoWhileLoopNode(
            LogicCondition.initialize_symbol("a", context), true_condition.copy()
        )
        assert WhileLoopNode(LogicCondition.initialize_symbol("a", context), true_condition.copy()) == WhileLoopNode(
            LogicCondition.initialize_symbol("a", context), true_condition.copy()
        )
        assert WhileLoopNode(
            LogicCondition.initialize_symbol("a", context), reaching_condition=LogicCondition.initialize_symbol("b", context)
        ) == WhileLoopNode(
            LogicCondition.initialize_symbol("a", context), reaching_condition=LogicCondition.initialize_symbol("b", context)
        )
        assert WhileLoopNode(
            LogicCondition.initialize_symbol("a", context), reaching_condition=LogicCondition.initialize_symbol("b", context)
        ) != WhileLoopNode(
            LogicCondition.initialize_symbol("a", context), reaching_condition=LogicCondition.initialize_symbol("a", context)
        )
        assert WhileLoopNode(LogicCondition.initialize_true(context), true_condition.copy()) != WhileLoopNode(
            LogicCondition.initialize_symbol("a", context), true_condition.copy()
        )

    def test_for_loop_node(self):
        context = LogicCondition.generate_new_context()
        true_condition = LogicCondition.initialize_true(context)
        assert ForLoopNode(
            Assignment(Variable("x"), Constant(2)),
            LogicCondition.initialize_true(context),
            Assignment(Variable("x"), BinaryOperation(OperationType.plus, [Variable("x"), Constant(1)])),
            true_condition.copy(),
        ) == ForLoopNode(
            Assignment(Variable("x"), Constant(2)),
            LogicCondition.initialize_true(context),
            Assignment(Variable("x"), BinaryOperation(OperationType.plus, [Variable("x"), Constant(1)])),
            true_condition.copy(),
        )
        assert ForLoopNode(
            Assignment(Variable("x"), Constant(2)),
            LogicCondition.initialize_true(context),
            Assignment(Variable("x"), BinaryOperation(OperationType.plus, [Variable("x"), Constant(1)])),
            true_condition.copy(),
        ) != ForLoopNode(
            Assignment(Variable("x"), Constant(2)),
            LogicCondition.initialize_false(context),
            Assignment(Variable("x"), BinaryOperation(OperationType.plus, [Variable("x"), Constant(1)])),
            true_condition.copy(),
        )
        assert ForLoopNode(
            Assignment(Variable("x"), Constant(2)),
            LogicCondition.initialize_true(context),
            Assignment(Variable("x"), BinaryOperation(OperationType.plus, [Variable("x"), Constant(1)])),
            true_condition.copy(),
        ) != ForLoopNode(
            Assignment(Variable("x"), Constant(2)),
            LogicCondition.initialize_true(context),
            Assignment(Variable("x"), BinaryOperation(OperationType.minus, [Variable("x"), Constant(1)])),
            true_condition.copy(),
        )
        assert ForLoopNode(
            Assignment(Variable("x"), Constant(2)),
            LogicCondition.initialize_true(context),
            Assignment(Variable("x"), BinaryOperation(OperationType.plus, [Variable("x"), Constant(1)])),
            true_condition.copy(),
        ) != ForLoopNode(
            Assignment(Variable("x"), Constant(3)),
            LogicCondition.initialize_true(context),
            Assignment(Variable("x"), BinaryOperation(OperationType.plus, [Variable("x"), Constant(1)])),
            true_condition.copy(),
        )

    def test_switch_node(self):
        context = LogicCondition.generate_new_context()
        true_condition = LogicCondition.initialize_true(context)
        assert SwitchNode(Variable("x"), true_condition.copy()) == SwitchNode(Variable("x"), true_condition.copy())
        assert SwitchNode(Variable("y"), true_condition.copy()) != SwitchNode(Variable("x"), true_condition.copy())
        assert SwitchNode(Variable("x"), LogicCondition.initialize_symbol("a", context)) == SwitchNode(
            Variable("x"), LogicCondition.initialize_symbol("a", context)
        )
        assert SwitchNode(Variable("x"), LogicCondition.initialize_symbol("a", context)) != SwitchNode(
            Variable("x"), LogicCondition.initialize_symbol("b", context)
        )

    def test_case_node(self):
        context = LogicCondition.generate_new_context()
        true_condition = LogicCondition.initialize_true(context)
        assert CaseNode(Variable("x"), Constant(1), true_condition.copy()) == CaseNode(Variable("x"), Constant(1), true_condition.copy())
        assert CaseNode(Variable("x"), Constant(1), LogicCondition.initialize_symbol("a", context)) == CaseNode(
            Variable("x"), Constant(1), LogicCondition.initialize_symbol("a", context)
        )
        assert CaseNode(Variable("x"), Constant(1), LogicCondition.initialize_symbol("a", context)) != CaseNode(
            Variable("x"), Constant(1), LogicCondition.initialize_symbol("b", context)
        )
        assert CaseNode(Variable("x"), Constant(1), true_condition.copy()) != CaseNode(Variable("x"), Constant(2), true_condition.copy())
        assert CaseNode(Variable("x"), Constant(1), true_condition.copy()) != CaseNode(Variable("y"), Constant(1), true_condition.copy())


class TestCodeNode:
    """Test CodeNode functionality."""

    instr_a = Assignment(Variable("a"), Constant(1))
    instr_b = Assignment(Variable("b"), Constant(2))
    instr_c = Assignment(Variable("c"), Constant(3))

    def test_insert_single_instruction(self):
        """Insertion of single instruction"""
        context = LogicCondition.generate_new_context()
        code_node = CodeNode([self.instr_a.copy(), self.instr_c.copy()], LogicCondition.initialize_true(context))
        code_node.insert_instruction_before(self.instr_b.copy(), code_node.instructions[-1])
        assert code_node.instructions == [self.instr_a.copy(), self.instr_b.copy(), self.instr_c.copy()]

    def test_insert_single_instruction_ambiguous(self):
        """Check if instruction is identified correctly"""
        context = LogicCondition.generate_new_context()
        code_node = CodeNode([self.instr_a.copy(), self.instr_c.copy(), self.instr_c.copy()], LogicCondition.initialize_true(context))
        code_node.insert_instruction_before(self.instr_b.copy(), code_node.instructions[2])
        assert code_node.instructions == [self.instr_a.copy(), self.instr_c.copy(), self.instr_b.copy(), self.instr_c.copy()]

    def test_insert_single_instruction_not_existent(self):
        """Insertion before non existent instruction should raise ValueError"""
        context = LogicCondition.generate_new_context()
        code_node = CodeNode([self.instr_a.copy()], LogicCondition.initialize_true(context))
        with pytest.raises(ValueError):
            code_node.insert_instruction_before(self.instr_b.copy(), self.instr_c.copy())

    def test_insert_multiple_instructions(self):
        """Insertion of multiple instructions"""
        context = LogicCondition.generate_new_context()
        code_node = CodeNode([self.instr_c.copy()], LogicCondition.initialize_true(context))
        code_node.insert_instruction_list_before([self.instr_a.copy(), self.instr_b.copy()], code_node.instructions[0])
        assert code_node.instructions == [self.instr_a.copy(), self.instr_b.copy(), self.instr_c.copy()]

    def test_insert_multiple_instructions_ambiguous(self):
        """Check if instruction is identified correctly"""
        context = LogicCondition.generate_new_context()
        code_node = CodeNode([self.instr_a.copy(), self.instr_c.copy(), self.instr_c.copy()], LogicCondition.initialize_true(context))
        code_node.insert_instruction_list_before([self.instr_b.copy()], code_node.instructions[2])
        assert code_node.instructions == [self.instr_a.copy(), self.instr_c.copy(), self.instr_b.copy(), self.instr_c.copy()]

    def test_insert_multiple_instructions_not_existent(self):
        """Insertion before non existend instruction should raise ValueError"""
        context = LogicCondition.generate_new_context()
        code_node = CodeNode([self.instr_a.copy()], LogicCondition.initialize_true(context))
        with pytest.raises(ValueError):
            code_node.insert_instruction_list_before([self.instr_b.copy()], self.instr_c.copy())


class TestRequirementsAndDefinitions:
    """Test that required/defined variables are yielded correctly."""

    def test_seq_node(self):
        context = LogicCondition.generate_new_context()
        node = SeqNode(LogicCondition.initialize_true(context))
        assert list(node.get_required_variables()) == []
        assert list(node.get_defined_variables()) == []

    def test_code_node(self):
        context = LogicCondition.generate_new_context()
        node = CodeNode([Assignment(Variable("x"), Variable("y"))], LogicCondition.initialize_true(context))
        assert list(node.get_required_variables()) == [Variable("y")]
        assert list(node.get_defined_variables()) == [Variable("x")]
        # test operands are yielded correctly from ListOperation
        node_2 = CodeNode(
            [Assignment(ListOperation([Variable("x"), Variable("y")]), Variable("y"))], LogicCondition.initialize_true(context)
        )
        assert list(node_2.get_defined_variables()) == [Variable("x"), Variable("y")]

    def test_condition_node(self):
        context = LogicCondition.generate_new_context()
        condition = LogicCondition.initialize_symbol("a", context)
        condition_2 = LogicCondition.initialize_symbol("b", context)
        condition_map = {condition: Condition(OperationType.less_or_equal, [Variable("x"), Variable("y")])}
        node = ConditionNode(condition, LogicCondition.initialize_true(context))
        assert list(node.get_defined_variables(condition_map)) == []
        assert list(node.get_required_variables(condition_map)) == [Variable("x"), Variable("y")]
        # test requirements when condition is not in condition map
        # todo should this raise an exception? Warning? Error? Silently skip?
        node_2 = ConditionNode(condition_2, LogicCondition.initialize_true(context))
        assert list(node_2.get_required_variables(condition_map)) == []

    def test_loop_node(self):
        context = LogicCondition.generate_new_context()
        endless_loop = WhileLoopNode(LogicCondition.initialize_true(context), LogicCondition.initialize_true(context))
        assert list(endless_loop.get_required_variables()) == []
        assert list(endless_loop.get_defined_variables()) == []

        condition = LogicCondition.initialize_symbol("a", context)
        condition_map = {condition: Condition(OperationType.less_or_equal, [Variable("x"), Variable("y")])}
        while_loop = WhileLoopNode(condition, LogicCondition.initialize_true(context))
        assert list(while_loop.get_defined_variables()) == []
        assert list(while_loop.get_defined_variables(condition_map)) == []
        assert list(while_loop.get_required_variables()) == []
        assert list(while_loop.get_required_variables(condition_map)) == [Variable("x"), Variable("y")]

        for_loop = ForLoopNode(
            declaration=Assignment(Variable("x"), Constant(0)),
            condition=condition,
            modification=Assignment(Variable("x"), BinaryOperation(OperationType.plus, [Variable("x"), Constant(1)])),
            reaching_condition=LogicCondition.initialize_true(context),
        )
        assert list(for_loop.get_required_variables()) == [Variable("x")]
        assert list(for_loop.get_required_variables(condition_map)) == [Variable("x"), Variable("x"), Variable("y")]
        assert list(for_loop.get_defined_variables()) == [Variable("x"), Variable("x")]
        assert list(for_loop.get_defined_variables(condition_map)) == [Variable("x"), Variable("x")]

    def test_switch_node(self):
        context = LogicCondition.generate_new_context()
        node = SwitchNode(Variable("x"), LogicCondition.initialize_true(context), context)
        assert list(node.get_required_variables()) == [Variable("x")]
        assert list(node.get_defined_variables()) == []

    def test_case_node(self):
        context = LogicCondition.generate_new_context()
        node = CaseNode(Variable("x"), Constant(0), LogicCondition.initialize_true(context))
        assert list(node.get_required_variables()) == [Variable("x")]
        assert list(node.get_defined_variables()) == []
