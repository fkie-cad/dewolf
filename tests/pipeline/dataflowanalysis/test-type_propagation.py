from decompiler.pipeline.dataflowanalysis.type_propagation import TypeGraph, TypePropagation
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Float, Integer, Pointer, UnknownType


class TestVerticalTypePropagation:
    """Test the recursive type propagation implemented into the typing system."""

    def test_condition(self):
        """The type returned by a condition is always boolean."""
        assert Condition(OperationType.equal, [Variable("a", UnknownType()), Variable("b", UnknownType())]).type.is_boolean

    def test_binary_operation(self):
        """In some cases, a binary operation should be able to deduce its output type. It should be the larger type."""
        assert (
            BinaryOperation(OperationType.plus, [Variable("a", Integer.uint32_t()), Constant(0xFFA, Integer.uint64_t())]).type
            == Integer.uint64_t()
        )

    def test_type_ambiguity(self):
        """In some cases, we might not be able to deduce the type."""
        assert BinaryOperation(OperationType.plus, [Variable("a", Integer.uint64_t()), Variable("b", Pointer(Float.float()))]).type in [
            Integer.uint64_t(),
            Float.float(),
        ]

    def test_nested_operations(self):
        """Check if types are propagates properly through nested operations."""
        assert BinaryOperation(OperationType.multiply, [])


class TestHorizontalTypePropagation:
    """Test the propagation of types through assignments by the pipeline stage."""

    def test_backwards(self):
        """Test if the type is inherited from an assignment."""
        cfg = ControlFlowGraph()
        cfg.add_node(
            BasicBlock(0, instructions=[Assignment(x := Variable("x", UnknownType(), ssa_label=0), Constant(0xAA, Integer.char()))])
        )
        TypePropagation().propagate(TypeGraph.from_cfg(cfg))
        assert x.type == Integer.char()

    def test_forward(self):
        """Check if the type of a value assigned depends on the storage type."""
        cfg = ControlFlowGraph()
        cfg.add_node(
            BasicBlock(0, instructions=[Assignment(Variable("x", Integer.char(), ssa_label=0), c := Constant(0xAA, UnknownType()))])
        )
        TypePropagation().propagate(TypeGraph.from_cfg(cfg))
        assert c.type == Integer.char()

    def test_ignore_primitives(self):
        """Test that primitives types are ignored in favor of others, if available."""
        cfg = ControlFlowGraph()
        cfg.add_node(
            BasicBlock(0, instructions=[Assignment(x := Variable("x", Float.float(), ssa_label=0), Constant(0xAA, Integer.char()))])
        )
        TypePropagation().propagate(TypeGraph.from_cfg(cfg))
        assert x.type == Float.float()

    def test_fallback_to_primitive(self):
        """Check that if we only got primitive types with the same amount of facts, we use alphabetical ordering."""
        cfg = ControlFlowGraph()
        cfg.add_node(
            BasicBlock(0, instructions=[Assignment(x := Variable("x", Integer.uint8_t(), ssa_label=0), Constant(0xAA, Integer.int32_t()))])
        )
        TypePropagation().propagate(TypeGraph.from_cfg(cfg))
        assert x.type == Integer.uint8_t()

    def test_propagation(self):
        """Test whether the types are spread globally."""
        cfg = ControlFlowGraph()
        cfg.add_node(
            BasicBlock(
                0,
                instructions=[
                    Assignment(x0 := Variable("x", UnknownType(), ssa_label=0), Constant(0xAA, Integer.char())),
                    Return([x := Variable("x", UnknownType(), ssa_label=0)]),
                ],
            )
        )
        TypePropagation().propagate(TypeGraph.from_cfg(cfg))
        assert x0.type == Integer.char()
        assert x.type == Integer.char()

    def test_constants_identical_value_different_types(self):
        """Test constants with identical values but different types do not cross-propagate"""
        cfg = ControlFlowGraph()
        cfg.add_node(
            BasicBlock(
                0,
                instructions=[
                    Assignment(x := Variable("x", UnknownType(), ssa_label=0), Constant(0x0, Integer.int64_t())),
                    Assignment(y := Variable("y", UnknownType(), ssa_label=0), Constant(0x0, Integer.int32_t())),
                ],
            )
        )
        TypePropagation().propagate(TypeGraph.from_cfg(cfg))
        assert x.type == Integer.int64_t()
        assert y.type == Integer.int32_t()

    def test_casted_constants_identical_value_different_types(self):
        """Test casted constants do not cross-propagate"""
        cfg = ControlFlowGraph()
        cfg.add_node(
            BasicBlock(
                0,
                instructions=[
                    Assignment(
                        x := Variable("x", Integer.int32_t(), ssa_label=0),
                        UnaryOperation(OperationType.cast, [Constant(0x0, Integer.int8_t())], vartype=Integer.int32_t()),
                    ),
                    Assignment(
                        y := Variable("y", Integer.int64_t(), ssa_label=0),
                        UnaryOperation(OperationType.cast, [Constant(0x0, Integer.int64_t())], vartype=Integer.int32_t()),
                    ),
                ],
            )
        )
        TypePropagation().propagate(TypeGraph.from_cfg(cfg))
        assert x.type == Integer.int32_t()
        assert y.type == Integer.int64_t()
