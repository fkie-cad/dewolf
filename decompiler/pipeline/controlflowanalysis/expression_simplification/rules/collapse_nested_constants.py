from functools import reduce
from typing import Iterator

from decompiler.pipeline.controlflowanalysis.expression_simplification.constant_folding import FOLDABLE_OPERATIONS, constant_fold
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.structures.pseudo import Constant, Expression, Operation, OperationType, Type
from decompiler.structures.pseudo.operations import COMMUTATIVE_OPERATIONS

_COLLAPSIBLE_OPERATIONS = COMMUTATIVE_OPERATIONS & FOLDABLE_OPERATIONS


class CollapseNestedConstants(SimplificationRule):
    """
    This rule walks the dafaflow tree and collects and folds constants in commutative operations.
    The first constant of the tree is replaced with the folded result and all remaining constants are replaced with the identity.
    This stage exploits associativity and is the only stage doing so. Therefore, it cannot be replaced by a combination of `TermOrder` and `CollapseConstants`.
    """

    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        if operation.operation not in _COLLAPSIBLE_OPERATIONS:
            return []
        if not isinstance(operation, Operation):
            raise TypeError(f"Expected Operation, got {type(operation)}")

        constants = list(_collect_constants(operation))
        if len(constants) <= 1:
            return []

        first, *rest = constants

        folded_constant = reduce(lambda c0, c1: constant_fold(operation.operation, [c0, c1]), rest, first)

        identity_constant = _identity_constant(operation.operation, operation.type)
        return [(first, folded_constant), *((constant, identity_constant) for constant in rest)]


def _collect_constants(operation: Operation) -> Iterator[Constant]:
    """
    Collects constants of potentially multiple nested commutative operations of the same type.

    This function traverses the subtree rooted at the provided operation and collects
    all constants that belong to operations with the same operation type as the root operation.
    The subtree includes only operations that have matching operation types.
    """

    operation_type = operation.operation
    operand_type = operation.type

    context_stack: list[Operation] = [operation]
    while context_stack:
        current_operation = context_stack.pop()

        for i, operand in enumerate(current_operation.operands):
            if operand.type != operand_type:
                continue

            if isinstance(operand, Operation):
                if operand.operation == operation_type:
                    context_stack.append(operand)
                    continue
            elif isinstance(operand, Constant) and _identity_constant(operation_type, operand_type).value != operand.value:
                yield operand


def _identity_constant(operation: OperationType, var_type: Type) -> Constant:
    """
    Return a const containing the identity element for the specified operation and variable type.
    """
    match operation:
        case OperationType.plus | OperationType.bitwise_xor | OperationType.bitwise_or:
            return Constant(0, var_type)
        case OperationType.multiply | OperationType.multiply_us:
            return Constant(1, var_type)
        case OperationType.bitwise_and:
            return constant_fold(OperationType.bitwise_not, [Constant(0, var_type)])
        case _:
            raise NotImplementedError()
