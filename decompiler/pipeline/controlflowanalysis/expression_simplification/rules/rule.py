from abc import ABC, abstractmethod

from decompiler.structures.pseudo import Expression, Operation


class SimplificationRule(ABC):
    """
    This class defines the interface for simplification rules that can be applied to expressions.
    """

    @abstractmethod
    def apply(self, operation: Operation) -> list[tuple[Expression, Expression]]:
        """
        Apply the simplification rule to the given operation.

        :param operation: The operation to which the simplification rule should be applied.
        :return: A list of tuples, each containing a pair of expressions representing the original
            and simplified versions resulting from applying the simplification rule to the given operation.
        :raises:
            MalformedData: Thrown inf malformed data, like a dereference operation with two operands, is encountered.
        """
        pass


class MalformedData(Exception):
    """Used to indicate that malformed data was encountered"""
    pass
