from binascii import hexlify, unhexlify
from pickle import dumps, loads

from dewolf.structures.pseudo.expressions import DataflowObject

from .interface import Serializer


class PseudoSerializer(Serializer):
    """Serializes and Deserializes Pseudo expressions using pickle."""

    def serialize(self, expression: DataflowObject) -> str:
        """Serialize the given z3 expression into a SMT2 string representation."""
        return hexlify(dumps(expression)).decode("ascii")

    def deserialize(self, data: str) -> DataflowObject:
        """Deserialize the given string representing a z3 expression."""
        return loads(unhexlify(data))
