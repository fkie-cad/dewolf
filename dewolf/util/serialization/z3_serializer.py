from typing import Union

from z3 import BoolRef, ExprRef, Solver

from .interface import Serializer

# class Z3StringSerializer(Serializer):
#     """Serializes and Deserializes AbstractSyntaxTrees to and from a dict representation."""
#
#     def serialize(self, expression: Union[ExprRef, BoolRef]) -> str:
#         """Serialize the given z3 expression into a SMT2 string representation."""
#         solver = Solver()
#         solver.add(expression)
#         return str(solver.sexpr())
#
#     def deserialize(self, data: str) -> Union[ExprRef, BoolRef]:
#         """Deserialize the given string representing a z3 expression."""
#         solver = Solver()
#         solver.from_string(data)
#         return solver.assertions()[0]
