"""Main module containing all binaryninja handlers."""
from .variables import VariableHandler
from .constants import ConstantHandler
from .types import TypeHandler
from .binary import BinaryOperationHandler
from .unary import UnaryOperationHandler
from .conditions import ConditionHandler
from .calls import CallHandler
from .assignments import AssignmentHandler
from .phi import PhiHandler

# List of all available binaryninja handlers
HANDLERS = [
    VariableHandler,
    ConstantHandler,
    TypeHandler,
    BinaryOperationHandler,
    UnaryOperationHandler,
    ConditionHandler,
    AssignmentHandler,
    PhiHandler,
    CallHandler,
]
