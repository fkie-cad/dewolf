"""Main module containing all binaryninja handlers."""
from .assignments import AssignmentHandler
from .binary import BinaryOperationHandler
from .calls import CallHandler
from .conditions import ConditionHandler
from .constants import ConstantHandler
from .controlflow import FlowHandler
from .globals import GlobalHandler
from .phi import PhiHandler
from .symbols import SymbolHandler
from .types import TypeHandler
from .unary import UnaryOperationHandler
from .variables import VariableHandler

# List of all available binaryninja handlers
HANDLERS = [
    VariableHandler,
    ConstantHandler,
    TypeHandler,
    BinaryOperationHandler,
    UnaryOperationHandler,
    ConditionHandler,
    FlowHandler,
    AssignmentHandler,
    PhiHandler,
    SymbolHandler,
    CallHandler,
    GlobalHandler,
]
