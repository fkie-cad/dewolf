"""Main module containing all ghidra handlers."""

from .opcodes import OpcodeHandler
from .types import TypeHandler
from .varnodes import VarnodeHandler

# List of all available ghidra handlers (registration order does not matter).
HANDLERS = [
    TypeHandler,
    VarnodeHandler,
    OpcodeHandler,
]
