"""module for anything pipeline related."""

from .frontend import Frontend
from .lifter import Lifter
from .parser import Parser

# Each frontend is optional; only import it when its backing tool is installed.
# This keeps dewolf importable on systems that have neither/only one of them.
try:
    from .binaryninja.frontend import BinaryninjaFrontend
except ImportError:  # binaryninja not installed
    BinaryninjaFrontend = None

try:
    from .ghidra.frontend import GhidraFrontend
except ImportError:  # pyghidra / ghidra not installed
    GhidraFrontend = None

# Registry of available frontends, keyed by name (None for unavailable ones).
FRONTENDS = {"binaryninja": BinaryninjaFrontend, "ghidra": GhidraFrontend}


def get_frontend(name: str):
    """Resolve a frontend class by name.

    With an explicit name, returns that frontend or raises if it is unknown or unavailable.
    Without a name, falls back to the first available frontend (Binary Ninja, then Ghidra).
    """
    if name:
        frontend = FRONTENDS.get(name)
        if frontend is None:
            available = [k for k, v in FRONTENDS.items() if v is not None]
            if name in FRONTENDS:
                raise ValueError(f"Frontend '{name}' is not installed; available: {available}")
            raise ValueError(f"Unknown frontend '{name}', available: {available}")
        return frontend
    for frontend in (BinaryninjaFrontend, GhidraFrontend):
        if frontend is not None:
            return frontend
    raise ValueError("No decompiler frontend is installed (need binaryninja or pyghidra).")
