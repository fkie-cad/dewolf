"""Semantics of Ghidra-frontend constant lifting: signedness (no noisy ``0U``) and bool 0/1.

The Ghidra frontend used to type every integer constant *unsigned*, so the C backend appended a ``U``
suffix to preserve the type -- rendering ordinary literals as ``0U`` / ``1U`` / ``8U`` unlike Ghidra's
own decompiler (and the Binary Ninja frontend, which types constants signed). And a ``0`` / ``1``
literal sitting next to a boolean value stayed an integer, rendering ``0`` / ``1`` instead of
``false`` / ``true``. These tests pin both behaviours against the real lifter methods + the real C
backend, without needing a live Ghidra.
"""

from decompiler.backend.cexpressiongenerator import CExpressionGenerator
from decompiler.frontend.ghidra.handlers.varnodes import VarnodeHandler
from decompiler.frontend.ghidra.lifter import GhidraLifter
from decompiler.structures.pseudo.expressions import Constant
from decompiler.structures.pseudo.typing import Integer, Pointer


class _StubLifter:
    """Just enough lifter surface for VarnodeHandler._lift_constant (no Ghidra, no strings)."""

    def _address_size_bits(self):
        return 64

    def _string_at(self, value):
        return None

    def _is_pointer_constant(self, value):
        return False


class _PointerStubLifter(_StubLifter):
    """A lifter that flags one address as a data-pointer target, so _lift_constant emits ``&global``."""

    program = None

    def __init__(self, pointer_value):
        self._pointer_value = pointer_value

    def _is_pointer_constant(self, value):
        return value == self._pointer_value

    def _global_symbol_name(self, addr):
        return None  # no real symbol -> data_<addr>

    def _global_type(self, program, addr, size):
        return Integer(32, signed=False)

    def _global_initial_value(self, addr, vartype):
        return Constant(0, vartype)


class _FakeConstVarnode:
    def __init__(self, value, size):
        self._value = value
        self._size = size

    def isConstant(self):
        return True

    def getOffset(self):
        return self._value

    def getSize(self):
        return self._size


def _lift_const(value, size):
    handler = object.__new__(VarnodeHandler)
    handler._lifter = _StubLifter()
    return handler._lift_constant(_FakeConstVarnode(value, size))


def _render(expr):
    return CExpressionGenerator().visit(expr)


# -- #1a: signedness / no noisy U ------------------------------------------------------------------


def test_small_values_are_signed_and_drop_the_U_suffix():
    for value in (0, 1, 8, 104, 0x7FFFFFFF):
        c = _lift_const(value, 4)
        assert c.type.is_signed, f"{value} should lift signed"
        assert "U" not in _render(c), f"{value} should render without a U suffix, got {_render(c)!r}"


def test_high_bit_values_stay_unsigned():
    # a value whose top bit is set would become a confusing negative if signed, so it stays unsigned
    for value in (0x80000000, 0xFFFFFFFF):
        c = _lift_const(value, 4)
        assert not c.type.is_signed, f"{hex(value)} should stay unsigned"


def test_byte_constant_signedness_follows_its_own_width():
    assert _lift_const(1, 1).type.is_signed  # 1 < 0x80 -> safe to sign
    assert not _lift_const(0xFF, 1).type.is_signed  # top bit set at width 1 -> keep unsigned (not -1)


def test_zero_renders_plain_zero():
    assert _render(_lift_const(0, 4)) == "0"
    assert _render(_lift_const(1, 4)) == "1"


# -- #1b: 0/1 next to a bool renders false/true ----------------------------------------------------


def test_as_bool_constant_maps_zero_and_one():
    false_c = GhidraLifter.as_bool_constant(Constant(0, Integer.int32_t()))
    true_c = GhidraLifter.as_bool_constant(Constant(1, Integer(8, signed=False)))
    assert false_c.type.is_boolean and _render(false_c) == "false"
    assert true_c.type.is_boolean and _render(true_c) == "true"


def test_as_bool_constant_leaves_other_values_untouched():
    # only 0/1 integer constants are boolean-coercible
    assert GhidraLifter.as_bool_constant(Constant(5, Integer.int32_t())).type == Integer.int32_t()
    ptr = Constant(0, Pointer(Integer.char()))
    assert GhidraLifter.as_bool_constant(ptr).type == Pointer(Integer.char())  # a null pointer stays a pointer


# -- pointer-valued immediates lift as &global instead of a bare integer ---------------------------


def test_data_pointer_constant_lifts_as_address_of_global():
    # An address-sized immediate Ghidra references as a data pointer (e.g. FUN(&data_413028)) renders
    # as a clickable global reference, not a meaningless 0x413028.
    handler = object.__new__(VarnodeHandler)
    handler._lifter = _PointerStubLifter(0x413028)
    expr = handler._lift_constant(_FakeConstVarnode(0x413028, 8))
    assert _render(expr) == "&data_413028"


def test_non_pointer_constant_stays_a_plain_integer():
    # the same value, when NOT flagged as a data pointer, keeps rendering as an ordinary literal
    handler = object.__new__(VarnodeHandler)
    handler._lifter = _PointerStubLifter(0xDEAD)  # flags a different address
    expr = handler._lift_constant(_FakeConstVarnode(0x413028, 8))
    assert isinstance(expr, Constant) and "data_" not in _render(expr)
