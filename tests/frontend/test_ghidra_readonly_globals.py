"""Semantics of the Ghidra frontend's read-only-global classification.

Ghidra models every global (ram-space varnode) as memory that any call *might* modify, emitting a
conservative INDIRECT for it after every call. Routing all of those through dewolf's aliased
memory-version machinery versions each global across every call and makes insert-missing-definitions
fabricate one carry-forward Relation per memory op -- an O(globals x memory-ops) blow-up that made
two versions of the same global interfere and crash out-of-ssa.

The frontend fix classifies a global as *written* only when the function genuinely assigns it (a
direct store to a known address, or a non-global value copied into it); every other global is
*read-only* -- a constant location that is lifted as a plain single-version global and never routed
through the aliased machinery. These tests pin that classification, which is the semantic contract
of the fix. They construct the real ``GhidraLifter.precompute_written_globals`` /
``_is_written_global`` / ``defines_readonly_global`` against a lightweight fake of Ghidra's PcodeOp /
Varnode API, so they run without a live Ghidra.
"""

import sys
import types

import pytest


def _install_fake_pcodeop():
    """Provide ``ghidra.program.model.pcode.PcodeOp`` with a distinct int per opcode name.

    The lifter does ``from ghidra.program.model.pcode import PcodeOp as P`` and compares
    ``op.getOpcode()`` against ``P.INDIRECT`` / ``P.MULTIEQUAL`` / ``P.STORE``. A metaclass that
    mints a stable unique value for any opcode name is enough, and lets tests build ops from the very
    same constants the code under test compares against.
    """
    if "ghidra.program.model.pcode" in sys.modules:
        return sys.modules["ghidra.program.model.pcode"].PcodeOp

    class _PcodeOpMeta(type):
        _values: dict = {}

        def __getattr__(cls, name):
            if name.startswith("_"):
                raise AttributeError(name)
            if name not in cls._values:
                cls._values[name] = 1000 + len(cls._values)
            return cls._values[name]

    class PcodeOp(metaclass=_PcodeOpMeta):
        @staticmethod
        def getMnemonic(opcode):
            return str(opcode)

    for pkg in ("ghidra", "ghidra.program", "ghidra.program.model", "ghidra.program.model.pcode"):
        sys.modules.setdefault(pkg, types.ModuleType(pkg))
    sys.modules["ghidra.program.model.pcode"].PcodeOp = PcodeOp
    return PcodeOp


PcodeOp = _install_fake_pcodeop()

from decompiler.frontend.ghidra.lifter import GhidraLifter  # noqa: E402  (after fake install)


class FakeVarnode:
    """A varnode that is either a ram global (``address``), a constant, or a register/unique."""

    def __init__(self, *, address=None, constant=None, uid=0, size=4):
        self._address = address
        self._constant = constant
        self._uid = uid
        self._size = size

    def isAddress(self):
        return self._address is not None

    def isConstant(self):
        return self._constant is not None

    def getOffset(self):
        return self._address if self._address is not None else (self._constant or 0)

    def getUniqueId(self):
        return self._uid

    def getSize(self):
        return self._size


class FakeOp:
    def __init__(self, opcode, output=None, inputs=()):
        self._opcode = opcode
        self._output = output
        self._inputs = list(inputs)

    def getOpcode(self):
        return self._opcode

    def getOutput(self):
        return self._output

    def getNumInputs(self):
        return len(self._inputs)

    def getInput(self, i):
        return self._inputs[i]


class FakeBlock:
    def __init__(self, ops):
        self._ops = ops

    def getIterator(self):
        return iter(self._ops)


class FakeHighFunction:
    def __init__(self, *blocks):
        self._blocks = list(blocks)

    def getBasicBlocks(self):
        return self._blocks


def _lifter():
    """A GhidraLifter with only the memory-SSA state, bypassing Ghidra-dependent handler setup."""
    lifter = object.__new__(GhidraLifter)
    lifter._written_globals = set()
    return lifter


def _ram(addr, uid=0):
    return FakeVarnode(address=addr, uid=uid)


def _reg(uid=0):
    return FakeVarnode(address=None, uid=uid)  # a register/unique: not an address varnode


def _const(value):
    return FakeVarnode(constant=value)


def _classify(*ops):
    lifter = _lifter()
    lifter.precompute_written_globals(FakeHighFunction(FakeBlock(list(ops))))
    return lifter


# -- read-only globals (must NOT be classified as written) -----------------------------------------


def test_indirect_only_global_is_readonly():
    # a global that only ever appears as a conservative may-write after a call (INDIRECT)
    op = FakeOp(PcodeOp.INDIRECT, output=_ram(0x405000), inputs=[_ram(0x405000), _const(0x2a)])
    lifter = _classify(op)
    assert 0x405000 not in lifter._written_globals
    assert not lifter._is_written_global(_ram(0x405000))
    assert lifter.defines_readonly_global(op)


def test_copy_rename_of_global_is_readonly():
    # COPY of a global from itself is an SSA rename, not a write
    op = FakeOp(PcodeOp.COPY, output=_ram(0x405000), inputs=[_ram(0x405000)])
    lifter = _classify(op)
    assert 0x405000 not in lifter._written_globals


def test_subpiece_fragment_of_global_is_readonly():
    # SUBPIECE fragmenting a wide global (0x405000) into a narrower view at 0x405002: still read-only
    op = FakeOp(PcodeOp.SUBPIECE, output=_ram(0x405002), inputs=[_ram(0x405000), _const(2)])
    lifter = _classify(op)
    assert 0x405002 not in lifter._written_globals
    assert lifter.defines_readonly_global(op)


def test_multiequal_of_global_is_readonly():
    # a memory phi is a merge of a global's own versions, not a write
    op = FakeOp(PcodeOp.MULTIEQUAL, output=_ram(0x405000), inputs=[_ram(0x405000), _ram(0x405000)])
    lifter = _classify(op)
    assert 0x405000 not in lifter._written_globals


def test_store_through_computed_pointer_does_not_write_globals():
    # a store whose target address is not a known constant is a conservative may-alias -> ignored,
    # matching Binary Ninja (a global is not re-versioned just because some pointer store might hit it)
    op = FakeOp(PcodeOp.STORE, output=None, inputs=[_const(0), _reg(uid=7), _const(0x99)])
    lifter = _classify(op)
    assert lifter._written_globals == set()


# -- genuinely-written globals (MUST be classified as written) -------------------------------------


def test_copy_from_register_writes_global():
    # a non-global value copied into the global address is a genuine write
    op = FakeOp(PcodeOp.COPY, output=_ram(0x405000), inputs=[_reg(uid=3)])
    lifter = _classify(op)
    assert 0x405000 in lifter._written_globals
    assert lifter._is_written_global(_ram(0x405000))
    assert not lifter.defines_readonly_global(op)


def test_direct_store_to_constant_address_writes_global():
    op = FakeOp(PcodeOp.STORE, output=None, inputs=[_const(0), _const(0x405010), _reg(uid=4)])
    lifter = _classify(op)
    assert 0x405010 in lifter._written_globals


def test_arithmetic_into_global_writes_it():
    op = FakeOp(PcodeOp.INT_ADD, output=_ram(0x405020), inputs=[_reg(uid=1), _const(1)])
    lifter = _classify(op)
    assert 0x405020 in lifter._written_globals


# -- mixed: one written global next to many read-only globals --------------------------------------


def test_written_and_readonly_globals_are_separated():
    # struct read-only fields versioned across a call (INDIRECT) + one genuinely written global
    ops = [
        FakeOp(PcodeOp.INDIRECT, output=_ram(0x405000), inputs=[_ram(0x405000), _const(1)]),
        FakeOp(PcodeOp.INDIRECT, output=_ram(0x405004), inputs=[_ram(0x405004), _const(1)]),
        FakeOp(PcodeOp.COPY, output=_ram(0x405100), inputs=[_reg(uid=9)]),  # the one real write
    ]
    lifter = _classify(*ops)
    assert lifter._written_globals == {0x405100}
    assert lifter._is_written_global(_ram(0x405100))
    assert not lifter._is_written_global(_ram(0x405000))
    assert not lifter._is_written_global(_ram(0x405004))


def test_write_anywhere_marks_global_written_even_with_readonly_uses():
    # order independence: a global written in one block and only read (INDIRECT) in another is written
    written_first = [
        FakeBlock([FakeOp(PcodeOp.COPY, output=_ram(0x405000), inputs=[_reg(uid=2)])]),
        FakeBlock([FakeOp(PcodeOp.INDIRECT, output=_ram(0x405000), inputs=[_ram(0x405000), _const(1)])]),
    ]
    lifter = _lifter()
    lifter.precompute_written_globals(FakeHighFunction(*written_first))
    assert 0x405000 in lifter._written_globals


def test_non_global_output_is_never_a_readonly_global():
    # an op that writes a register/unique (not a ram global) is not "defining a read-only global"
    op = FakeOp(PcodeOp.INT_ADD, output=_reg(uid=5), inputs=[_reg(uid=1), _const(1)])
    lifter = _classify(op)
    assert lifter._written_globals == set()
    assert not lifter.defines_readonly_global(op)
