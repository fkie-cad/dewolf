"""Ghidra counterpart of the Binary Ninja ``visualtest`` (see the Makefile).

The binja ``visualtest`` runs ``decompile.py`` on a handful of representative functions to confirm the
whole decompile -> render path produces output without crashing. This mirrors it for the Ghidra
frontend on the same functions, lifting in-process (a ``decompile.py`` subprocess re-inits pyghidra's
JVM, which is unreliable on CI -- see ``tests.ghidra_inprocess``). Skipped when Ghidra is unavailable.
"""

import pytest

from tests.ghidra_availability import ghidra_unavailable_reason
from tests.ghidra_inprocess import close_ghidra_decompilers, decompile_ghidra

pytestmark = [
    pytest.mark.ghidra,
    pytest.mark.skipif(ghidra_unavailable_reason() is not None, reason=ghidra_unavailable_reason() or "Ghidra available"),
]

# The same functions the Binary Ninja visualtest renders.
VISUAL_CASES = [
    ("tests/samples/bin/systemtests/32/0/test_loop", "test10"),
    ("tests/samples/bin/systemtests/32/2/test_switch", "test2"),
    ("tests/samples/bin/systemtests/64/0/test_loop", "test2"),
    ("tests/samples/bin/systemtests/64/1/test_condition", "test5"),
    ("tests/samples/bin/systemtests/64/3/test_switch", "test7"),
    ("tests/samples/bin/systemtests/64/2/condmap", "main"),
    ("tests/samples/bin/systemtests/32/0/test_goto", "test2"),
]


@pytest.fixture(scope="session", autouse=True)
def _release_ghidra_after_session():
    """Close the shared Ghidra program/JVM once all tests in this module have run."""
    yield
    close_ghidra_decompilers()


@pytest.mark.parametrize("sample, function_name", VISUAL_CASES)
def test_ghidra_visual(sample, function_name):
    """Decompile a representative function through the Ghidra frontend without crashing."""
    ok, detail = decompile_ghidra(sample, function_name)
    assert ok, detail
