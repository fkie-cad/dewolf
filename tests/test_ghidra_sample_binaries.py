"""End-to-end decompilation tests through the Ghidra frontend (``--frontend ghidra``).

Mirror of ``tests/test_sample_binaries.py`` for the Ghidra frontend. Split the same way binja's
systemtests/extendedtests are:

* ``test_ghidra_smoke`` -- a small curated set of functions, run on every PR.
* ``test_ghidra_sample`` -- the full parametrized sample matrix (shared ``test_cases`` fixture),
  only under ``--fulltests`` (the nightly extended pipeline).

Unlike the Binary Ninja sample tests (which shell out to ``decompile.py``), these lift in-process
via ``tests.ghidra_inprocess`` -- the Ghidra frontend runs a JVM in-process and re-initialising it in
a fresh subprocess is unreliable on CI (see that module). The whole module is skipped when
Ghidra/pyghidra is unavailable, so it is a no-op in the Binary Ninja CI image and on developer
machines without a Ghidra install.
"""

import pytest

from tests.ghidra_availability import ghidra_unavailable_reason
from tests.ghidra_inprocess import close_ghidra_decompilers, decompile_ghidra
from tests.sample_decompilation import record_crash

pytestmark = [
    pytest.mark.ghidra,
    pytest.mark.skipif(ghidra_unavailable_reason() is not None, reason=ghidra_unavailable_reason() or "Ghidra available"),
]


@pytest.fixture(scope="session", autouse=True)
def _release_ghidra_after_session():
    """Close the shared Ghidra program/JVM once all tests in this module have run."""
    yield
    close_ghidra_decompilers()


# A short, representative set exercising loops, conditions, switches and gotos across x86/x86-64 and
# several optimization levels. Kept to functions that currently decompile cleanly through the Ghidra
# frontend so this stays a meaningful green gate; the full matrix (nightly) covers everything else.
GHIDRA_SMOKE_CASES = [
    ("tests/samples/bin/systemtests/64/0/test_loop", "test2"),
    ("tests/samples/bin/systemtests/64/1/test_loop", "test1"),
    ("tests/samples/bin/systemtests/64/1/test_condition", "test5"),
    ("tests/samples/bin/systemtests/64/2/test_switch", "test2"),
    ("tests/samples/bin/systemtests/64/3/test_switch", "test7"),
    ("tests/samples/bin/systemtests/64/0/test_goto", "test1"),
]


@pytest.mark.parametrize("sample, function_name", GHIDRA_SMOKE_CASES)
def test_ghidra_smoke(sample, function_name):
    """Decompile a curated function through the Ghidra frontend (runs on every PR)."""
    ok, detail = decompile_ghidra(sample, function_name)
    if not ok:
        record_crash(sample, function_name)
    assert ok, detail


def test_ghidra_sample(test_cases, request):
    """Decompile every sample function through the Ghidra frontend (nightly, ``--fulltests`` only)."""
    if not request.config.getoption("fulltests"):
        pytest.skip("full Ghidra sample matrix runs only under --fulltests (nightly)")
    sample, function_name = test_cases
    ok, detail = decompile_ghidra(sample, function_name)
    if not ok:
        record_crash(sample, function_name)
    assert ok, detail
