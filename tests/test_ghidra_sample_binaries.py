"""End-to-end decompilation tests through the Ghidra frontend.

Mirror of ``tests/test_sample_binaries.py`` for the Ghidra frontend, driven by the same ``test_cases``
fixture: the system-test set on ``--systemtests`` (every PR) and the full sample matrix on
``--fulltests`` (the nightly extended pipeline) -- exactly like the Binary Ninja ``test_sample``.

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


def test_ghidra_sample(test_cases):
    """Decompile a sample function through the Ghidra frontend (system set on PR, full set nightly)."""
    sample, function_name = test_cases
    ok, detail = decompile_ghidra(sample, function_name)
    if not ok:
        record_crash(sample, function_name)
    assert ok, detail
