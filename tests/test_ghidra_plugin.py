"""Smoke test for the Ghidra frontend + GUI-plugin decompilation path.

Analogous to ``tests/test_plugin.py`` (which exercises the Binary Ninja plugin's ``decompile`` entry
point). The Ghidra GUI plugin runs dewolf *in-process* via the Ghidra frontend and then feeds the
formatted C through ``ghidra_plugin.tokenizer`` for rendering. This test exercises that exact path
headlessly -- start PyGhidra, lift + decompile a real function, tokenize the result -- without
needing the Ghidra GUI. It is skipped when pyghidra / a Ghidra install is unavailable.
"""

import pytest

# Import the plugin tokenizer at module load: pyghidra.start() strips the repo root (cwd) from
# sys.path when it boots the JVM, so a deferred `import ghidra_plugin` after a decompile would fail.
from ghidra_plugin.tokenizer import BREAK, tokenize

from tests.ghidra_availability import ghidra_unavailable_reason

pytestmark = [
    pytest.mark.ghidra,
    pytest.mark.skipif(ghidra_unavailable_reason() is not None, reason=ghidra_unavailable_reason() or "Ghidra available"),
]

SAMPLE = "tests/samples/bin/systemtests/64/0/test_loop"
FUNCTION = "test2"


@pytest.fixture(scope="module")
def ghidra_decompiler(tmp_path_factory):
    """A dewolf decompiler backed by the Ghidra frontend on a sample binary (analyzed once)."""
    from decompile import Decompiler

    # own project directory so this test never collides with the sample-binary tests' projects
    options = Decompiler.create_options()
    options.set("ghidra.project_location", str(tmp_path_factory.mktemp("ghidra_project")))
    decompiler = Decompiler.from_path(SAMPLE, options=options, frontend="ghidra")
    try:
        yield decompiler
    finally:
        frontend = getattr(decompiler, "_frontend", None)
        if frontend is not None and hasattr(frontend, "close"):
            frontend.close()


def test_ghidra_frontend_decompiles_a_function(ghidra_decompiler):
    """The Ghidra frontend lifts + decompiles a function without failing."""
    task, code = ghidra_decompiler.decompile(FUNCTION)
    assert not task.failed
    assert code and "Decompilation Failed" not in code


def test_plugin_tokenizer_consumes_ghidra_output(ghidra_decompiler):
    """The GUI plugin's tokenizer turns the decompiled C into a non-empty token stream."""
    _, code = ghidra_decompiler.decompile(FUNCTION)
    tokens = tokenize(code, lambda name: (4, -1))  # classify every identifier as a plain variable
    assert tokens, "tokenizer produced no tokens for the decompiled function"
    assert any(kind == BREAK for kind, *_ in tokens), "multi-line output should yield line breaks"
