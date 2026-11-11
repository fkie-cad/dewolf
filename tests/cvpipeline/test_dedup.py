import shutil
import subprocess

import pytest

from cvpipeline.corpus import DedupResult, deduplicate, group_by_binary, make_key, parse_key


def test_key_roundtrip_with_cpp_names():
    key = make_key("proj", "bin", "ns::Class::method")
    assert parse_key(key) == ("proj", "bin", "ns::Class::method")


def test_duplicates_within_a_project_keep_alphabetically_first():
    fingerprints = {"p": {"b1": {"f": "X", "g": "Y"}, "a0": {"h": "X"}}}
    result = deduplicate(fingerprints)
    assert result.kept == sorted([make_key("p", "a0", "h"), make_key("p", "b1", "g")])
    assert result.excluded == {make_key("p", "b1", "f"): make_key("p", "a0", "h")}


def test_fingerprint_claimed_by_earlier_project_is_excluded_in_later_one():
    fingerprints = {
        "zeta": {"b": {"shared": "S", "own": "Z"}},
        "alpha": {"b": {"shared": "S"}},
    }
    result = deduplicate(fingerprints)
    assert make_key("alpha", "b", "shared") in result.kept
    assert make_key("zeta", "b", "shared") not in result.kept
    assert result.excluded[make_key("zeta", "b", "shared")] == make_key("alpha", "b", "shared")
    assert make_key("zeta", "b", "own") in result.kept


def test_unfingerprinted_functions_are_always_kept():
    fingerprints = {"p": {"b": {"f": None, "g": None, "h": "X"}}, "q": {"b": {"f": None}}}
    result = deduplicate(fingerprints)
    assert len(result.kept) == 4
    assert result.unfingerprinted == 3
    assert result.excluded == {}


def test_result_independent_of_input_order():
    a = {"p": {"b": {"f": "X", "g": "X"}}, "q": {"c": {"h": "X"}}}
    b = {"q": {"c": {"h": "X"}}, "p": {"b": {"g": "X", "f": "X"}}}
    assert deduplicate(a) == deduplicate(b)


def test_json_roundtrip():
    result = deduplicate({"p": {"b": {"f": "X", "g": "X", "h": None}}})
    assert DedupResult.from_json(result.to_json()) == result


def test_group_by_binary():
    keys = [make_key("p", "b", "z"), make_key("p", "b", "a"), make_key("q", "c", "m")]
    assert group_by_binary(keys) == {("p", "b"): ["a", "z"], ("q", "c"): ["m"]}


# --------------------------------------------------------------------------------------------- #
# functions sharing a name within one binary
# --------------------------------------------------------------------------------------------- #


def test_same_named_functions_get_distinct_identifiers():
    from types import SimpleNamespace

    from cvpipeline.corpus import function_identifiers

    functions = [SimpleNamespace(name=name, start=start) for name, start in (("main", 0x1000), ("helper", 0x1100), ("helper", 0x1200))]
    identifiers = function_identifiers(functions)
    assert list(identifiers) == ["main", "helper@0x1100", "helper@0x1200"]
    assert identifiers["helper@0x1200"] is functions[2]
    assert parse_key(make_key("p", "b", "helper@0x1200")) == ("p", "b", "helper@0x1200")


def test_same_named_static_functions_are_fingerprinted_and_decompiled_separately(tmp_path):
    """Two files each define a static `helper`: both are fingerprinted, and each identifier is lifted as its own function."""
    import shutil
    import subprocess

    import pytest

    pytest.importorskip("binaryninja")
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    from cvpipeline.corpus import fingerprint_binary
    from cvpipeline.decompilation import make_options, process_binary
    from cvpipeline.storage import read_json

    (tmp_path / "a.c").write_text("static int helper(int x) { return x * 3 + 1; }\nint first(int x) { return helper(x); }\n")
    (tmp_path / "b.c").write_text(
        "static int helper(int x) { int s = 0; for (int i = 0; i < x; i++) s += i; return s; }\n"
        "int first(int);\nint main(int argc, char **argv) { return helper(argc) + first(argc); }\n"
    )
    binary = tmp_path / "same_names"
    build = subprocess.run(["gcc", "-g", "-O0", "-fno-inline", "-o", str(binary), str(tmp_path / "a.c"), str(tmp_path / "b.c")], capture_output=True)
    if build.returncode != 0:
        pytest.skip(f"could not build sample: {build.stderr.decode()[:200]}")

    fingerprint_binary(str(binary), str(tmp_path / "fingerprints.json"), str(tmp_path / "errors.log"))
    fingerprints = read_json(tmp_path / "fingerprints.json")["functions"]
    helpers = sorted(identifier for identifier in fingerprints if identifier.startswith("helper@"))
    assert len(helpers) == 2 and "helper" not in fingerprints and "main" in fingerprints
    assert fingerprints[helpers[0]] != fingerprints[helpers[1]]  # different bodies

    process_binary(
        binary_path=str(binary),
        functions=helpers,
        output_path=str(tmp_path / "result.json"),
        options=make_options("min"),
        analyze=lambda _name, task: {"identifier": task.function_identifier, "blocks": len(task.graph.nodes)},
        timeout_s=None,
        error_log=str(tmp_path / "errors.log"),
        metadata={},
    )
    results = read_json(tmp_path / "result.json")["functions"]
    assert [results[identifier]["status"] for identifier in helpers] == ["success", "success"]
    # after lifting the task carries the identifier string, not Binary Ninja's function object
    assert [results[identifier]["result"]["identifier"] for identifier in helpers] == helpers
    # each identifier was lifted as its own function: one is straight-line code, the other a loop
    assert results[helpers[0]]["result"]["blocks"] != results[helpers[1]]["result"]["blocks"]


@pytest.mark.parametrize("mode", ["conditional", "simple", "min", "lift_minimal", "sreedhar", "boissinot2008"])
def test_every_out_of_ssa_mode_runs_through_the_pipeline_entry_point(mode, corpus_sample, tmp_path):
    """Each algorithm the pipeline can evaluate decompiles the sample's functions via process_binary.
    (Boissinot's stage deep-copies the task, which fails if the task holds Binary Ninja's function object.)"""
    pytest.importorskip("binaryninja")
    from cvpipeline.decompilation import make_options, process_binary
    from cvpipeline.storage import read_json

    process_binary(
        binary_path=corpus_sample,
        functions=["main", "count_lines"],
        output_path=str(tmp_path / "result.json"),
        options=make_options(mode),
        analyze=lambda _name, task: len(task.graph.nodes),
        timeout_s=None,
        error_log=str(tmp_path / "errors.log"),
        metadata={},
    )
    results = read_json(tmp_path / "result.json")["functions"]
    assert {name: entry["status"] for name, entry in results.items()} == {"main": "success", "count_lines": "success"}, results


# --------------------------------------------------------------------------------------------- #
# fingerprints are name agnostic
# --------------------------------------------------------------------------------------------- #

_FINGERPRINT_SOURCE = """\
#define NOINLINE __attribute__((noinline))
int ga, gb;
NOINLINE int a(int x) { return x * 3 + 1; }
NOINLINE int b(int x) { int s = 0; for (int i = 0; i < x; i++) s += i; return s; }
NOINLINE int two(int x, int y) { return x - y; }
int wrap_a(int x) { return a(x); }
int wrap_b(int x) { return b(x); }
int wrap_two(int x) { return two(x, x); }
int same_twice(int x) { return a(x) + a(x + 1); }
int two_different(int x) { return a(x) + b(x + 1); }
int read_ga(void) { return ga + 1; }
int read_gb(void) { return gb + 1; }
int one_global_twice(void) { return ga * ga; }
int two_globals(void) { return ga * gb; }
int rec_one(int n) { return n <= 0 ? 0 : n + rec_one(n - 1); }
int rec_two(int n) { return n <= 0 ? 0 : n + rec_two(n - 1); }
int main(int argc, char **argv) {
    return wrap_a(argc) + wrap_b(argc) + wrap_two(argc) + same_twice(argc) + two_different(argc) + read_ga() + read_gb()
        + one_global_twice() + two_globals() + rec_one(argc) + rec_two(argc);
}
"""


def test_fingerprints_ignore_the_names_of_referenced_symbols(tmp_path):
    import shutil
    import subprocess

    import pytest

    pytest.importorskip("binaryninja")
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    from cvpipeline.corpus import fingerprint_binary
    from cvpipeline.storage import read_json

    (tmp_path / "names.c").write_text(_FINGERPRINT_SOURCE)
    binary = tmp_path / "names"
    build = subprocess.run(["gcc", "-g", "-O0", "-fno-inline", "-o", str(binary), str(tmp_path / "names.c")], capture_output=True)
    if build.returncode != 0:
        pytest.skip(f"could not build sample: {build.stderr.decode()[:200]}")
    fingerprint_binary(str(binary), str(tmp_path / "fingerprints.json"), str(tmp_path / "errors.log"))
    fingerprint = read_json(tmp_path / "fingerprints.json")["functions"]

    # same code, other callee / global / own name: duplicates
    assert fingerprint["wrap_a"] == fingerprint["wrap_b"]
    assert fingerprint["read_ga"] == fingerprint["read_gb"]
    assert fingerprint["rec_one"] == fingerprint["rec_two"]
    # the code itself still counts: different bodies, another number of arguments
    assert fingerprint["a"] != fingerprint["b"]
    assert fingerprint["wrap_a"] != fingerprint["wrap_two"]
    # one symbol used twice is not the same as two symbols
    assert fingerprint["same_twice"] != fingerprint["two_different"]
    assert fingerprint["one_global_twice"] != fingerprint["two_globals"]


# --------------------------------------------------------------------------------------------- #
# a sample binary for the corpus rules, built on the spot
# --------------------------------------------------------------------------------------------- #

_CORPUS_SAMPLE_SOURCE = """\
#include <stdio.h>
#include <stdlib.h>

/* Its symbol is removed after linking, so Binary Ninja has to find and name it by itself. */
__attribute__((noinline)) static int unnamed_helper(int x) { return x * 7 + 3; }

__attribute__((noinline)) int count_lines(const char *path) {
    FILE *file = fopen(path, "r");
    int lines = 0, c;
    if (file == NULL) {
        perror(path);
        exit(1);
    }
    while ((c = getc(file)) != EOF)
        lines += c == '\\n';
    fclose(file);
    return lines;
}

/* The error paths end in exit(): gcc -O2 moves them into main.cold / count_lines.cold. */
int main(int argc, char **argv) {
    if (argc < 2) {
        perror("usage");
        exit(1);
    }
    return count_lines(argv[1]) + unnamed_helper(argc);
}
"""


@pytest.fixture(scope="module")
def corpus_sample(tmp_path_factory):
    """A small -O2 binary with (if the compiler splits functions) cold fragments and a function
    without a symbol. Skips without gcc; the symbol is only removed if objcopy is available."""
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    directory = tmp_path_factory.mktemp("corpus_sample")
    (directory / "sample.c").write_text(_CORPUS_SAMPLE_SOURCE)
    binary = directory / "sample"
    build = subprocess.run(["gcc", "-g", "-O2", "-o", str(binary), str(directory / "sample.c")], capture_output=True)
    if build.returncode != 0 or not binary.exists():
        pytest.skip(f"could not build sample: {build.stderr.decode()[:200]}")
    if shutil.which("objcopy") is not None:
        subprocess.run(["objcopy", "--strip-symbol=unnamed_helper", str(binary)], capture_output=True)
    return str(binary)


# --------------------------------------------------------------------------------------------- #
# cold fragments are no corpus functions
# --------------------------------------------------------------------------------------------- #


def test_cold_fragments_are_recognised_by_name():
    from cvpipeline.corpus import is_cold_fragment

    assert is_cold_fragment("main.cold") and is_cold_fragment("pspeak.cold.1")
    # complete functions: other GCC variants, and names that merely contain "cold"
    for name in ("main", "foo.isra.0", "foo.constprop.0", "foo.part.0", "cold", "cold_start", "ns::cold"):
        assert not is_cold_fragment(name), name


def test_corpus_functions_leave_out_cold_fragments_and_scaffolding(corpus_sample, tmp_path):
    """On a binary with a hot/cold split: the cold fragment Binary Ninja lists is not fingerprinted."""
    binaryninja = pytest.importorskip("binaryninja")
    from cvpipeline.config import BN_LOAD_OPTIONS
    from cvpipeline.corpus import corpus_functions, fingerprint_binary, is_cold_fragment, settle_analysis
    from cvpipeline.storage import read_json

    view = binaryninja.load(corpus_sample, options=dict(BN_LOAD_OPTIONS))
    try:
        settle_analysis(view)
        listed = {function.name for function in view.functions}
        kept = corpus_functions(view)
    finally:
        view.file.close()
    if not any(is_cold_fragment(name) for name in listed):
        pytest.skip("this compiler did not split a cold fragment off the sample's functions")
    assert {"main", "count_lines"} <= set(kept) and not any(is_cold_fragment(name) for name in kept)

    fingerprint_binary(corpus_sample, str(tmp_path / "fingerprints.json"), str(tmp_path / "errors.log"))
    assert set(read_json(tmp_path / "fingerprints.json")["functions"]) == set(kept)


# --------------------------------------------------------------------------------------------- #
# Binary Ninja's analysis is settled before a binary is read
# --------------------------------------------------------------------------------------------- #


def test_settle_analysis_reads_every_function_then_waits():
    from cvpipeline.corpus import settle_analysis

    events = []

    class Function:
        def __init__(self, name, broken=False):
            self.name, self.broken = name, broken

        @property
        def mlil(self):
            if self.broken:
                raise RuntimeError("no IL")
            events.append(f"read {self.name}")
            return type("Il", (), {"ssa_form": None})()

    class View:
        functions = [Function("a"), Function("broken", broken=True), Function("b")]

        def update_analysis_and_wait(self):
            events.append("wait")

    settle_analysis(View())
    assert events == ["read a", "read b", "wait"]  # a function without IL does not stop the others


def test_fingerprints_of_a_binary_repeat_between_loads(corpus_sample, tmp_path):
    """Two separate loads of the same binary give the same fingerprints (the pipeline loads a binary
    once per stage, and deduplication relies on the stages seeing the same code)."""
    pytest.importorskip("binaryninja")
    from cvpipeline.corpus import fingerprint_binary
    from cvpipeline.storage import read_json

    results = []
    for attempt in range(2):
        output = tmp_path / f"fingerprints_{attempt}.json"
        fingerprint_binary(corpus_sample, str(output), str(tmp_path / "errors.log"))
        results.append(read_json(output)["functions"])
    assert results[0] == results[1] and results[0]


# --------------------------------------------------------------------------------------------- #
# functions without a symbol and functions Binary Ninja gave up on are no corpus functions
# --------------------------------------------------------------------------------------------- #


def test_generated_names_are_recognised_by_their_address():
    from types import SimpleNamespace

    from cvpipeline.corpus import has_generated_name

    assert has_generated_name(SimpleNamespace(name="sub_401000", start=0x401000))
    # a real function that merely starts with "sub_", or whose name is another address
    assert not has_generated_name(SimpleNamespace(name="sub_matrix", start=0x401000))
    assert not has_generated_name(SimpleNamespace(name="sub_401000", start=0x402000))
    assert not has_generated_name(SimpleNamespace(name="main", start=0x401000))
    # a thunk Binary Ninja named after its target; a real function that merely starts with "j_" is none
    assert has_generated_name(SimpleNamespace(name="j_luaE_warning", start=0x401000, is_thunk=True))
    assert not has_generated_name(SimpleNamespace(name="j_index", start=0x401000, is_thunk=False))
    assert not has_generated_name(SimpleNamespace(name="wrapper", start=0x401000, is_thunk=True))


def test_identifiers_do_not_depend_on_which_copy_a_corpus_rule_leaves_out():
    """Two functions share a name and Binary Ninja skipped the analysis of one: the other keeps the
    identifier it has when both are analysed, so every load of the binary names it the same."""
    binaryninja = pytest.importorskip("binaryninja")
    from types import SimpleNamespace

    from cvpipeline.corpus import corpus_functions

    def function(name, start, skipped=False):
        symbol = SimpleNamespace(type=binaryninja.SymbolType.FunctionSymbol)
        return SimpleNamespace(name=name, start=start, symbol=symbol, analysis_skipped=skipped, is_thunk=False)

    both = corpus_functions(SimpleNamespace(functions=[function("main", 0x1000), function("helper", 0x1100), function("helper", 0x1200)]))
    one = corpus_functions(SimpleNamespace(functions=[function("main", 0x1000), function("helper", 0x1100), function("helper", 0x1200, skipped=True)]))
    assert list(both) == ["main", "helper@0x1100", "helper@0x1200"]
    assert list(one) == ["main", "helper@0x1100"]


def test_function_missing_on_this_load_is_reported(tmp_path, monkeypatch):
    """A wanted function the binary does not have on this load gets its status and a line in the error log."""
    pytest.importorskip("binaryninja")
    from contextlib import contextmanager
    from types import SimpleNamespace

    from cvpipeline import decompilation
    from cvpipeline.storage import read_json

    @contextmanager
    def fake_frontend(_path, _options):
        yield SimpleNamespace(_bv=SimpleNamespace(functions=[]))

    monkeypatch.setattr(decompilation, "open_frontend", fake_frontend)
    error_log = tmp_path / "worker_errors.log"
    decompilation.process_binary(
        binary_path="bin", functions=["gone"], output_path=str(tmp_path / "out.json"), options=None,
        analyze=lambda _name, _task: None, timeout_s=None, error_log=str(error_log), metadata={},
    )
    assert read_json(tmp_path / "out.json")["functions"]["gone"]["status"] == decompilation.DECOMPILATION_ERROR
    assert "bin::gone: function not found in binary" in error_log.read_text()


def test_skipped_analysis_is_read_from_binary_ninja():
    from types import SimpleNamespace

    from cvpipeline.corpus import analysis_was_skipped

    assert analysis_was_skipped(SimpleNamespace(analysis_skipped=True))
    assert not analysis_was_skipped(SimpleNamespace(analysis_skipped=False))
    assert not analysis_was_skipped(SimpleNamespace())


def test_corpus_functions_have_symbols_and_complete_analysis(corpus_sample):
    """On a binary: no generated names and no skipped functions among the corpus functions."""
    binaryninja = pytest.importorskip("binaryninja")
    from cvpipeline.config import BN_LOAD_OPTIONS
    from cvpipeline.corpus import corpus_functions, has_generated_name, settle_analysis

    view = binaryninja.load(corpus_sample, options=dict(BN_LOAD_OPTIONS))
    try:
        settle_analysis(view)
        generated = [function.name for function in view.functions if has_generated_name(function)]
        kept = corpus_functions(view)
        assert generated, "the sample should have functions without a symbol"
        assert {"main", "count_lines"} <= set(kept) and "unnamed_helper" not in kept
        assert not any(has_generated_name(function) or function.analysis_skipped for function in kept.values())
    finally:
        view.file.close()


def test_binary_whose_analysis_cannot_be_settled_is_left_out_with_a_reason(tmp_path, monkeypatch):
    """Fingerprinting writes its result with a load error instead of failing the job without one."""
    binaryninja = pytest.importorskip("binaryninja")
    from types import SimpleNamespace

    from cvpipeline import corpus
    from cvpipeline.storage import read_json

    closed = []
    view = SimpleNamespace(functions=[], file=SimpleNamespace(close=lambda: closed.append(True)))

    def failing_settle(_view):
        raise RuntimeError("analysis aborted")

    monkeypatch.setattr(binaryninja, "load", lambda path, options=None: view)
    monkeypatch.setattr(corpus, "settle_analysis", failing_settle)
    error_log = tmp_path / "worker_errors.log"
    corpus.fingerprint_binary("bin", str(tmp_path / "fingerprints.json"), str(error_log))
    result = read_json(tmp_path / "fingerprints.json")
    assert result["functions"] == {} and "could not be settled" in result["load_error"] and "analysis aborted" in result["load_error"]
    assert "fingerprinting bin: Binary Ninja's analysis could not be settled" in error_log.read_text()
    assert closed == [True]
