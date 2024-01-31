import pathlib
import re
from itertools import chain
from typing import Iterator

import pytest
from _pytest.mark import ParameterSet
from _pytest.python import Metafunc


def pytest_addoption(parser):
    """Adds command line options for pytest
    - fulltests for all binaries on all optimization levels across x86 and x86-64
    - systemtests for x86 -O0 only
    """
    parser.addoption("--fulltests", action="store_true", help="run tests for all samples")
    parser.addoption("--systemtests", action="store_true", help="run the system tests")
    parser.addoption("--coreutils", action="store_true", help="run the coreutils tests")


def pytest_configure(config):
    if not config.option.coreutils:
        if expr := config.option.markexpr:
            setattr(config.option, "markexpr", f"{expr} and not coreutils")
        else:
            setattr(config.option, "markexpr", "not coreutils")


def pytest_generate_tests(metafunc: Metafunc):
    """Generates test_cases based on command line options

    the resulting fixture test_cases can then be used to parametrize our test_sample function
    """
    if "test_cases" in metafunc.fixturenames:
        full_tests = metafunc.config.getoption("fulltests")
        if full_tests:
            test_cases = _discover_full_tests()
        else:
            test_cases = _discover_system_tests()

        metafunc.parametrize("test_cases", _create_params(test_cases))

    if "coreutils_tests" in metafunc.fixturenames:
        coreutils_tests = _discover_coreutils_tests()
        metafunc.parametrize("coreutils_tests", _create_params(coreutils_tests))


def _create_params(cases: Iterator[(pathlib.Path, str)]) -> list[ParameterSet]:
    """
    Accepts an iterator of sample binaries paired with a function name to test.
    Returns a list of ParameterSet objects to be used with metafunc.parametrize.

    Note that we sort all test cases by their id so that we have a deterministic/consistent ordering of tests.
    This is needed by pytest-xdist to function properly.
    See https://pytest-xdist.readthedocs.io/en/stable/known-limitations.html#order-and-amount-of-test-must-be-consistent
    """
    test_cases = map(lambda i: pytest.param((i[0], i[1]), id=f"{i[0]}::{i[1]}"), cases)
    return sorted(test_cases, key=lambda p: p.id)


def _discover_full_tests() -> Iterator[(pathlib.Path, str)]:
    """Discover test source files and the test functions in these files.

    All files with a .c extension that contain at least one test function are considered as test files.
    """
    makefile = _parse_makefile()
    test_cases = _discover_tests_in_directory_tree(makefile["system_tests_src_path"], makefile["system_tests_bin_path"])
    extended_test_cases = _discover_tests_in_directory_tree(makefile["extended_tests_src_path"], makefile["extended_tests_bin_path"])

    for sample_path, functions in chain(test_cases.items(), extended_test_cases.items()):
        for function in functions:
            yield sample_path, function


def _discover_system_tests() -> Iterator[(pathlib.Path, str)]:
    """Returns a mapping of system tests binaries to the lists of function names contained in those binaries"""
    makefile = _parse_makefile()
    test_code_files = makefile["system_tests_src_path"].glob("*.c")
    for test_code_file in test_code_files:
        sample_path = makefile["system_tests_bin_path"] / "32" / "0" / test_code_file.stem
        for function_name in _discover_test_functions_in_sample_code(test_code_file):
            yield sample_path, function_name


def _discover_coreutils_tests() -> Iterator[(pathlib.Path, str)]:
    """Returns list of (binary, func_name) from a text file for the coreutils binaries."""
    with pathlib.Path("tests/coreutils/functions.txt").open("r", encoding="utf-8") as f:
        funcs_contents = f.readlines()

    for line in funcs_contents:
        (sample_name, function_name) = line.split()
        yield pathlib.Path(f"tests/coreutils/binaries/{sample_name}"), function_name


def _discover_tests_in_directory_tree(src_path: pathlib.Path, bin_path: pathlib.Path) -> dict[pathlib.Path, list[str]]:
    """Return a mapping of binaries collected recursively in the bin_path to function names contained in those binaries"""
    test_cases = dict()
    test_code_files = src_path.glob("*.c")
    # todo check if executable
    test_binaries = [f for f in bin_path.glob("**/*") if f.is_file()]
    for test_code_file in test_code_files:
        if test_functions := _discover_test_functions_in_sample_code(test_code_file):
            for f in test_binaries:
                if f.name.endswith(test_code_file.stem):
                    test_cases[f] = test_functions
    return test_cases


def _discover_test_functions_in_sample_code(sample: pathlib.Path) -> list[str]:
    """Discover test functions in the given source file.
    Test function to be included have to be named 'testN' where 'N' has to be an integer."""
    test_names = list()
    with sample.open("r", encoding="utf-8") as f:
        for line in f.readlines():
            if match := re.match(r"\w+ (?P<test_name>test\d+)\(.*\)", line):
                test_names.append(match.group("test_name"))
    return test_names


def _parse_makefile() -> dict[str, pathlib.Path]:
    """Parse from Makefile path to systemtests sources and binaries as well as
    path to extended tests sources and binaries"""
    makefile = dict()
    with pathlib.Path("Makefile").open("r", encoding="utf-8") as f:
        mkfile_contents = f.readlines()
    for line in mkfile_contents:
        if match := re.match(r"^SYSTEM_TESTS_BIN_PATH\s:=\s(.*)$", line):
            makefile["system_tests_bin_path"] = pathlib.Path(match.group(1))
        if match := re.match(r"^EXTENDED_TESTS_BIN_PATH\s:=\s(.*)$", line):
            makefile["extended_tests_bin_path"] = pathlib.Path(match.group(1))
        if match := re.match(r"^SYSTEM_TESTS_SRC_PATH\s:=\s(.*)$", line):
            makefile["system_tests_src_path"] = pathlib.Path(match.group(1))
        if match := re.match(r"^EXTENDED_TESTS_SRC_PATH\s:=\s(.*)$", line):
            makefile["extended_tests_src_path"] = pathlib.Path(match.group(1))
    return makefile
