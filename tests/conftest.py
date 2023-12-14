import pathlib
import re
from typing import Dict, List, Tuple

import pytest


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


def pytest_generate_tests(metafunc):
    """Generates test_cases based on command line options

    the resulting fixture test_cases can then be used to parametrize our test_sample function
    """
    if "test_cases" in metafunc.fixturenames:
        full_tests = metafunc.config.getoption("fulltests")
        if full_tests:
            test_cases = _discover_full_tests()
        else:
            test_cases = _discover_system_tests()
        params = list()
        for sample_name, functions in test_cases.items():
            for f in functions:
                params.append((sample_name, f))
        metafunc.parametrize("test_cases", params)

    if "coreutils_tests" in metafunc.fixturenames:
        coreutils_tests = _discover_coreutils_tests()
        metafunc.parametrize("coreutils_tests", coreutils_tests)


def _discover_full_tests() -> Dict[pathlib.Path, List[str]]:
    """Discover test source files and the test functions in these files.

    All files with a .c extension that contain at least one test function are considered as test files.
    """
    makefile = _parse_makefile()
    test_cases = _discover_tests_in_directory_tree(makefile["system_tests_src_path"], makefile["system_tests_bin_path"])
    extended_test_cases = _discover_tests_in_directory_tree(makefile["extended_tests_src_path"], makefile["extended_tests_bin_path"])
    test_cases.update(extended_test_cases)
    return test_cases


def _discover_system_tests() -> Dict[pathlib.Path, List[str]]:
    """Returns a mapping of system tests binaries to the lists of function names contained in those binaries"""
    test_cases = dict()
    makefile = _parse_makefile()
    test_code_files = makefile["system_tests_src_path"].glob("*.c")
    for test_code_file in test_code_files:
        if test_functions := _discover_test_functions_in_sample_code(test_code_file):
            test_cases[makefile["system_tests_bin_path"] / "32" / "0" / test_code_file.stem] = test_functions
    return test_cases


def _discover_coreutils_tests() -> List[Tuple[pathlib.Path, str]]:
    """Returns list of (binary, func_name) from a text file for the coreutils binaries."""
    with pathlib.Path("tests/coreutils/functions.txt").open("r", encoding="utf-8") as f:
        funcs_contents = f.readlines()
    files = []
    for line in funcs_contents:
        f = line.split()
        path = pathlib.Path(f"tests/coreutils/binaries/{f[0]}")
        files.append(pytest.param((path, f[1]), id=f"{f[0]}:{f[1]}"))
    return files


def _discover_tests_in_directory_tree(src_path, bin_path) -> Dict[pathlib.Path, List[str]]:
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


def _discover_test_functions_in_sample_code(sample: pathlib.Path) -> List[str]:
    """Discover test functions in the given source file.
    Test function to be included have to be named 'testN' where 'N' has to be an integer."""
    test_names = list()
    with sample.open("r", encoding="utf-8") as f:
        for line in f.readlines():
            if match := re.match(r"\w+ (?P<test_name>test\d+)\(.*\)", line):
                test_names.append(match.group("test_name"))
    return test_names


def _parse_makefile() -> Dict[str, pathlib.Path]:
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
