import re
import subprocess

import pytest
from decompiler.backend.codegenerator import FAIL_MESSAGE


def test_sample(test_cases):
    """Test the decompiler with the given test case."""
    sample, function_name = test_cases
    output = subprocess.run(("python", "decompile.py", sample, function_name), check=True, capture_output=True).stdout.decode("utf-8")
    assert FAIL_MESSAGE not in output


def test_globals():
    """Test and ensure that display of global variables appear correct."""
    base_args = ["python", "decompile.py"]
    args1 = base_args + ["tests/samples/bin/systemtests/64/2/condmap", "main"]
    args2 = base_args + ["tests/samples/bin/systemtests/32/0/test_goto", "test2"]

    output1 = str(subprocess.run(args1, check=True, capture_output=True).stdout)
    output2 = str(subprocess.run(args2, check=True, capture_output=True).stdout)

    # ensure there is no duplicated declarations of the main function.
    assert output1.count("main") == 1
    # this binary should not produce any null pointers.
    assert output1.count("NULL") == 0
    # ensure that the first few bytes of the ELF header are not accidentally dereferenced.
    assert output2.count("ELF") == 0


def test_var_decls():
    """Test that function arguments are not declared more than once."""
    sample = "tests/samples/bin/systemtests/64/2/undefined_variables"
    function_name = "test10"
    args = ["python", "decompile.py", sample, function_name]
    output = str(subprocess.run(args, check=True, capture_output=True).stdout)
    assert output.count("int arg1") == 1


def test_tailcall_display():
    """Test that we display tailcalls correctly."""
    args = ["python", "decompile.py", "tests/coreutils/binaries/sha224sum", "rpl_fseeko"]
    output = str(subprocess.run(args, check=True, capture_output=True).stdout)

    assert output.count("return fseeko(") == 1


def test_member_access_is_in_decompiled_code():
    """Test that arg1#0->_IO_read_ptr, arg1#0->_IO_write_base and arg1#0->_IO_save_base
    are displayed as member accesses in the decompiled code."""
    args = ["python", "decompile.py", "tests/coreutils/binaries/sha224sum", "rpl_fseeko"]
    output = str(subprocess.run(args, check=True, capture_output=True).stdout)

    assert "->_IO_read_ptr" in output
    assert "->_IO_save" in output
    assert "->_IO_write_base" in output


def test_issue_70():
    """Test Issue #70."""
    args = ["python", "decompile.py", "tests/samples/others/issue-70.bin", "main"]
    subprocess.run(args, check=True)


def test_iat_entries_are_decompiled_correctly():
    """Test Win API call to GetModuleHandleW is decompiled correctly."""
    args = ["python", "decompile.py", "tests/samples/others/test.exe", "0x401865"]
    subprocess.run(args, check=True)
    output = str(subprocess.run(args, check=True, capture_output=True).stdout)
    assert re.search(r"=\s*GetModuleHandleW\((0x0|/\* lpModuleName \*/ 0x0\))", output)
