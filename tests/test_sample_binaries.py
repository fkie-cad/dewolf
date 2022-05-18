import subprocess

import pytest

# def test_sample(test_cases):
#    """Test the decompiler with the given test case."""
#    sample, function_name = test_cases
#    subprocess.run(("python", "decompile.py", sample, function_name), check=True)


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


def test_global_strings_and_tables():
    """Test that strings appear when they should and global tables appear as bytes."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_table"]
    args2 = base_args + ["global_string"]

    output1 = str(subprocess.run(args1, check=True, capture_output=True).stdout)
    output2 = str(subprocess.run(args2, check=True, capture_output=True).stdout)

    # Make sure the global variable table.xxx is generated
    assert output1.count("extern char * table") == 1
    # Make sure the contents of this table variable are bytes
    assert output1.count("\\\\x20\\\\x14\\\\x13\\\\x63\\\\x63") == 1
    # Make sure that table is referenced by address
    assert output1.count("&table") == 1
    # Ensure string type is char *
    assert output2.count("extern char * hello_string") == 1
    # Make sure the global string contains the string hello world.
    assert output2.count('"Hello World"') == 1
    # Ensure that string is referenced correctly
    assert output2.count("puts(/* str */ hello_string") == 1


def test_global_indirect_ptrs():
    """Test that indirect pointers in globals are dereferenced correctly."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_indirect_ptrs"]
    output1 = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    assert output1.count("g_3 = ") == 1
    assert output1.count("g_2 = &(g_3)") == 1


def test_global_import_address_symbol():
    """Test that ImportAddressSymbols from Binja gets displayed correctly."""
    base_args = ["python", "decompile.py", "tests/samples/others/app1.so"]
    args1 = base_args + ["test_case"]
    output1 = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    assert output1.count("g_22 = ") == 1
    assert output1.count("g_22_1 = &(g_22)") == 1
    assert output1.count("g_26 = ") == 1
    assert output1.count("g_26_1 = &(g_26)") == 1
    assert output1.count("g_29 = ") == 1
    assert output1.count("g_29_1 = &(g_29)") == 1
    assert output1.count("g_30 = ") == 1
    assert output1.count("g_30_1 = &(g_30)") == 1
    assert output1.count("g_32 = ") == 1
    assert output1.count("g_32_1 = &(g_32)") == 1
    assert output1.count("g_35 = ") == 1
    assert output1.count("g_35_1 = &(g_35)") == 1
    assert output1.count("g_38 = ") == 1
    assert output1.count("g_38_1 = &(g_38)") == 1


def test_tailcall_display():
    """Test that we display tailcalls correctly."""
    args = ["python", "decompile.py", "tests/coreutils/binaries/sha224sum", "rpl_fseeko"]
    output = str(subprocess.run(args, check=True, capture_output=True).stdout)

    assert output.count("return fseeko(") == 1
