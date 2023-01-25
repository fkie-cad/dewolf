import re
import subprocess

import pytest


def test_sample(test_cases):
    """Test the decompiler with the given test case."""
    sample, function_name = test_cases
    output = subprocess.run(("python", "decompile.py", sample, function_name), check=True, capture_output=True).stdout.decode('utf-8')
    assert "Failed to decompile due to error during " not in output


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
    # Make sure that table is referenced by its name, not by address
    assert output1.count("&table") == 0
    assert output1.count("table") > 1
    # Ensure string type is char *
    assert output2.count("extern char * hello_string") == 1
    # Make sure the global string contains the string hello world.
    assert output2.count('"Hello World"') == 1
    # Ensure that string is referenced correctly
    # TODO use this line instead of last assertion when expression propagation is adapted for global variables
    # assert output2.count("puts(/* str */ hello_string") == 1

    # Assert that the output looks like this:
    # ==============================================
    # extern char * hello_string = "Hello World";
    #
    # long global_string()
    # {
    #     char * var_1;
    #     var_1 = hello_string;
    #     return puts( / * str * / var_1);
    # }
    # ==============================================
    # important here that var is the same type as global string
    # and puts gets the variable as argument and not the *variable
    # after propagation done, should be simply ...return puts( / * str * / hello_string);...
    assert re.search(r'char\s*\*\s+var_\d.*\svar_\d\s*=\s*hello_string;', output2)
    assert re.search(r'return\s+puts\(/\*\s*str\s*\*/\s+var_\d\)', output2)


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

    # TODO add tests for " = &g_x" after solving issue with deleting stack strings/arrays
    # since for the moment we delete all variables storing stack string components,
    # e.g. var_e0#1 = &g_22

    # test occurences of global variables in decompiled code
    # first occurence in declaration
    # second when they are assigned some value
    assert output1.count("g_22 = ") == 2
    assert output1.count("g_26 = ") == 2
    assert output1.count("g_29 = ") == 2
    assert output1.count("g_30 = ") == 2
    assert output1.count("g_32 = ") == 2
    assert output1.count("g_35 = ") == 2
    assert output1.count("g_38 = ") == 2

    # test types and initial values (dec or hex) are correct in declarations
    assert re.search(r'unsigned short\s*g_22\s*=\s*54249', output1) or re.search(r'unsigned short\s*g_26\s*=\s*0xd3e9', output1)
    assert re.search(r'unsigned char\s*g_26\s*=\s*157', output1) or re.search(r'unsigned char\s*g_26\s*=\s*0x9d', output1)
    assert re.search(r'unsigned int\s*g_29\s*=\s*65537', output1) or re.search(r'unsigned int\s*g_29\s*=\s*0x10001', output1)
    assert re.search(r'unsigned char\s*g_30\s*=\s*236', output1) or re.search(r'unsigned char\s*g_30\s*=\s*0xec', output1)
    assert re.search(r'unsigned int\s*g_32\s*=\s*1578356047', output1) or re.search(r'unsigned int\s*g_32\s*=\s*0x5e13cd4f', output1)
    assert re.search(r'unsigned char\s*g_35\s*=\s*255', output1) or re.search(r'unsigned char\s*g_35\s*=\s*0xff', output1)
    assert re.search(r'unsigned int\s*g_38\s*=\s*130747369', output1) or re.search(r'unsigned int\s*g_38\s*=\s*0x7cb0be9', output1)


def test_tailcall_display():
    """Test that we display tailcalls correctly."""
    args = ["python", "decompile.py", "tests/coreutils/binaries/sha224sum", "rpl_fseeko"]
    output = str(subprocess.run(args, check=True, capture_output=True).stdout)

    assert output.count("return fseeko(") == 1


def test_issue_70():
    """Test Issue #70."""
    args = ["python", "decompile.py", "tests/samples/others/issue-70.bin", "main"]
    subprocess.run(args, check=True)


def test_iat_entries_are_decompiled_correctly():
    """Test Win API call to GetModuleHandleW is decompiled correctly."""
    args = ["python", "decompile.py", "tests/samples/others/test.exe", "0x401865"]
    subprocess.run(args, check=True)
    output = str(subprocess.run(args, check=True, capture_output=True).stdout)
    assert re.search(r'=\s*GetModuleHandleW\((0x0|/\* lpModuleName \*/ 0x0\))', output)