import re
import subprocess

import pytest


def test_sample(test_cases):
    """Test the decompiler with the given test case."""
    sample, function_name = test_cases
    output = subprocess.run(("python", "decompile.py", sample, function_name), check=True, capture_output=True).stdout.decode("utf-8")
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


def test_global_table():
    """Test that global tables appear as bytes."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_table"]

    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # Make sure the global variable table.xxx is generated
    assert output.count("extern void * table") == 1
    # Make sure the contents of this table variable are bytes
    assert output.count("\\\\x20\\\\x14\\\\x13\\\\x63\\\\x63") == 1
    # Make sure that table is referenced by its name, not by address
    assert output.count("&table") == 0
    assert output.count("table") > 1


def test_global_indirect_ptrs():
    """Test that indirect pointers in globals are dereferenced correctly."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_indirect_ptrs"]
    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    assert output.count("g_3 = ") == 1
    assert output.count("g_2 = &(g_3)") == 1


def test_global_addr():
    """Test that global variables are lifted correctly + address operator working"""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_addr_add"]

    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # Assert global variables correct
    assert output.count("a = 0x0") == 1
    assert output.count("b = 0x0") == 1
    # Asssert call correct; function signatur: int _add(int*, int*)
    assert output.count("_add(&a, &b") == 1


def test_global_ptr():
    """Test that global pointers are lifted correctly."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_ptr_add"]

    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # Assert global pointer correct
    assert output.count("c = 0x0") == 1
    assert output.count("d = 0x0") == 1
    # Assert call correct
    len(re.findall("var_[0-9]+= d", output)) == 1
    len(re.findall("var_[0-9]+= c", output)) == 1
    len(re.findall("_add(var_[0-9]+, var_[0-9]+)", output)) == 1


def test_global_ptr_addr():
    """Test that global pointer and variables are lifted correctly."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_addr_ptr_add"]

    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # Assert global pointer correct
    assert output.count("e = 0x17") == 1
    assert output.count("f = 0x42") == 1
    assert output.count("h = 0x0") == 1
    assert output.count("unsigned int * g = &(e)") == 1
    # Assert call correct
    len(re.findall("h = &f", output)) == 1
    len(re.findall("var_[0-9]+= h", output)) == 1
    len(re.findall("var_[0-9]+= g", output)) == 1
    len(re.findall("_add(var_[0-9]+, var_[0-9]+)", output)) == 1


def test_global_struct():
    """Test that global structs are lifted correctly."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_add_struct"]

    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # Assert global pointer correct
    assert output.count("void * i") == 1
    # Assert call correct
    len(re.findall("add_struct(i)", output)) == 1


def test_global_strings():
    """Test that global strings are lifted correctly."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_strings"]

    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # Assert global pointer correct
    assert output.count('char * j = "Hello Decompiler!"') == 1
    assert output.count('char * k = "Hello Void*!"') == 1
    # Assert call correct
    assert output.count("Hello World!") == 1


def test_global_fkt_ptr():
    """Test that global function pointers are lifted correctly."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_fkt_ptr"]

    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # Assert global variables correct
    assert output.count("a = 0x0") == 1
    assert output.count("b = 0x0") == 1
    assert output.count("l = 0x0") == 1
    # Assert call correct
    len(re.findall("var_[0-9]+(&a, &b, &a)", output)) == 1


def test_global_indirect_ptr2():
    """Test that global indirect pointers are lifted correctly."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_indirect_ptrs2"]

    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # Assert global variables correct
    assert output.count("p = 0xffffffbe") == 2  # should be one, still one lifter issue
    assert output.count("o = &(p)") == 1
    assert output.count("n = &(o)") == 1
    assert output.count("m = &(n)") == 1
    # Assert call correct
    len(re.findall("var_[0-9]+ = m", output)) == 1
    len(re.findall("_add(\*\*var_[0-9]+, &p)", output)) == 1


def test_global_recursive_ptr():
    """Test that global recursiv pointers are lifted correctly."""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_recursive_ptr"]

    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # Assert global variables correct
    assert output.count("void * q = q") == 1
    # Assert call correct
    len(re.findall("var_[0-9]+ = q", output)) == 2
    len(re.findall("_add(var_[0-9]+, var_[0-9]+)", output)) == 1


def test_global_import_address_symbol():
    """Test that ImportAddressSymbols from Binja gets displayed correctly."""
    base_args = ["python", "decompile.py", "tests/samples/others/app1.so"]
    args1 = base_args + ["test_case"]
    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    # TODO add tests for " = &g_x" after solving issue with deleting stack strings/arrays
    # since for the moment we delete all variables storing stack string components,
    # e.g. var_e0#1 = &g_22

    # test occurences of global variables in decompiled code
    # test ptr versions (_got to _data)
    assert output.count("g_22 = &(g_22)") == 1
    assert output.count("g_26 = &(g_26)") == 1
    assert output.count("g_29 = &(g_29)") == 1
    assert output.count("g_30 = &(g_30)") == 1
    assert output.count("g_32 = &(g_32)") == 1
    assert output.count("g_35 = &(g_35)") == 1
    assert output.count("g_38 = &(g_38)") == 1

    # test _data values
    assert output.count("g_22 = 0xd3e9") == 1
    assert output.count("g_26 = 0x9d") == 1
    assert output.count("g_29 = 0x10001") == 1
    assert output.count("g_30 = 0xec") == 1
    assert output.count("g_32 = 0x5e13cd4f") == 1
    assert output.count("g_35 = 0xff") == 1
    assert output.count("g_38 = 0x7cb0be9") == 1

    # test types and initial values (dec or hex) are correct in declarations
    assert re.search(r"unsigned short\s*g_22\s*=\s*54249", output) or re.search(r"unsigned short\s*g_22\s*=\s*0xd3e9", output)
    assert re.search(r"unsigned char\s*g_26\s*=\s*157", output) or re.search(r"unsigned char\s*g_26\s*=\s*0x9d", output)
    assert re.search(r"unsigned int\s*g_29\s*=\s*65537", output) or re.search(r"unsigned int\s*g_29\s*=\s*0x10001", output)
    assert re.search(r"unsigned char\s*g_30\s*=\s*236", output) or re.search(r"unsigned char\s*g_30\s*=\s*0xec", output)
    assert re.search(r"unsigned int\s*g_32\s*=\s*1578356047", output) or re.search(r"unsigned int\s*g_32\s*=\s*0x5e13cd4f", output)
    assert re.search(r"unsigned char\s*g_35\s*=\s*255", output) or re.search(r"unsigned char\s*g_35\s*=\s*0xff", output)
    assert re.search(r"unsigned int\s*g_38\s*=\s*130747369", output) or re.search(r"unsigned int\s*g_38\s*=\s*0x7cb0be9", output)


def test_string_with_pointer_compare():
    """Test that if(ptr == "String") works with logic engine"""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_string_compare"]
    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    assert output.count("Hello Decompiler") == 1  # it's enough to test if the output has the string. Would crash if not possible in if


def test_w_char():
    """Test that w_char strings are correctly found and propagated"""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_w_char"]
    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    assert output.count('L"Hello wchar32_t string"') == 1
    assert output.count('printf(/* format */ "%ls\\\\n", L"Inlined wchar32_t string")') == 1


def test_string_length():
    """Test that long strings/bytes are cut after a certain number of chars"""
    base_args = ["python", "decompile.py", "tests/samples/bin/systemtests/64/0/globals"]
    args1 = base_args + ["global_string_length"]
    output = str(subprocess.run(args1, check=True, capture_output=True).stdout)

    assert output.count("...") == 2


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
