from binaryninja import load

from __init__ import decompile


def test_plugin():
    """Test if plugin does not raise errors"""
    filename = "tests/samples/bin/systemtests/64/0/test_loop"
    bv = load(filename)
    function = bv.get_functions_by_name("main")[0]
    decompile(bv, function)
