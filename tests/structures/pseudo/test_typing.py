"""Tests for the pseudo typing functionality."""
import pytest
from decompiler.structures.pseudo.typing import CustomType, Float, Integer, Pointer, TypeParser


def test_representation():
    """Test the text representation of various types."""
    # Integer tests
    assert str(Integer(32, signed=True)) == "int"
    assert str(Integer(32, signed=False)) == "unsigned int"
    assert str(Integer(64, signed=True)) == "long"
    assert str(Integer(16, signed=False)) == "unsigned short"
    assert str(Integer(8, signed=True)) == "char"
    assert str(Integer(8, signed=False)) == "unsigned char"
    assert str(Integer(42, signed=False)) == "uint42_t"
    # Float
    assert str(Float(32)) == "float"
    assert str(Float(64)) == "double"
    assert str(Float(80)) == "long double"
    assert str(Float(128)) == "quadruple"
    assert str(Float(256)) == "octuple"
    with pytest.raises(KeyError):
        assert str(Float(63))
    # Custom
    assert str(CustomType.void()) == "void"
    assert str(CustomType.bool()) == "bool"
    assert str(CustomType("test", 32)) == "test"
    # Pointer
    assert str(Pointer(CustomType.void())) == "void *"
    assert str(Pointer(Integer.int32_t())) == "int *"
    assert str(Pointer(Pointer(Integer.uint32_t()))) == "unsigned int **"


def test_char_representation():
    """Test parsing and printing of signed / unsigned char"""
    parser = TypeParser()
    assert parser.parse("unsigned char") == Integer(8, signed=False)
    assert parser.parse("signed char") == Integer(8, signed=True)
    assert parser.parse("char") == Integer(8, signed=True)


def test_equality():
    """Test the equality of types defined in typing.py"""
    assert Integer(32, signed=True) == Integer.int32_t()
    assert Integer(32, signed=False) != Integer.int32_t()
    assert Integer(32) > Integer(16)
    assert CustomType.bool() > CustomType.void()
    assert Float.float().size < Integer.int64_t().size


def test_resize():
    """Test the resize system generating new types."""
    assert Integer.int32_t().resize(64) == Integer.int64_t()
    assert Float.float().resize(64) == Float.double()
    assert Integer.uint8_t() + Integer.int16_t() == Integer(24, signed=False)
    assert CustomType.void() + CustomType.void() == CustomType.void()
    assert CustomType.bool() + Float.float() == CustomType("bool", 33)


def test_is_bool():
    """Test the is_bool member function of the Type class."""
    assert CustomType.bool().is_boolean
    assert not CustomType.void().is_boolean
    assert not Integer.int32_t().is_boolean
    assert Integer.int32_t().resize(1).is_boolean


def test_type_parser():
    """Test the type parser to support basic type guessing."""
    parser = TypeParser()
    assert parser.parse("void *") == Pointer(CustomType.void())
    assert parser.parse("unsigned int **") == Pointer(Pointer(Integer(32, signed=False)))
