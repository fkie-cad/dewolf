"""Module implementing the typing system for the pseudo language."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from typing import Tuple


@dataclass(frozen=True, order=True)
class Type(ABC):
    """Base interface for all type classes."""

    size: int

    @property
    def is_boolean(self) -> bool:
        """Check whether the given value is a boolean."""
        return self.size == 1

    def copy(self, **kwargs) -> Type:
        """Generate a copy of the current type."""
        return replace(self, **kwargs)

    def resize(self, new_size: int) -> Type:
        """Create an object of the type with a different size."""
        return self.copy(size=new_size)

    @abstractmethod
    def __str__(self) -> str:
        """Every type should provide a c-like string representation."""

    def __add__(self, other) -> Type:
        """Add two types to generate one type of bigger size."""
        return self.copy(size=self.size + other.size)

    def __hash__(self) -> int:
        """Return a hash value for the given type."""
        return hash(repr(self))


@dataclass(frozen=True, order=True)
class UnknownType(Type):
    """Represent an unknown type, mostly utilized for testing purposes."""

    def __init__(self, size: int = 0):
        """Create a type with size 0."""
        super().__init__(size)

    def __str__(self):
        """Return the representation of the unknown type."""
        return "unknown type"


@dataclass(frozen=True, order=True)
class Integer(Type):
    """Type for values representing numbers."""

    signed: bool = False

    SIZE_TYPES = {8: "char", 16: "short", 32: "int", 64: "long"}

    @classmethod
    def char(cls) -> Integer:
        """
        Return a character type (8 bit signed).
        Signedness of char is compiler specific,
        we follow major compilers with char ~ signed char
        """
        return cls(8, signed=True)

    @classmethod
    def int8_t(cls) -> Integer:
        """Return a char type (8 bit signed)."""
        return cls(8, signed=True)

    @classmethod
    def int16_t(cls) -> Integer:
        """Return a short type (16 bit signed)."""
        return cls(16, signed=True)

    @classmethod
    def int32_t(cls) -> Integer:
        """Return an integer type of default size (32 bit signed)."""
        return cls(32, signed=True)

    @classmethod
    def int64_t(cls) -> Integer:
        """Return an integer type of default size (64 bit signed)."""
        return cls(64, signed=True)

    @classmethod
    def int128_t(cls) -> Integer:
        """Return an integer type of default size (128 bit signed)."""
        return cls(128, signed=True)

    @classmethod
    def uint8_t(cls) -> Integer:
        """Return an integer type of default size (8 bit unsigned)."""
        return cls(8, signed=False)

    @classmethod
    def uint16_t(cls) -> Integer:
        """Return an integer type of default size (16 bit unsigned)."""
        return cls(16, signed=False)

    @classmethod
    def uint32_t(cls) -> Integer:
        """Return an integer type of default size (32 bit unsigned)."""
        return cls(32, signed=False)

    @classmethod
    def uint64_t(cls) -> Integer:
        """Return an integer type of default size (32 bit unsigned)."""
        return cls(64, signed=False)

    @classmethod
    def uint128_t(cls) -> Integer:
        """Return an integer type of default size (128 bit unsigned)."""
        return cls(128, signed=False)

    @property
    def is_signed(self) -> bool:
        """Check whether the value is signed."""
        return self.signed

    def __str__(self):
        """Generate a nice string representation based on known types."""
        if size_type := self.SIZE_TYPES.get(self.size):
            return f"{'unsigned ' if not self.signed else ''}{size_type}"
        return f"{'u' if not self.is_signed else ''}int{self.size}_t"


@dataclass(frozen=True, order=True)
class Float(Integer):
    """Class representing the type of a floating point number as defined in IEEE 754."""

    SIZE_TYPES = {16: "half", 32: "float", 64: "double", 80: "long double", 128: "quadruple", 256: "octuple"}

    def __init__(self, size: int, signed=True):
        """Create a new float type with the given size."""
        super().__init__(size, signed)

    @classmethod
    def float(cls) -> Float:
        """Return a float type (IEEE 754)."""
        return cls(32)

    @classmethod
    def double(cls) -> Float:
        """Return a double sized float."""
        return cls(64)

    def __str__(self) -> str:
        """Return a string representation."""
        return self.SIZE_TYPES[self.size]


@dataclass(frozen=True, order=True)
class Pointer(Type):
    """Class representing types based on being pointers on other types."""

    basetype: Type

    def __init__(self, basetype: Type, size: int = 32):
        """Custom constructor to change the order of the parameters."""
        object.__setattr__(self, "basetype", basetype)
        object.__setattr__(self, "size", size)

    @property
    def type(self) -> Type:
        """Return the pointee."""
        return self.basetype

    def __str__(self) -> str:
        """Return a nice string representation."""
        if isinstance(self.type, Pointer):
            return f"{self.basetype}*"
        return f"{self.basetype} *"


@dataclass(frozen=True, order=True)
class CustomType(Type):
    """Class representing a non-basic type."""

    text: str

    def __init__(self, text: str, size: int):
        """Custom constructor to change the order of the parameters."""
        object.__setattr__(self, "text", text)
        object.__setattr__(self, "size", size)

    @classmethod
    def bool(cls) -> CustomType:
        """Return a boolean type representing either TRUE or FALSE."""
        return cls("bool", 1)

    @classmethod
    def void(cls) -> CustomType:
        """Return a void type representing a nil value."""
        return cls("void", 0)

    def __str__(self) -> str:
        """Return the given string representation."""
        return self.text


@dataclass(frozen=True, order=True)
class FunctionTypeDef(Type):
    return_type: Type
    parameters: Tuple[Type, ...]

    def __str__(self) -> str:
        """Return an anonymous string representation such as void*(int, int, char*)."""
        return f"{self.return_type}({', '.join(str(x) for x in self.parameters)})"


class TypeParser:
    """A type parser in charge of creating types."""

    KNOWN_TYPES = {
        "char": Integer.char(),
        "signed char": Integer.int8_t(),
        "unsigned char": Integer.uint8_t(),
        "short": Integer.int16_t(),
        "unsigned short": Integer.uint16_t(),
        "word": Integer.int16_t(),
        "unsigned word": Integer.uint16_t(),
        "int": Integer.int32_t(),
        "unsigned int": Integer.uint32_t(),
        "dword": Integer.int32_t(),
        "unsigned dword": Integer.uint32_t(),
        "long": Integer.int64_t(),
        "unsigned long": Integer.int64_t(),
        "long int": Integer.int64_t(),
        "unsigned long int": Integer.uint64_t(),
        "long long": Integer.int128_t(),
        "unsigned long long": Integer.int128_t(),
        "void": CustomType.void(),
        "bool": CustomType.bool(),
        "float": Float.float(),
        "double": Float.double(),
    }

    def __init__(self, bitness: int = 32):
        """Generate a new type parser with the given wordsize."""
        self._wordsize = bitness

    def parse(self, text: str) -> Type:
        """Parse the given string and return a fitting type object."""
        text = text.strip()
        if text.endswith("*"):
            return Pointer(self.parse(text[:-1]), size=self._wordsize)
        return self.KNOWN_TYPES.get(text.lower(), CustomType(text, self._wordsize))
