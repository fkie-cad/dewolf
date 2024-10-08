import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from decompiler.structures.pseudo.typing import Type


class ComplexTypeSpecifier(Enum):
    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    CLASS = "class"


@dataclass(frozen=True, order=True, slots=True)
class ComplexType(Type):
    size = 0
    name: str

    def __str__(self):
        return self.name

    def declaration(self) -> str:
        raise NotImplementedError

    @property
    def complex_type_name(self):
        return ComplexTypeName(0, self.name)


@dataclass(frozen=True, order=True)
class ComplexTypeMember(ComplexType):
    """Class representing a member of a struct type.
    @param name: name of the struct member
    @param offset: offset of the member within the struct
    @param type: datatype of the member
    @param value: initial value of the member, enums only
    """

    name: str
    offset: int
    type: Type
    value: Optional[int] = None

    def __str__(self) -> str:
        return f"{self.name}"

    def declaration(self) -> str:
        """Return declaration field for the complex type member."""
        if isinstance(self.type, Union):
            return self.type.declaration()
        return f"{self.type.__str__()} {self.name}"


@dataclass(frozen=True, order=True)
class _BaseStruct(ComplexType):
    """Class representing a struct type."""

    members: Dict[int, ComplexTypeMember] = field(compare=False)
    type_specifier: ComplexTypeSpecifier

    def add_member(self, member: ComplexTypeMember):
        self.members[member.offset] = member

    def get_member_by_offset(self, offset: int) -> Optional[ComplexTypeMember]:
        return self.members.get(offset)

    def get_member_name_by_offset(self, offset: int) -> str:
        """Get the name of a member by its offset and gracefully handle unknown offsets."""
        member = self.get_member_by_offset(offset)
        if member is not None:
            return member.name
        else:
            logging.warning(f"Cannot get member name for type {self} at offset {offset}")
            return f"field_{hex(offset)}".replace("-", "minus_")

    def declaration(self) -> str:
        members = ";\n\t".join(self.members[k].declaration() for k in sorted(self.members.keys())) + ";"
        return f"{self.type_specifier.value} {self.name} {{\n\t{members}\n}}"

    def __hash__(self) -> int:
        # Because dict is not hashable, we need our own hash implementation
        return hash(repr(self))


@dataclass(frozen=True, order=True)
class Struct(_BaseStruct):
    type_specifier: ComplexTypeSpecifier = ComplexTypeSpecifier.STRUCT


@dataclass(frozen=True, order=True)
class Class(_BaseStruct):
    type_specifier: ComplexTypeSpecifier = ComplexTypeSpecifier.CLASS


@dataclass(frozen=True, order=True)
class Union(ComplexType):
    members: List[ComplexTypeMember] = field(compare=False)
    type_specifier = ComplexTypeSpecifier.UNION

    def add_member(self, member: ComplexTypeMember):
        self.members.append(member)

    def declaration(self) -> str:
        members = ";\n\t".join(x.declaration() for x in self.members) + ";"
        return f"{self.type_specifier.value} {self.name} {{\n\t{members}\n}}"

    def get_member_by_type(self, _type: Type) -> ComplexTypeMember:
        """Retrieve member of union by its type."""
        for member in self.members:
            if member.type == _type:
                return member

    def get_member_name_by_type(self, _type: Type) -> str:
        """Get the name of a member of a union by its type and gracefully handle unknown types."""
        member = self.get_member_by_type(_type)
        if member is not None:
            return member.name
        else:
            logging.warning(f"Cannot get member name for union {self}")
            return "unknown_field"

    def __hash__(self) -> int:
        # Because list is not hashable, we need our own hash implementation
        return hash(repr(self))


@dataclass(frozen=True, order=True)
class Enum(ComplexType):
    members: Dict[int, ComplexTypeMember] = field(compare=False)
    type_specifier = ComplexTypeSpecifier.ENUM

    def add_member(self, member: ComplexTypeMember):
        self.members[member.value] = member

    def get_name_by_value(self, value: int) -> Optional[str]:
        member = self.members.get(value)
        return member.name if member is not None else None

    def declaration(self) -> str:
        members = ",\n\t".join(f"{x.name} = {x.value}" for x in self.members.values())
        return f"{self.type_specifier.value} {self.name} {{\n\t{members}\n}}"

    def __hash__(self) -> int:
        # Because dict is not hashable, we need our own hash implementation
        return hash(repr(self))


@dataclass(frozen=True, order=True)
class ComplexTypeName(Type):
    """Class that store a name of a complex type. Used to prevent recursions when constructing
    struct(...) members of the same complex type"""

    name: str

    def __str__(self) -> str:
        return self.name


class UniqueNameProvider:
    """The purpose of this class is to provide unique names for types, as duplicate names can potentially be encountered in the lifting stage (especially anonymous structs, etc.)
    This class keeps track of all the names already used. If duplicates are found, they are renamed by appending suffixes with incrementing numbers.
    E.g. `classname`, `classname__2`, `classname__3`, ...
    Assumes that incoming names do not end with __{number}.
    """

    def __init__(self):
        self._name_to_count: Dict[str, int] = {}

    def get_unique_name(self, name: str) -> str:
        """This method returns the input name if it was unique so far.
        Otherwise it returns the name with an added incrementing suffix.
        In any case, the name occurence of the name is counted.
        Assumes that incoming names do not end with __{number}.
        """
        if name not in self._name_to_count:
            self._name_to_count[name] = 1
            return name
        else:
            self._name_to_count[name] += 1
            return f"{name}__{self._name_to_count[name]}"


class ComplexTypeMap:
    """A class in charge of storing complex custom/user defined types by their string representation"""

    def __init__(self):
        self._name_to_type_map: Dict[ComplexTypeName, ComplexType] = {}
        self._id_to_type_map: Dict[int, ComplexType] = {}

    def retrieve_by_name(self, typename: ComplexTypeName) -> Optional[ComplexType]:
        """Get complex type by name; used to avoid recursion."""
        return self._name_to_type_map.get(typename, None)

    def retrieve_by_id(self, id: int) -> Optional[ComplexType]:
        return self._id_to_type_map.get(id, None)

    def add(self, complex_type: ComplexType, type_id: int):
        """Add complex type to the mapping."""
        self._id_to_type_map[type_id] = complex_type
        self._name_to_type_map[complex_type.complex_type_name] = complex_type

    def pretty_print(self):
        for t in self._name_to_type_map.values():
            logging.error(t.declaration())

    def declarations(self) -> str:
        """Returns declarations of all complex types used in decompiled function."""
        return ";\n".join(t.declaration() for t in self._name_to_type_map.values()) + ";" if self._name_to_type_map else ""
