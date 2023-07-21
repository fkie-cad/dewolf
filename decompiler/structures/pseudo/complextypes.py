import logging
from abc import ABC
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from decompiler.structures.pseudo.typing import Type


class ComplexTypeSpecifier(Enum):
    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    CLASS = "class"


@dataclass(frozen=True, order=True)
class ComplexType(Type):
    size = 0
    name: str

    def __str__(self):
        return self.name


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

    def declaration(self):
        if isinstance(self.type, Union):
            return self.type.declaration()
        return f"{self.type.__str__()} {self.name}"


@dataclass(frozen=True, order=True)
class Struct(ComplexType):
    """Class representing a struct type."""

    # TODO size/width field
    members: Dict[int, ComplexTypeMember] = field(compare=False)
    type_specifier: ComplexTypeSpecifier = ComplexTypeSpecifier.STRUCT

    def add_member_(self, offset: int, name: str, type_: Type):
        self.members[offset] = ComplexTypeMember(0, name, offset, type_)

    def add_member(self, member: ComplexTypeMember):
        self.members[member.offset] = member

    def get_member_by_offset(self, offset: int) -> ComplexTypeMember:
        return self.members.get(offset)

    def declaration(self):
        members = ";\n\t".join(x.declaration() for x in self.members.values())+";"
        return f"{self.type_specifier.value} {self.name} {{\n\t{members}\n}};"


@dataclass(frozen=True, order=True)
class Union(ComplexType):
    members: List[ComplexTypeMember] = field(compare=False)
    type_specifier = ComplexTypeSpecifier.UNION

    def add_member(self, member: ComplexTypeMember):
        self.members.append(member)

    def add_member_(self, name: str, type_: Type):
        self.members.append(ComplexTypeMember(name, 0, type_))

    def declaration(self):
        members = ";\n\t".join(x.declaration() for x in self.members)
        return f"{self.type_specifier.value} {self.name} {{\n\t{members}\n}};"


@dataclass(frozen=True, order=True)
class Enum(ComplexType):
    members: Dict[int, ComplexTypeMember] = field(compare=False)
    type_specifier = ComplexTypeSpecifier.ENUM

    def add_member(self, member: ComplexTypeMember):
        self.members[member.value] = member

    def get_name_by_value(self, value: int) -> str:
        return self.members.get(value).name
        
    def declaration(self):
        members = ",\n\t".join(f"{x.name} = {x.value}" for x in self.members.values())
        return f"{self.type_specifier.value} {self.name} {{\n\t{members}\n}};"


@dataclass(frozen=True, order=True)
class ComplexTypeName(Type):
    """Class that store a name of a complex type. Used to prevent recursions when constructing
    struct(...) members of the same complex type"""

    name: str

    def __str__(self) -> str:
        return self.name


class ComplexTypeMap:
    """A class in charge of storing complex custom/user defined types by their string representation"""

    def __init__(self):
        self._name_to_type_map: Dict[ComplexTypeName, Struct] = {}

    def retrieve_by_name(self, typename: ComplexTypeName) -> Struct:
        return self._name_to_type_map.get(typename, None)

    def add(self, complex_type: Struct):
        self._name_to_type_map[ComplexTypeName(0, complex_type.name)] = complex_type

    def pretty_print(self):
        for t in self._name_to_type_map.values():
            logging.error(t.declaration())

    def declarations(self) -> str:
        return "\n".join(t.declaration() for t in self._name_to_type_map.values())
