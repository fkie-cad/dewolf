import logging
from abc import abstractmethod
from typing import Union, Optional

from binaryninja import BinaryView, StructureVariant
from binaryninja.types import (
    ArrayType,
    BoolType,
    CharType,
    EnumerationMember,
    EnumerationType,
    FloatType,
    FunctionType,
    IntegerType,
    NamedTypeReferenceType,
    PointerType,
    StructureMember,
    StructureType,
    Type,
    VoidType,
    WideCharType,
)
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import CustomType, Float, FunctionTypeDef, Integer, Pointer, UnknownType, Variable
from decompiler.structures.pseudo.complextypes import ComplexTypeMember, ComplexTypeName, Enum, Struct
from decompiler.structures.pseudo.complextypes import Union as Union_


class TypeHandler(Handler):
    """Handler lifting types from binaryninja mlil."""

    def register(self):
        self._lifter.HANDLERS.update(
            {
                IntegerType: self.lift_integer,
                FloatType: self.lift_float,
                ArrayType: self.lift_array,
                PointerType: self.lift_pointer,
                BoolType: self.lift_bool,
                VoidType: self.lift_void,
                CharType: self.lift_integer,
                WideCharType: self.lift_custom,
                NamedTypeReferenceType: self.lift_named_type_reference_type,
                StructureType: self.lift_struct,
                StructureMember: self.lift_struct_member,
                FunctionType: self.lift_function_type,
                EnumerationType: self.lift_enum,
                EnumerationMember: self.lift_enum_member,
                type(None): self.lift_none,
            }
        )

    def lift_none(self, _: None, **kwargs):
        """Lift a given None-type as an UnknownType object."""
        return UnknownType()

    def lift_custom(self, custom: Type, **kwargs) -> CustomType:
        """Lift custom types such as structs as a custom type."""
        return CustomType(str(custom), custom.width * self.BYTE_SIZE)

    def lift_named_type_reference_type(self, custom: NamedTypeReferenceType, **kwargs) -> Union[Type, CustomType]:
        """Lift a special type that binary ninja uses as placeholder for references on complex types like structs, unions, etc. as well
        as user-defined types. E.g.
        typedef PVOID HANDLE;
        causes HANDLE to be NamedTypeReferenceType, despite the fact that it is actually a void pointer.
        Binja does not attach named types to expressions, but this type instead that barely holds infos about name of the
        corresponding complex type. #TODO is it a case for typedefs also?
        We try to retrieve the original complex type from binary view using this placeholder type, and lift it correspondingly.
        """
        view: BinaryView = self._lifter.bv
        if defined_type := view.get_type_by_name(custom.name):  # actually should always be the case
            return self._lifter.lift(defined_type, name=str(custom.name))
        logging.warning(f"NamedTypeReferenceType {custom} was not found in binary view types.")
        return CustomType(str(custom), custom.width * self.BYTE_SIZE)

    def lift_enum(self, binja_enum: EnumerationType, name: str = None, **kwargs) -> Enum:
        """Lift enum type."""
        # TODO better way to get enum name
        enum_name = name if name else self._get_data_type_name(binja_enum, keyword="enum")
        enum = Enum(0, enum_name, {})
        for member in binja_enum.members:
            enum.add_member(self._lifter.lift(member))
        self._lifter.complex_types.add(enum)
        return enum

    def lift_enum_member(self, enum_member: EnumerationMember, **kwargs) -> ComplexTypeMember:
        """Lift enum member type."""
        return ComplexTypeMember(size=0, name=enum_member.name, offset=-1, type=Integer(32), value=self._lifter.lift(enum_member.value))

    def lift_struct(self, struct: StructureType, name: str = None, **kwargs) -> Union[Struct, ComplexTypeName]:
        """Lift struct or union type."""
        if struct.type == StructureVariant.StructStructureType:
            type_name = name if name else self._get_data_type_name(struct, keyword="struct")
            lifted_struct = Struct(struct.width * self.BYTE_SIZE, type_name, {})
        elif struct.type == StructureVariant.UnionStructureType:
            type_name = name if name else self._get_data_type_name(struct, keyword="union")
            lifted_struct = Union_(struct.width * self.BYTE_SIZE, type_name, [])
        else:
            raise RuntimeError(f"Unknown struct type {struct.type.name}")
        for member in struct.members:
            lifted_struct.add_member(self.lift_struct_member(member, type_name))
        self._lifter.complex_types.add(lifted_struct)
        return lifted_struct

    @abstractmethod
    def _get_data_type_name(self, complex_type: Union[StructureType, EnumerationType], keyword: str):
        string = complex_type.get_string()
        if keyword in string:
            return complex_type.get_string().split(keyword)[1]
        return string

    def lift_struct_member(self, member: StructureMember, parent_struct_name: str = None) -> ComplexTypeMember:
        # handle the case when struct member is a pointer on the same struct
        if structPtr := self._get_member_pointer_on_the_parent_struct(member, parent_struct_name):
            return structPtr
        else:
            # if member is an embedded struct/union, the name is already available
            member_type = self._lifter.lift(member.type, name=member.name)
        return ComplexTypeMember(0, name=member.name, offset=member.offset, type=member_type)

    @abstractmethod
    def _get_member_pointer_on_the_parent_struct(self, member: StructureMember, parent_struct_name: str) -> ComplexTypeMember:
        if (
            isinstance(member.type, PointerType)
            and (isinstance(member.type.target, StructureType) or isinstance(member.type.target, NamedTypeReferenceType))
            and member.type.target.name.__str__() == parent_struct_name
        ):
            member_struct_name = member.type.target.name.__str__()
            member_type = Pointer(ComplexTypeName(0, member_struct_name))
            return ComplexTypeMember(0, name=member.name, offset=member.offset, type=member_type)

    def lift_void(self, _, **kwargs) -> CustomType:
        """Lift the void-type (should only be used as function return type)."""
        return CustomType.void()

    def lift_integer(self, integer: IntegerType, **kwargs) -> Integer:
        """Lift the given integer type, such as long, unsigned int, etc."""
        return Integer(integer.width * self.BYTE_SIZE, signed=integer.signed.value)

    def lift_float(self, float: FloatType, **kwargs) -> Float:
        """Lift the given float or double type as a generic float type."""
        return Float(float.width * self.BYTE_SIZE)

    def lift_bool(self, bool: BoolType, **kwargs) -> CustomType:
        """Lift a boolean type (e.g. either TRUE or FALSE)."""
        return CustomType.bool()

    def lift_pointer(self, pointer: PointerType, **kwargs) -> Pointer:
        """Lift the given pointer type as a pointer on the nested type."""
        return Pointer(self._lifter.lift(pointer.target, parent=pointer), pointer.width * self.BYTE_SIZE)

    def lift_array(self, array: ArrayType, **kwargs) -> Pointer:
        """Lift an array as a pointer of the given type, omitting the size information."""
        return Pointer(self._lifter.lift(array.element_type))

    def lift_function_type(self, function_type: FunctionType, **kwargs) -> FunctionTypeDef:
        """Lift an anonymous function signature such as void*(int, long)."""
        return FunctionTypeDef(
            function_type.width * self.BYTE_SIZE,
            self._lifter.lift(function_type.return_value),
            tuple(self._lifter.lift(param.type) for param in function_type.parameters),
        )
