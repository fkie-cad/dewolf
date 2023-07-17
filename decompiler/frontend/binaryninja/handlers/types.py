import logging
from typing import Union

from binaryninja import BinaryView, StructureVariant
from binaryninja.types import (
    ArrayType,
    BoolType,
    CharType,
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
from decompiler.structures.pseudo.complextypes import ComplexTypeMember, ComplexTypeName, Struct
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
                NamedTypeReferenceType: self.lift_custom,
                StructureType: self.lift_struct,
                StructureMember: self.lift_struct_member,
                FunctionType: self.lift_function_type,
                EnumerationType: self.lift_custom,
                type(None): self.lift_none,
            }
        )

    def lift_none(self, _: None, **kwargs):
        """Lift a given None-type as an UnknownType object."""
        return UnknownType()

    def lift_custom(self, custom: Type, **kwargs) -> CustomType:
        """Lift custom types such as structs as a custom type."""
        # TODO split lifting custom from lifting namedtypereferencetype
        view: BinaryView = self._lifter.bv
        if isinstance(custom, NamedTypeReferenceType) and (defined_type := view.get_type_by_name(custom.name)):
            return self._lifter.lift(defined_type, **kwargs)
        return CustomType(str(custom), custom.width * self.BYTE_SIZE)

    # def lift_union(self, union):
    #     logging.error("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    #     return CustomType(str(union), union.width * self.BYTE_SIZE)

    def lift_struct(self, struct: StructureType, name=None, incomplete=False, **kwargs) -> Union[Struct, ComplexTypeName]:
        """Lift struct type."""
        # TODO better way to get the name
        # TODO type width?
        if name:
            struct_name = name
        else:
            struct_name = self._get_data_type_name(struct)
        lifted_struct = None
        if struct.type == StructureVariant.StructStructureType:
            lifted_struct = Struct(0, struct_name, {})
        elif struct.type == StructureVariant.UnionStructureType:
            lifted_struct = Union_(0, struct_name, [])
        else:
            raise RuntimeError(f"Unk struct type {struct.type.name}")
        for m in struct.members:
            member = self.lift_struct_member(m, struct_name)
            lifted_struct.add_member(member)
        self._lifter.complex_types.add(lifted_struct)
        # logging.error(lifted_struct.declaration())
        return lifted_struct

    def _get_data_type_name(self, struct: StructureType):
        string = struct.get_string()
        if "struct" in string:
            return struct.get_string().split(" ")[1]
        return string

    def lift_struct_member(self, member: StructureMember, parent_struct_name: str = None) -> ComplexTypeMember:
        member_type = None

        # handle the case when struct member is a pointer on the same struct
        if (
            isinstance(member.type, PointerType)
            and (isinstance(member.type.target, StructureType) or isinstance(member.type.target, NamedTypeReferenceType))
            and member.type.target.name.__str__() == parent_struct_name
        ):
            member_struct_name = member.type.target.name.__str__()
            member_type = Pointer(ComplexTypeName(0, member_struct_name))

        else:
            # logging.error(f"Parent: {parent_struct_name}")
            # logging.error(f"Member {member}")
            member_type = self._lifter.lift(member.type, name=member.name)
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
