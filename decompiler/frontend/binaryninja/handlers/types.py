import logging

from binaryninja import BinaryView
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
from decompiler.structures.pseudo.typing import StructureType as PseudoStructureType, StructureMemberType as PseudoStructureMember


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
        if (defined_type:= view.get_type_by_name(custom.name)):
            return self._lifter.lift(defined_type, **kwargs)
        return CustomType(str(custom), custom.width * self.BYTE_SIZE)

    def lift_struct(self, struct: StructureType, **kwargs) -> PseudoStructureType:
        """Lift struct type."""
        # TODO better way to get the name
        # TODO type width?
        struct_name = struct.get_string().split(" ")[1]
        # members_dict = {m.offset: self.lift_struct_member(m) for m in struct.members}
        members_dict = {}
        for m in struct.members:
            members_dict[m.offset] = self.lift_struct_member(m)
        return PseudoStructureType(tag_name=struct_name, members=members_dict, size=0)

    def lift_struct_member(self, member: StructureMember) -> PseudoStructureMember:
        # TODO handle the case when struct member is a pointer on the same struct
        if isinstance(member.type, PointerType) and (isinstance(member.type.target, StructureType) or isinstance(member.type.target, NamedTypeReferenceType)):
            return CustomType("SomeStructTemp", size=0)
        return PseudoStructureMember(name=member.name, offset=member.offset, type=self._lifter.lift(member.type), size=0)

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
