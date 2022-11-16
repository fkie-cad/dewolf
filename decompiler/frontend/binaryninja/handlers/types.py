from binaryninja.types import (
    ArrayType,
    BoolType,
    CharType,
    FloatType,
    IntegerType,
    NamedTypeReferenceType,
    PointerType,
    StructureType,
    Type,
    VoidType,
    FunctionType,
    FunctionParameter,
)
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import CustomType, Float, Integer, Pointer, UnknownType, Type as pType, FunctionTypeDef


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
                NamedTypeReferenceType: self.lift_custom,
                StructureType: self.lift_custom,
                FunctionParameter: self.lift_function_parameter,
                FunctionType: self.lift_function_type,
                type(None): self.lift_none,
            }
        )

    def lift_none(self, _: None, **kwargs):
        """Lift a given None-type as an UnknownType object."""
        return UnknownType()

    def lift_custom(self, custom: Type, **kwargs) -> CustomType:
        """Lift custom types such as structs as a custom type."""
        return CustomType(str(custom), custom.width * self.BYTE_SIZE)

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

    def lift_function_parameter(self, parameter: FunctionParameter, **kwargs) -> pType:
        """Omit the location information and lift a parameter as its basic type."""
        return self._lifter.lift(parameter.type)

    def lift_function_type(self, function_type: FunctionType, **kwargs) -> FunctionTypeDef:
        """Lift an anonymous function signature such as void*(int, long)."""
        return FunctionTypeDef(
            function_type.width,
            self._lifter.lift(function_type.return_value),
            tuple(self._lifter.lift(param) for param in function_type.parameters)
        )
