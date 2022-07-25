from binaryninja.types import ArrayType, BoolType, CharType, FloatType, IntegerType, NamedTypeReferenceType, PointerType, StructureType, Type,  VoidType
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import CustomType, Float, Integer, Pointer, UnknownType


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
                type(None): self.lift_none,
            }
        )

    def lift_none(self, _: None, **kwargs):
        return UnknownType()

    def lift_custom(self, custom: Type, **kwargs) -> CustomType:
        return CustomType(str(custom), custom.width * self.BYTE_SIZE)

    def lift_void(self, _, **kwargs) -> CustomType:
        return CustomType.void()

    def lift_integer(self, integer: IntegerType, **kwargs) -> Integer:
        return Integer(integer.width * self.BYTE_SIZE, signed=integer.signed.value)

    def lift_float(self, float: FloatType, **kwargs) -> Float:
        return Float(float.width * self.BYTE_SIZE)

    def lift_bool(self, bool: BoolType, **kwargs) -> CustomType:
        return CustomType.bool()

    def lift_pointer(self, pointer: PointerType, **kwargs) -> Pointer:
        return Pointer(self._lifter.lift(pointer.target, parent=pointer), pointer.width * self.BYTE_SIZE)

    def lift_array(self, array: ArrayType, **kwargs) -> Pointer:
        return Pointer(self._lifter.lift(array.element_type))
