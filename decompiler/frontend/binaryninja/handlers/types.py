from typing import Callable, Dict

from binaryninja.types import Type, IntegerType, FloatType, ArrayType, BoolType, VoidType, CharType, PointerType, NamedTypeReferenceType

from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import Pointer, Integer, CustomType, Float


class TypeHandler(Handler):
    def register(self):
        self._lifter.HANDLERS.update(
            {
                IntegerType: self.lift_integer,
                FloatType: self.lift_float,
                ArrayType: self.lift_pointer,
                PointerType: self.lift_pointer,
                BoolType: self.lift_bool,
                VoidType: self.lift_void,
                CharType: self.lift_integer,
                NamedTypeReferenceType: self.lift_unknown,
                type(None): self.lift_none,
            }
        )

    def lift_none(self, expr, **kwargs):
        return CustomType("unknown", 32)

    def lift_unknown(self, unknown: Type, **kwargs) -> CustomType:
        return CustomType(str(unknown), unknown.width * self.BYTE_SIZE)

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
