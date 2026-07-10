"""Handler lifting Ghidra DataType objects to dewolf pseudo types."""

import logging
from typing import Optional

from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import ArrayType, CustomType, Float, FunctionTypeDef, Integer, Pointer, Type, UnknownType
from decompiler.structures.pseudo.complextypes import Class, ComplexTypeMember, ComplexTypeName, Enum, Struct
from decompiler.structures.pseudo.complextypes import Union as PseudoUnion

BYTE_SIZE = 8


class TypeHandler(Handler):
    """Lift ghidra data types onto pseudo types."""

    _class_cache: dict = {}

    def register(self) -> None:
        self._lifter.lift_type = self.lift_type
        self._lifter.HANDLERS[type(None)] = self.lift_none

    @classmethod
    def _cls(cls, simple_name: str):
        """Resolve a ghidra DataType class by simple name, tolerating missing classes."""
        if simple_name in cls._class_cache:
            return cls._class_cache[simple_name]
        try:
            module = __import__("ghidra.program.model.data", fromlist=[simple_name])
            resolved = getattr(module, simple_name)
        except Exception:  # noqa: BLE001
            resolved = None
        cls._class_cache[simple_name] = resolved
        return resolved

    def _is(self, dtype, simple_name: str) -> bool:
        cls = self._cls(simple_name)
        return cls is not None and isinstance(dtype, cls)

    def lift_none(self, _: None, **kwargs) -> UnknownType:
        return UnknownType()

    def lift_type(self, dtype, **kwargs) -> Optional[Type]:
        """Lift a ghidra DataType (or None) to a pseudo type."""
        if dtype is None:
            return UnknownType()
        try:
            return self._lift_type(dtype)
        except Exception as exc:  # noqa: BLE001
            logging.warning("[GhidraTypeHandler] failed to lift %r: %s", dtype, exc)
            return self._fallback_by_size(self._length_of(dtype))

    def _lift_type(self, dtype):
        # Resolve typedefs to their underlying type.
        if self._is(dtype, "TypeDefDataType"):
            try:
                base = dtype.getBaseDataType() or dtype.getDataType()
                return self._lift_type(base)
            except Exception:  # noqa: BLE001
                pass

        if self._is(dtype, "VoidDataType"):
            return CustomType.void()

        if self._is(dtype, "BooleanDataType"):
            return CustomType.bool()

        if self._is(dtype, "FloatDataType"):
            return Float(self._length_of(dtype) * BYTE_SIZE)

        if self._is(dtype, "CharDataType") or self._is(dtype, "WideCharDataType") or self._is(dtype, "UnsignedCharDataType"):
            return Integer.char()

        if self._is(dtype, "PointerDataType"):
            base = dtype.getDataType()
            return Pointer(self.lift_type(base), self._length_of(dtype) * BYTE_SIZE)

        if self._is(dtype, "ArrayDataType"):
            base = dtype.getDataType()
            return ArrayType(self.lift_type(base), dtype.getNumElements())

        if self._is(dtype, "StringDataType"):
            return Pointer(Integer.char(), 64 if self._length_of(dtype) == 8 else 32)

        if self._is(dtype, "StructureDataType"):
            return self._lift_struct(dtype)
        if self._is(dtype, "UnionDataType"):
            return self._lift_union(dtype)
        if self._is(dtype, "EnumDataType"):
            return self._lift_enum(dtype)

        if self._is(dtype, "FunctionDefinitionDataType"):
            return self._lift_function_type(dtype)

        # Integer / byte / undefined / default -> integer of appropriate size/signedness.
        return self._lift_integer_like(dtype)

    def _lift_integer_like(self, dtype) -> Integer:
        size = self._length_of(dtype)
        signed = self._is_signed(dtype)
        bits = (size or 4) * BYTE_SIZE
        return Integer(bits, signed=signed)

    @staticmethod
    def _length_of(dtype) -> int:
        try:
            length = dtype.getLength()
        except Exception:  # noqa: BLE001
            length = 0
        if length is None or length < 0:
            return 0
        return int(length)

    @staticmethod
    def _is_signed(dtype) -> bool:
        name = dtype.getClass().getSimpleName()
        if "Unsigned" in name:
            return False
        if name in ("ByteDataType", "Undefined", "UndefinedDataType", "DefaultDataType"):
            return False
        try:
            if dtype.isSigned():
                return True
        except Exception:  # noqa: BLE001
            pass
        return True

    def _lift_struct(self, dtype) -> Struct:
        type_id = self._identity(dtype)
        cached = self._lifter.complex_types.retrieve_by_id(type_id)
        if cached is not None:
            return cached
        name = dtype.getName() or "struct"
        struct = Struct(self._length_of(dtype) * BYTE_SIZE, name, {})
        self._lifter.complex_types.add(struct, type_id)
        for i in range(dtype.getNumComponents()):
            comp = dtype.getComponent(i)
            member = ComplexTypeMember(
                size=(comp.getLength() or 0) * BYTE_SIZE,
                name=comp.getFieldName() or f"field_{comp.getOffset():x}",
                offset=int(comp.getOffset()),
                type=self.lift_type(comp.getDataType()),
            )
            struct.add_member(member)
        return struct

    def _lift_union(self, dtype) -> PseudoUnion:
        type_id = self._identity(dtype)
        cached = self._lifter.complex_types.retrieve_by_id(type_id)
        if cached is not None:
            return cached
        name = dtype.getName() or "union"
        union = PseudoUnion(self._length_of(dtype) * BYTE_SIZE, name, [])
        self._lifter.complex_types.add(union, type_id)
        for i in range(dtype.getNumComponents()):
            comp = dtype.getComponent(i)
            member = ComplexTypeMember(
                size=(comp.getLength() or 0) * BYTE_SIZE,
                name=comp.getFieldName() or f"field_{i}",
                offset=-1,
                type=self.lift_type(comp.getDataType()),
            )
            union.add_member(member)
        return union

    def _lift_enum(self, dtype) -> Enum:
        type_id = self._identity(dtype)
        cached = self._lifter.complex_types.retrieve_by_id(type_id)
        if cached is not None:
            return cached
        name = dtype.getName() or "enum"
        enum = Enum(self._length_of(dtype) * BYTE_SIZE, name, {})
        self._lifter.complex_types.add(enum, type_id)
        for value, ename in dtype.getNames().items():
            enum.add_member(ComplexTypeMember(size=0, name=str(ename), offset=-1, type=Integer.int32_t(), value=int(value)))
        return enum

    def _lift_function_type(self, dtype) -> FunctionTypeDef:
        # FunctionTypeDef(size, return_type, parameters)
        try:
            ret = self.lift_type(dtype.getReturnType())
            params = tuple(self.lift_type(p.getDataType()) for p in dtype.getArguments())
        except Exception:  # noqa: BLE001
            ret, params = UnknownType(), ()
        size = self._length_of(dtype) * BYTE_SIZE or 64
        return FunctionTypeDef(size, ret, params)

    @staticmethod
    def _identity(dtype):
        # Mirror the BN handler: use the (Java) object hash as a stable cache key.
        return hash(dtype)

    def _fallback_by_size(self, size: int) -> Integer:
        bits = (size or 4) * BYTE_SIZE
        return Integer(bits, signed=False)
