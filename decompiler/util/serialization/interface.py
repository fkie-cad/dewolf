"""Module implementing the base interface for all serializers."""
from abc import ABC, abstractmethod
from typing import Dict, Generic, TypeVar

from decompiler.structures.logic.logic_condition import LogicCondition

T = TypeVar("T")


class Serializer(ABC, Generic[T]):
    """Serializes and deserializes an object into and from a specific representation."""

    @abstractmethod
    def serialize(self, data: T) -> Dict:
        """Serialize the given object, returning its projected form."""
        pass

    @abstractmethod
    def deserialize(self, data: Dict) -> T:
        """Return an object from the given projection."""
        pass


class SerializerGroup(Serializer[T]):
    """Convenience class allowing a group of serializers to be utilized as one."""

    def __init__(self):
        """Create a group based on empty mappings for serializers."""
        self._serializers: Dict[str, Serializer] = {}
        self.new_context = LogicCondition.generate_new_context()

    def register(self, serializeable_class: type, serializer: Serializer):
        """Register the given serializer in the group based on data identifiers."""
        self._serializers[serializeable_class.__name__] = serializer

    def serialize(self, data: T) -> Dict:
        """Serialize the given data utilizing an registered serializer."""
        serializer = self._serializers.get(data.__class__.__name__, None)
        if not serializer:
            raise ValueError(f"Can not serialize an object of type {type(data)}!")
        return serializer.serialize(data)

    def deserialize(self, data: Dict) -> T:
        """Deserialize the given data utilizing an registered serializer."""
        deserializer = self._serializers.get(data.get("type", None), None)
        if not deserializer:
            raise ValueError(f"Can not serialize an object of type {type(data)}!")
        return deserializer.deserialize(data)
