from __future__ import annotations

from typing import AbstractSet, Any, Dict, Generic, Iterable, Iterator, List, Mapping, MutableSet, Optional, TypeVar

T = TypeVar("T")


class InsertionOrderedSet(dict, Generic[T], MutableSet):
    def __init__(self, iterable: Optional[Iterable[T]] = None, **kwargs: Dict[str, Any]):
        if iterable:
            super().__init__([(i, None) for i in iterable], **kwargs)
        else:
            super().__init__(**kwargs)

    def __iter__(self) -> Iterator[T]:
        yield from self.keys()

    def update(self, *args: Iterable[T], **kwargs: Dict[str, Any]):  # type: ignore
        # Type checking ignored as we cannot satisfy the dict.update signature.
        if kwargs:
            raise TypeError("update() takes no keyword arguments")
        for s in args:
            for e in s:
                self.add(e)

    def add(self, element: T):
        self[element] = None

    def pop(self, elem=None):
        if not elem:
            elem = next(iter(self.keys()))
        super().pop(elem, None)
        return elem

    def discard(self, element: T):
        self.pop(element)

    def __le__(self, other: AbstractSet[Any]):
        return all(e in other for e in self)

    def __lt__(self, other: AbstractSet[Any]):
        return self <= other and self != other

    def __ge__(self, other: AbstractSet[Any]):
        return all(e in self for e in other)

    def __gt__(self, other: AbstractSet[Any]):
        return self >= other and self != other

    def __eq__(self, other: object):
        if isinstance(other, set):
            return set(self.keys()) == other
        elif isinstance(other, dict):
            return self.keys() == other.keys()
        return False

    def __repr__(self):
        return "InsertionOrderedSet([%s])" % (", ".join(map(repr, self.keys())))

    def __str__(self):
        return "{%s}" % (", ".join(map(repr, self.keys())))

    difference = property(lambda self: self.__sub__)
    difference_update = property(lambda self: self.__isub__)
    intersection = property(lambda self: self.__and__)
    intersection_update = property(lambda self: self.__iand__)
    issubset = property(lambda self: self.__le__)
    issuperset = property(lambda self: self.__ge__)
    symmetric_difference = property(lambda self: self.__xor__)
    symmetric_difference_update = property(lambda self: self.__ixor__)
    union = property(lambda self: self.__or__)
