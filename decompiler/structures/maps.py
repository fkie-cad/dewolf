from collections import defaultdict
from typing import DefaultDict, Dict, Iterator, Optional, Set, Tuple

from decompiler.structures.pseudo import Instruction, Variable
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


class DefMap:
    def __init__(self) -> None:
        self._map: Dict[Variable, Instruction] = dict()

    def __contains__(self, definition: Variable) -> bool:
        return definition in self._map.keys()

    def __iter__(self) -> Iterator[Tuple[Variable, Instruction]]:
        for definition, instruction in self._map.items():
            yield definition, instruction

    def add(self, instruction: Instruction) -> None:
        for definition in instruction.definitions:
            if definition in self._map:
                raise ValueError(
                    f"Program is not in SSA-Form. Variable {definition} is defined twice, "
                    f"once in instruction {self._map[definition]} and once in instruction {instruction}"
                )
            self._map[definition] = instruction

    def get(self, definition: Variable) -> Optional[Instruction]:
        if definition in self._map:
            return self._map[definition]
        return None

    @property
    def defined_variables(self) -> InsertionOrderedSet[Variable]:
        return InsertionOrderedSet(self._map.keys())


class UseMap:
    def __init__(self) -> None:
        self._map: DefaultDict[Variable, Set[Instruction]] = defaultdict(set)

    def __contains__(self, used: Variable) -> bool:
        return used in self._map.keys()

    def __iter__(self) -> Iterator[Tuple[Variable, Set[Instruction]]]:
        for used, instructions in self._map.items():
            yield used, instructions

    def add(self, instruction: Instruction) -> None:
        for used in instruction.requirements:
            self._map[used].add(instruction)

    def get(self, used: Variable) -> Set[Instruction]:
        return self._map[used]

    def update(self, used, instruction) -> None:
        """When instruction gets modified e.g. during propagation and does not contain certain variable anymore,
        remove that instruction from the uses of that variable and add it to the correspondent variable's uses"""
        if used not in instruction.requirements:
            uses = self.get(used)
            if instruction in uses:
                uses.remove(instruction)
            self.add(instruction)


    @property
    def used_variables(self) -> InsertionOrderedSet[Variable]:
        return InsertionOrderedSet(self._map.keys())
