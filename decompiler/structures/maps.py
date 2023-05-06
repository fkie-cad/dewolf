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

    def remove_use(self, variable: Variable, instruction: Instruction) -> None:
        """Remove the instruction from the uses of a certain variable
        e.g. if the instruction has been changed and the variable is not being used by it anymore."""
        self.get(variable).discard(instruction)

    @property
    def used_variables(self) -> InsertionOrderedSet[Variable]:
        return InsertionOrderedSet(self._map.keys())
