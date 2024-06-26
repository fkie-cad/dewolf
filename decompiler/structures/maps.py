from collections import defaultdict
from typing import DefaultDict, Dict, Iterator, Optional, Set, Tuple

from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.pseudo import Instruction, Variable
from decompiler.structures.pseudo.locations import InstructionLocation
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


class DefMap:
    def __init__(self) -> None:
        self._map: dict[Variable, InstructionLocation] = dict()

    def __contains__(self, definition: Variable) -> bool:
        return definition in self._map.keys()

    def __iter__(self) -> Iterator[tuple[Variable, InstructionLocation]]:
        for definition, instruction in self._map.items():
            yield definition, instruction

    def add(self, location: InstructionLocation) -> None:
        for definition in location.instruction.definitions:
            if definition in self._map:
                raise ValueError(
                    f"Program is not in SSA-Form. Variable {definition} is defined twice, "
                    f"once in instruction {self._map[definition]} and once in instruction {location}"
                )
            self._map[definition] = location

    def get(self, definition: Variable) -> InstructionLocation | None:
        return self._map.get(definition)

    def pop(self, definition: Variable) -> InstructionLocation:
        return self._map.pop(definition)

    def update_block_range(self, block: BasicBlock, start: int, len: int, new_len: int):
        # remove usages in range which got updated
        for definition, location in list(self._map.items()):
            if id(location.block) == id(block) and start <= location.index < start + len:
                self._map.pop(definition)

        # update definitions which got shifted because of range
        if len != new_len:
            dif = new_len - len
            for definition, location in self._map.items():
                if id(location.block) == id(block) and location.index >= start + len:
                    self._map[definition] = InstructionLocation(location.block, location.index + dif)

        # add new usages
        for index, instruction in list(enumerate(block.instructions))[start:(start + new_len)]:
            self.add(InstructionLocation(block, index))

    @property
    def defined_variables(self) -> InsertionOrderedSet[Variable]:
        return InsertionOrderedSet(self._map.keys())


class UseMap:
    def __init__(self) -> None:
        self._map: defaultdict[Variable, set[InstructionLocation]] = defaultdict(set)

    def __contains__(self, used: Variable) -> bool:
        return used in self._map.keys()

    def __iter__(self) -> Iterator[tuple[Variable, set[InstructionLocation]]]:
        for used, instructions in self._map.items():
            yield used, instructions

    def add(self, location: InstructionLocation) -> None:
        for used in location.instruction.requirements:
            self._map[used].add(location)

    def get(self, used: Variable) -> set[InstructionLocation]:
        return self._map[used]

    def update_block_range(self, block: BasicBlock, start: int, len: int, new_len: int):
        # remove usages in range which got updated
        if len > 0:
            for var in self._map:
                for location in list(self._map[var]):
                    if id(location.block) == id(block) and start <= location.index < start + len:
                        self._map[var].remove(location)

        # update usages which got shifted because of range
        if len != new_len:
            dif = new_len - len

            for var in self._map:
                for location in list(self._map[var]):
                    if id(location.block) == id(block) and location.index >= start + len:
                        self._map[var].remove(location)
                        self._map[var].add(InstructionLocation(location.block, location.index + dif))

        # add new usages
        if new_len > 0:
            for index, instruction in list(enumerate(block.instructions))[start:(start + new_len)]:
                self.add(InstructionLocation(block, index))

    def remove_use(self, variable: Variable, location: InstructionLocation) -> None:
        """Remove the instruction from the uses of a certain variable
        e.g. if the instruction has been changed and the variable is not being used by it anymore."""
        self.get(variable).discard(location)

    @property
    def used_variables(self) -> InsertionOrderedSet[Variable]:
        return InsertionOrderedSet(self._map.keys())
