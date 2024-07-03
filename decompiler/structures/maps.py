from array import array
from collections import defaultdict
from dataclasses import dataclass, field
from typing import DefaultDict, Dict, Iterable, Iterator, Optional, Set, Tuple

import line_profiler
import numpy as np
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.pseudo import Instruction, Variable
from decompiler.structures.pseudo.locations import InstructionLocation
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


@dataclass(frozen=True, slots=True)
class BasicBlockIdentyWrapper:
    block: BasicBlock

    def __eq__(self, other):
        return isinstance(other, BasicBlockIdentyWrapper) and self.block is other.block
    def __hash__(self):
        return hash(id(self.block))


class DefMap:
    def __init__(self) -> None:
        self._index_lookup: dict[BasicBlockIdentyWrapper, array[int]] = defaultdict(lambda: array('L'))
        self._map: dict[Variable, tuple[BasicBlockIdentyWrapper, int]] = dict()

    def __contains__(self, definition: Variable) -> bool:
        return definition in self._map.keys()

    def __iter__(self) -> Iterator[tuple[Variable, InstructionLocation]]:
        for definition, instruction in self._map.items():
            yield definition, instruction

    def add(self, location: InstructionLocation) -> None:
        block_wrapper = BasicBlockIdentyWrapper(location.block)

        indices = self._index_lookup[block_wrapper]
        indices.append(location.index)

        for definition in location.instruction.definitions:
            if definition in self._map:
                raise ValueError(
                    f"Program is not in SSA-Form. Variable {definition} is defined twice, "
                    f"once in instruction {self._map[definition]} and once in instruction {location}"
                )
            self._map[definition] = (block_wrapper, len(indices) - 1)

    def get(self, definition: Variable) -> InstructionLocation | None:
        if (location := self._map.get(definition)) is None:
            return None

        block_wrapper, index_id = location
        return InstructionLocation(block_wrapper.block, self._index_lookup[block_wrapper][index_id])

    def pop(self, definition: Variable) -> InstructionLocation:
        block_wrapper, index_id = self._map.pop(definition)
        return InstructionLocation(block_wrapper.block, self._index_lookup[block_wrapper][index_id])

    @line_profiler.profile
    def update_block_range(self, block: BasicBlock, start: int, length: int, new_len: int):
        block_identy_wrapper = BasicBlockIdentyWrapper(block)

        # remove definitions in range which got updated
        if length > 0:
            vars_to_remove = []
            for var, def_location in self._map.items():
                block_wrapper, index_id = def_location
                if block_wrapper.block is block and start <= self._index_lookup[block_wrapper][index_id] < start + length:
                    vars_to_remove.append(var)

            for var in vars_to_remove:
                self._map.pop(var)

        # update usages which got shifted because of range
        if length != new_len:
            dif = new_len - length
            locations = self._index_lookup[block_identy_wrapper]
            # shift_indices(locations, start + length, dif)
            locations_np = np.asarray(locations, copy=False)
            locations_np[locations_np >= start + length] += dif
            del locations_np

        # add new usages
        if new_len > 0:
            for index, instruction in enumerate(block.instructions[start:(start + new_len)]):
                self.add(InstructionLocation(block, start + index))

    @property
    def defined_variables(self) -> InsertionOrderedSet[Variable]:
        return InsertionOrderedSet(self._map.keys())


class UseMap:
    def __init__(self) -> None:
        self._index_lookup: dict[BasicBlockIdentyWrapper, array[int]] = defaultdict(lambda: array('L'))
        self._map: defaultdict[Variable, set[tuple[BasicBlockIdentyWrapper, int]]] = defaultdict(set)

    def __contains__(self, used: Variable) -> bool:
        return used in self._map.keys()

    def __iter__(self) -> Iterator[tuple[Variable, Iterator[InstructionLocation]]]:
        for used, locations in self._map.items():
            yield used, self._get_locations(locations)

    def add(self, location: InstructionLocation) -> None:
        block_wrapper = BasicBlockIdentyWrapper(location.block)

        indices = self._index_lookup[block_wrapper]
        indices.append(location.index)

        for used in location.instruction.requirements:
            self._map[used].add((block_wrapper, len(indices) - 1))

    def get(self, used: Variable) -> Iterator[InstructionLocation]:
        return self._get_locations(self._map[used])

    def _get_locations(self, locations: Iterable[tuple[BasicBlockIdentyWrapper, int]]) -> Iterator[InstructionLocation]:
        for block_wrapper, index in locations:
            yield InstructionLocation(block_wrapper.block, self._index_lookup[block_wrapper][index])

    @line_profiler.profile
    def update_block_range(self, block: BasicBlock, start: int, length: int, new_len: int):
        block_identy_wrapper = BasicBlockIdentyWrapper(block)

        # remove usages in range which got updated
        if length > 0:
            for var, used_locations in self._map.items():
                locations_to_remove = []
                for location in used_locations:
                    block_wrapper, index_id = location
                    if block_wrapper.block is block and start <= self._index_lookup[block_wrapper][index_id] < start + length:
                        locations_to_remove.append(location)

                used_locations.difference_update(locations_to_remove)

        # update usages which got shifted because of range
        if length != new_len:
            dif = new_len - length
            locations = self._index_lookup[block_identy_wrapper]
            # shift_indices(locations, start + length, dif)
            locations_np = np.asarray(locations, copy=False)
            locations_np[locations_np >= start + length] += dif
            del locations_np

        # add new usages
        if new_len > 0:
            for index, instruction in enumerate(block.instructions[start:(start + new_len)]):
                self.add(InstructionLocation(block, start + index))

    def remove_use(self, variable: Variable, location: InstructionLocation) -> None:
        raise NotImplemented()
        """Remove the instruction from the uses of a certain variable
        e.g. if the instruction has been changed and the variable is not being used by it anymore."""
        self.get(variable).discard(location)

    @property
    def used_variables(self) -> InsertionOrderedSet[Variable]:
        return InsertionOrderedSet(self._map.keys())
