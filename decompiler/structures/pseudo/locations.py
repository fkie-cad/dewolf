from dataclasses import dataclass

from decompiler.structures.graphs.basicblock import BasicBlock


@dataclass(frozen=True)
class InstructionLocation:
    block: BasicBlock
    index: int

    @property
    def instruction(self):
        return self.block.instructions[self.index]

    def __eq__(self, other):
        return isinstance(other, InstructionLocation) and id(self.block) == id(other.block) and self.index == other.index

    def __hash__(self):
        return hash((id(self.block), self.index))
