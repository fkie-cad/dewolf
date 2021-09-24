"""Module implementing the BinaryNinjaLifter of the binaryninja frontend."""
from typing import Optional, Tuple
from logging import warning

from binaryninja import MediumLevelILInstruction

from .handlers import HANDLERS
from dewolf.structures.pseudo import UnknownExpression, DataflowObject, Tag
from dewolf.frontend.lifter import ObserverLifter


class BinaryninjaLifter(ObserverLifter):
    """Lifter converting Binaryninja.mediumlevelil expressions to pseudo expressions."""

    def __init__(self, no_bit_masks: bool = True):
        self._no_bit_maks = no_bit_masks
        for handler in HANDLERS:
            handler(self).register()

    def lift(self, expression: MediumLevelILInstruction) -> Optional[DataflowObject]:
        """Lift the given Binaryninja instruction to an expression."""
        handler = self.HANDLERS.get(type(expression), self.lift_unknown)
        if pseudo_expression := handler(expression):
            if isinstance(expression, MediumLevelILInstruction):
                pseudo_expression.tags = self.lift_tags(expression)
            return pseudo_expression

    def lift_unknown(self, expression: MediumLevelILInstruction) -> UnknownExpression:
        with open('log.txt', 'a') as log:
            log.write(f"Can not lift {expression} ({type(expression)}\n")
        warning(f"Can not lift {expression} ({type(expression)}")
        return UnknownExpression(str(expression))

    def lift_tags(self, instruction: MediumLevelILInstruction) -> Tuple[Tag, ...]:
        """Lift the Tags of the given Binaryninja instruction"""
        if function := instruction.function:
            binja_tags = function.source_function.view.get_data_tags_at(instruction.address)
            return tuple(Tag(tag.type.name, tag.data) for tag in binja_tags)
        else:
            warning(f"Cannot lift tags for instruction because binary view cannot be accessed.")
            return ()