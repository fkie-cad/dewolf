"""Module implementing the BinaryNinjaLifter of the binaryninja frontend."""
from logging import warning
from typing import Optional, Tuple

from binaryninja import MediumLevelILInstruction
from decompiler.frontend.lifter import ObserverLifter
from decompiler.structures.pseudo import DataflowObject, Tag, UnknownExpression

from .handlers import HANDLERS


class BinaryninjaLifter(ObserverLifter):
    """Lifter converting Binaryninja.mediumlevelil expressions to pseudo expressions."""

    def __init__(self, no_bit_masks: bool = True):
        self._no_bit_maks = no_bit_masks
        for handler in HANDLERS:
            handler(self).register()

    @property
    def is_omitting_masks(self) -> bool:
        """Return a bool indicating whether bitmasks should be omitted."""
        return self._no_bit_maks

    def lift(self, expression: MediumLevelILInstruction, **kwargs) -> Optional[DataflowObject]:
        """Lift the given Binaryninja instruction to an expression."""
        handler = self.HANDLERS.get(type(expression), self.lift_unknown)
        if pseudo_expression := handler(expression, **kwargs):
            if isinstance(expression, MediumLevelILInstruction):
                pseudo_expression.tags = self.lift_tags(expression)
            return pseudo_expression

    def lift_unknown(self, expression: MediumLevelILInstruction, **kwargs) -> UnknownExpression:
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
