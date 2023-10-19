"""Module implementing the BinaryNinjaLifter of the binaryninja frontend."""
from logging import warning
from typing import Optional, Tuple, Union

from binaryninja import BinaryView, MediumLevelILInstruction, Type
from decompiler.frontend.lifter import ObserverLifter
from decompiler.structures.pseudo import DataflowObject, Tag, UnknownExpression, UnknownType

from ...structures.pseudo.complextypes import ComplexTypeMap, UniqueNameProvider
from .handlers import HANDLERS


class BinaryninjaLifter(ObserverLifter):
    """Lifter converting Binaryninja.mediumlevelil expressions to pseudo expressions."""

    def __init__(self, no_bit_masks: bool = True, bv: BinaryView = None):
        self.no_bit_masks = no_bit_masks
        self.bv: BinaryView = bv
        self.complex_types: ComplexTypeMap = ComplexTypeMap()
        self.unique_name_provider: UniqueNameProvider = UniqueNameProvider()
        for handler in HANDLERS:
            handler(self).register()

    @property
    def is_omitting_masks(self) -> bool:
        """Return a bool indicating whether bitmasks should be omitted."""
        return self.no_bit_masks

    def lift(self, expression: MediumLevelILInstruction, **kwargs) -> Optional[DataflowObject]:
        """Lift the given Binaryninja instruction to an expression."""
        handler = self.HANDLERS.get(expression.__class__, self.lift_unknown)
        if pseudo_expression := handler(expression, **kwargs):
            if isinstance(expression, MediumLevelILInstruction):
                pseudo_expression.tags = self.lift_tags(expression)
            return pseudo_expression

    def lift_unknown(self, expression, **kwargs) -> Union[UnknownType, UnknownExpression]:
        """Lift a unknown expression or type of a given expression."""
        if isinstance(expression, Type):
            warning(f"Can not lift unknown type {expression}")
            return UnknownType()
        warning(f"Can not lift {expression} ({type(expression)}")
        return UnknownExpression(str(expression))

    def lift_tags(self, instruction: MediumLevelILInstruction) -> Tuple[Tag, ...]:
        """Lift the Tags of the given Binaryninja instruction"""
        if function := instruction.function:
            binja_tags = function.source_function.view.get_tags_at(instruction.address)
            return tuple(Tag(tag.type.name, tag.data) for tag in binja_tags)
        else:
            warning(f"Cannot lift tags for instruction because binary view cannot be accessed.")
            return ()
