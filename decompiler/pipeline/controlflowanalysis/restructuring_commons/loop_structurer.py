"""Module to structure Loops"""

from typing import Optional

from decompiler.pipeline.controlflowanalysis.restructuring_commons.ast_processor import LoopProcessor
from decompiler.pipeline.controlflowanalysis.restructuring_commons.loop_structuring_rules import (
    ConditionToSequenceRule,
    DoWhileLoopRule,
    LoopStructuringRule,
    NestedDoWhileLoopRule,
    SequenceRule,
    WhileLoopRule,
)
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, WhileLoopNode
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest


class LoopStructurer:
    """Class in charge of refining the endless loop represented by the AST with a certain root."""

    LoopRestructuringRules = [WhileLoopRule, DoWhileLoopRule, NestedDoWhileLoopRule, SequenceRule, ConditionToSequenceRule]

    def __init__(self, asforest: AbstractSyntaxForest):
        """initialize a new instance of the LoopStructurer with a abstract syntax forest and a root node."""
        self.asforest: AbstractSyntaxForest = asforest
        self._processor = LoopProcessor(asforest)

    @classmethod
    def refine_loop(cls, asforest: AbstractSyntaxForest, root: WhileLoopNode) -> AbstractSyntaxTreeNode:
        """Refine the ast subtree with the given loop-root in the given abstract syntax forest, i.e., we refine loops."""
        asforest.set_current_root(root)
        loop_structurer = cls(asforest)
        loop_structurer._structure_loop_type()
        new_root = asforest.current_root
        asforest.remove_current_root()
        return new_root

    def _structure_loop_type(self) -> None:
        """This function figures out the loop type and restructures it accordingly."""
        self._processor.preprocess_loop()
        while loop_structuring_rule := self.match_restructurer():
            loop_structuring_rule.restructure()
            self._processor.preprocess_loop()
        self._processor.postprocess_loop()

    def match_restructurer(self) -> Optional[LoopStructuringRule]:
        """Figure out the loop-restructuring rule."""
        if not self.asforest.current_root.is_endless_loop:
            return None

        for restructuring in self.LoopRestructuringRules:
            if restructuring.can_be_applied(self.asforest.current_root):
                return restructuring(self.asforest)
