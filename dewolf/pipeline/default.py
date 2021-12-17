"""Module defining the available pipelines."""

from dewolf.pipeline.controlflowanalysis import ExpressionSimplification, InstructionLengthHandler, ReadabilityBasedRefinement
from dewolf.pipeline.dataflowanalysis import (
    ArrayAccessDetection,
    CommonSubexpressionElimination,
    DeadCodeElimination,
    DeadLoopElimination,
    DeadPathElimination,
    ExpressionPropagation,
    ExpressionPropagationFunctionCall,
    ExpressionPropagationMemory,
    IdentityElimination,
    RedundantCastsElimination,
    TypePropagation,
)

CFG_STAGES = [
    ExpressionPropagation,
    TypePropagation,
    DeadPathElimination,
    DeadLoopElimination,
    ExpressionPropagationMemory,
    ExpressionPropagationFunctionCall,
    DeadCodeElimination,
    RedundantCastsElimination,
    IdentityElimination,
    CommonSubexpressionElimination,
    ArrayAccessDetection,
    ExpressionSimplification,
]

AST_STAGES = [ReadabilityBasedRefinement, ExpressionSimplification, InstructionLengthHandler]
