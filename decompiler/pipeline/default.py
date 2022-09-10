"""Module defining the available pipelines."""

from decompiler.pipeline.controlflowanalysis import ExpressionSimplification, InstructionLengthHandler, ReadabilityBasedRefinement
from decompiler.pipeline.dataflowanalysis import (
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
from decompiler.pipeline.expressions import DeadComponentPruner, EdgePruner, GraphExpressionFolding, BitFieldComparisonUnrolling


CFG_STAGES = [
    GraphExpressionFolding,
    DeadComponentPruner,
    ExpressionPropagation,
    BitFieldComparisonUnrolling,
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
    DeadComponentPruner,
    GraphExpressionFolding,
    EdgePruner,
]

AST_STAGES = [ReadabilityBasedRefinement, ExpressionSimplification, InstructionLengthHandler]
