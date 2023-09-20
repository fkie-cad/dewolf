import logging
from abc import ABC, abstractmethod

from decompiler.backend.cexpressiongenerator import CExpressionGenerator
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.collapse_add_neg import CollapseAddNeg
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.collapse_constants import CollapseConstants
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.collect_terms import CollectTerms
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.positive_constants import PositiveConstants
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.rule import SimplificationRule
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_redundant_reference import SimplifyRedundantReference
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_trivial_arithmetic import SimplifyTrivialArithmetic
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_trivial_bit_arithmetic import (
    SimplifyTrivialBitArithmetic,
)
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_trivial_logic_arithmetic import (
    SimplifyTrivialLogicArithmetic,
)
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.simplify_trivial_shift import SimplifyTrivialShift
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.sub_to_add import SubToAdd
from decompiler.pipeline.controlflowanalysis.expression_simplification.rules.term_order import TermOrder
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import CodeNode
from decompiler.structures.pseudo import Instruction, Operation
from decompiler.structures.visitors.substitute_visitor import SubstituteVisitor
from decompiler.task import DecompilerTask


class _ExpressionSimplificationBase(PipelineStage, ABC):

    def run(self, task: DecompilerTask):
        max_iterations = task.options.getint("expression-simplification.max_iterations")
        self._simplify_instructions(self._get_instructions(task), max_iterations)

    @abstractmethod
    def _get_instructions(self, task: DecompilerTask) -> list[Instruction]:
        pass

    @classmethod
    def _simplify_instructions(cls, instructions: list[Instruction], max_iterations: int):
        rule_sets = [
            ("pre-rules", _pre_rules),
            ("rules", _rules),
            ("post-rules", _post_rules)
        ]
        for rule_name, rule_set in rule_sets:
            # max_iterations is counted per rule_set
            iteration_count = cls._simplify_instructions_with_rule_set(instructions, rule_set, max_iterations)
            if iteration_count <= max_iterations:
                logging.info(f"Expression simplification took {iteration_count} iterations for {rule_name}")
            else:
                logging.warning(f"Exceeded max iteration count for {rule_name}")

    @classmethod
    def _simplify_instructions_with_rule_set(
            cls,
            instructions: list[Instruction],
            rule_set: list[SimplificationRule],
            max_iterations: int
    ) -> int:
        iteration_count = 0

        changes = True
        while changes:
            changes = False

            for rule in rule_set:
                for instruction in instructions:
                    additional_iterations = cls._simplify_instruction_with_rule(instruction, rule, max_iterations - iteration_count)
                    if additional_iterations > 0:
                        changes = True

                    iteration_count += additional_iterations
                    if iteration_count > max_iterations:
                        return iteration_count

        return iteration_count

    @classmethod
    def _simplify_instruction_with_rule(
            cls,
            instruction: Instruction,
            rule: SimplificationRule,
            max_iterations: int
    ) -> int:
        iteration_count = 0
        for expression in instruction.subexpressions():
            while True:
                # NOTE: By breaking out of the inner endless loop, we just continue with the next subexpression.
                if expression is None:
                    break
                if not isinstance(expression, Operation):
                    break

                substitutions = rule.apply(expression)
                if not substitutions:
                    break

                iteration_count += 1

                if iteration_count > max_iterations:
                    logging.warning("Took to many iterations for rule set to finish")
                    return iteration_count

                for i, (replacee, replacement) in enumerate(substitutions):
                    expression_gen = CExpressionGenerator()
                    logging.debug(
                        f"[{rule.__class__.__name__}] {i}. Substituting: '{replacee.accept(expression_gen)}'"
                        f" with '{replacement.accept(expression_gen)}' in '{expression.accept(expression_gen)}'"
                    )
                    instruction_repl = instruction.accept(SubstituteVisitor.identity(replacee, replacement))

                    # instruction.accept should never replace itself and consequently return none, because replacee is
                    # of type Expression and doesn't permit Instruction
                    assert instruction_repl is None

                    # This is modifying the expression tree, while we are iterating over it.
                    # This works because we are iterating depth first and only
                    # modifying already visited nodes.

                    # if expression got replaced, we need to update the reference
                    if replacee == expression:
                        expression = replacement

        return iteration_count


class ExpressionSimplificationCfg(_ExpressionSimplificationBase):
    """
    Pipeline stage that simplifies cfg expressions by applying a set of simplification rules.
    """

    name = "expression-simplification-cfg"

    def _get_instructions(self, task: DecompilerTask) -> list[Instruction]:
        return list(task.graph.instructions)


class ExpressionSimplificationAst(_ExpressionSimplificationBase):
    """
    Pipeline stage that simplifies ast expressions by applying a set of simplification rules.
    """

    name = "expression-simplification-ast"

    def _get_instructions(self, task: DecompilerTask) -> list[Instruction]:
        instructions = []
        for node in task.syntax_tree.topological_order():
            if isinstance(node, CodeNode):
                instructions.extend(node.instructions)

        return instructions


_pre_rules: list[SimplificationRule] = []
_rules: list[SimplificationRule] = [
    TermOrder(),
    SubToAdd(),
    SimplifyRedundantReference(),
    SimplifyTrivialArithmetic(),
    SimplifyTrivialBitArithmetic(),
    SimplifyTrivialLogicArithmetic(),
    SimplifyTrivialShift(),
    CollapseConstants(),
    CollectTerms(),
]
_post_rules: list[SimplificationRule] = [
    CollapseAddNeg(),
    PositiveConstants()
]
