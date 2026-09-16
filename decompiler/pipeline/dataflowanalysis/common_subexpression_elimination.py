"""Module implementing common subexpression elimination."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from itertools import chain
from logging import info, warning
from typing import DefaultDict, Deque, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.graphs.nxgraph import NetworkXGraph
from decompiler.structures.pseudo.expressions import Constant, DataflowObject, Expression, Symbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, GenericBranch, Instruction, Phi, Relation
from decompiler.structures.pseudo.operations import Call, ListOperation, Operation, OperationType, UnaryOperation
from decompiler.task import DecompilerTask
from networkx import dfs_postorder_nodes


@dataclass(frozen=True, eq=False)
class CfgInstruction:
    """
    dataclass in charge of tracking the location of Instruction objects in the cfg

    -> The considered instruction, where block is the basic block where it is contained and index the position in the basic block.

    Note: Two instances with the same data will not be equal (because of eq=False).
    This way, eq and hash are way more performant, because at the time of writing this, eq and hash are very
    expensive on big instructions.

    eq=True would probably be nicer to use, but we don't actually create instances with the same data
    multiple times. (Rationale: initially just one instance is created per (block, index) pair.
    All further instances with the same (block, index) will have a less complex instruction than before)
    """

    instruction: Instruction
    block: BasicBlock

    @property
    def index(self):
        return next(index for index, instruction in enumerate(self.block.instructions) if id(instruction) == id(self.instruction))


@dataclass()
class DefinedVariable:
    """
    A dataclass for defined variables. The attribute variable is a defined variable and block the basic block where it is defined.
    """

    variable: Variable
    block: BasicBlock


def _subexpression_dfs(expression: DataflowObject) -> Iterator[Expression]:
    """Yield all subexpressions of the given instructions in a depth-first fashion."""
    remaining_subexpressions: Deque[Expression]
    if isinstance(expression, Branch):
        remaining_subexpressions = deque(expression.condition)
    else:
        remaining_subexpressions = deque(expression)
    while remaining_subexpressions:
        head: Expression = remaining_subexpressions.pop()
        remaining_subexpressions.extendleft(head)
        yield head


def _contains_dereference_operation(expression: DataflowObject) -> bool:
    """Check whether there is a dereference operation nested in the given expression."""
    for subexpression in chain([expression], _subexpression_dfs(expression)):
        if isinstance(subexpression, UnaryOperation) and subexpression.operation == OperationType.dereference:
            return True
    return False


def _contains_call(expression: DataflowObject) -> bool:
    for subexpression in chain([expression], _subexpression_dfs(expression)):
        if isinstance(subexpression, Call):
            return True
    return False


# Operators for which truncating a correctly computed wider result to N bits is guaranteed to equal what a native
# computation at N bits would have produced -- i.e. the low N bits of the result depend only on the low N bits of the
# operands. Used by ExistingSubexpressionReplacer to decide when reusing a wider, already-computed value via a downward
# cast is safe. Every other OperationType is deliberately excluded; see the class docstring for the reasoning.
_SIZE_TRUNCATION_SAFE_OPERATIONS = frozenset(
    {
        OperationType.plus,
        OperationType.minus,
        OperationType.multiply,
        OperationType.multiply_us,
        OperationType.negate,
        OperationType.left_shift,
        OperationType.bitwise_and,
        OperationType.bitwise_or,
        OperationType.bitwise_xor,
        OperationType.bitwise_not,
    }
)


class ExistingSubexpressionReplacer:
    """Class in charge of replacing subexpression that are already assigned to a variable, if these definition dominates the usage."""

    def __init__(
        self,
        cfg: ControlFlowGraph,
        dominator_tree: NetworkXGraph,
        defining_var_of: Optional[Dict[Expression, DefinedVariable]] = None,
    ):
        """Generate a new instance based on data parsed from a cfg."""
        self._cfg = cfg
        self._dominator_tree = dominator_tree
        self._defining_variable_of = defining_var_of if defining_var_of else dict()
        self._initialize_reachable_nodes_from_relation_defining()

    def _initialize_reachable_nodes_from_relation_defining(self) -> None:
        """
        Initializes the dictionary `_relations_for_aliased_variable` which maps to each variable-name defined via a relation all basic
        blocks that are reachable from this relation.
        """
        self._relations_for_aliased_variable: DefaultDict[str, Set[BasicBlock]] = defaultdict(set)
        for basic_block in self._cfg.nodes:
            if relations := set(inst for inst in basic_block.instructions if isinstance(inst, Relation)):
                reachable_nodes = set(self._cfg.iter_postorder(basic_block))
                for relation in relations:
                    self._relations_for_aliased_variable[relation.destination.name].update(reachable_nodes)

    def replace(self, head: BasicBlock) -> None:
        """
        If a subexpression is already assigned to a variable, then replace all occurrences that are dominated by this definition.

        -> Consider the dominator tree in pre-order
        -> We have to remove the keys (expressions) from the dictionary `replacements_for` that are no longer defined by a variable,
           when considering the next node.
        """
        stack = [head]
        new_keys_list: List[List[Expression]] = []
        while stack:
            current_node = stack.pop()
            if current_node == "remove_keys":
                self._remove_old_expressions(new_keys_list.pop())
                continue
            new_keys_list.append(self._replacements_for(current_node))
            stack += ["remove_keys"] + list(self._dominator_tree.get_successors(current_node))

    def _remove_old_expressions(self, old_keys: List[Expression]) -> None:
        """Removes all the dict entries, i.e., expressions, that are no longer defined when considering the next node."""
        for key in old_keys:
            del self._defining_variable_of[key]

    def _replacements_for(self, node: BasicBlock) -> List[Expression]:
        """
        Replace the existing subexpressions in the given node. All available subexpressions are contained in the dictionary
        self._defining_variable_of.
        """
        new_keys = list()
        for instruction in node.instructions:
            sorted_subexpressions = sorted({expr for expr in _subexpression_dfs(instruction)}, key=lambda x: x.complexity)
            while sorted_subexpressions:
                subexpr = sorted_subexpressions.pop()
                match = self._matching_definition_for(subexpr)
                if match is not None:
                    key, defined_variable = match
                    if self._does_not_jump_over_relation(instruction, node, key):
                        replacement = (
                            defined_variable.variable
                            if key.type == subexpr.type
                            else UnaryOperation(OperationType.cast, [defined_variable.variable], subexpr.type)
                        )
                        instruction.substitute(subexpr, replacement)
                        sorted_subexpressions = sorted({expr for expr in _subexpression_dfs(instruction)}, key=lambda x: x.complexity)
            if self._is_definition_of_new_subexpression(instruction):
                self._defining_variable_of[instruction.value] = DefinedVariable(instruction.destination, node)
                new_keys.append(instruction.value)
        return new_keys

    def _matching_definition_for(self, subexpr: Expression) -> Optional[Tuple[Expression, DefinedVariable]]:
        """
        Return the definition that should be used to replace `subexpr`, if any.

        -> An exact match (same expression, including type) is always preferred, exactly as before.
        -> Otherwise, if `subexpr` is an Operation whose operator is in _SIZE_TRUNCATION_SAFE_OPERATIONS, we also accept a
           structurally identical definition (same operator and operands) whose type is at least as wide as `subexpr`'s:
           reading such a wider, already-computed value and truncating it (a downward cast) to `subexpr`'s narrower type
           is guaranteed, for exactly these operators, to yield the same result the narrower expression would have
           computed itself, so no information is lost. A narrower definition is never used to replace a wider usage,
           since the reverse (an upward cast) can not safely reconstruct bits that were never computed.
        -> Among multiple sufficiently wide candidates we pick the tightest (smallest) one, to keep casts minimal.
        """
        if subexpr in self._defining_variable_of:
            return subexpr, self._defining_variable_of[subexpr]
        if not isinstance(subexpr, Operation) or subexpr.operation not in _SIZE_TRUNCATION_SAFE_OPERATIONS:
            return None
        candidates = [
            (key, defined_variable)
            for key, defined_variable in self._defining_variable_of.items()
            if type(key) is type(subexpr)
            and key.operation == subexpr.operation
            and key.operands == subexpr.operands
            and key.type.size >= subexpr.type.size
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda candidate: candidate[0].type.size)

    def _is_definition_of_new_subexpression(self, instruction: Instruction) -> bool:
        """
        Checks whether the given instruction is an Assignment that we want to consider for replacing the existing subexpression defined in
        this instruction.

        -> no Phi-functions, because we do not want to replace the value of Phi-functions with a variable.
        -> LHS must be a variable (that is defined)
        -> RHS must be an expression of complexity larger than 1 that is not defined so far, i.e., not in self._defining_variable_of
        -> Avoid memory problems by checking that no dereference operation on RHS, and the LHS variable is not aliased.
        """
        return (
            isinstance(instruction, Assignment)
            and not isinstance(instruction, Phi)
            and isinstance(instruction.destination, Variable)
            and instruction.value.complexity > 1
            and instruction.value not in self._defining_variable_of
            and not _contains_dereference_operation(instruction.value)
            and not _contains_call(instruction.value)
        )

    def _does_not_jump_over_relation(self, instruction: Instruction, node: BasicBlock, subexpr: Expression) -> bool:
        """
        When replacing the given subexpression in the given instruction, we have to check that either the variable defining the
        subexpression is not an aliased variable or that there is no Relation of this aliased variable on any path form the definition to
        the instruction. The given variable is the node that contains the instruction.
        -> node is the node where the instruction is contained in.
        """
        defining_variable = self._defining_variable_of[subexpr]
        if not defining_variable.variable.is_aliased:
            return True
        if node == defining_variable.block:
            return self._no_relation_between_instructions(node, defining_variable.variable, instruction)

        nodes_on_paths = self._get_all_nodes_on_paths_between(defining_variable.block, node)
        return not nodes_on_paths & self._relations_for_aliased_variable[defining_variable.variable.name]

    def _no_relation_between_instructions(self, node: BasicBlock, defining_variable: Variable, instruction: Instruction) -> bool:
        """
        Checks whether there is a relation between the instruction defining the given variable and the given instruction in the given basic
        block, i.e., True means that there is no relation and false that there is a relation."""
        if node not in self._relations_for_aliased_variable[defining_variable.name]:
            return True
        found_definition = False
        for inst in node.instructions:
            if not found_definition:
                found_definition = inst.destination == defining_variable
                continue
            if isinstance(inst, Relation) and inst.destination.name == defining_variable.name:
                return False
            if inst == instruction:
                return True
        return True

    def _get_all_nodes_on_paths_between(self, source: BasicBlock, sink: BasicBlock) -> Set[BasicBlock]:
        """Returns a set of all nodes that are contained in any path from source to sink except the sink node itself."""
        return set(self._cfg.iter_postorder(source)) & set(dfs_postorder_nodes(self._cfg._graph.reverse(copy=False), sink))


class DefinitionGenerator:
    """Class in charge of inserting definitions for expressions."""

    def __init__(
        self,
        expression_usages: DefaultDict[Expression, Counter[CfgInstruction]],
        dominator_tree: NetworkXGraph,
    ):
        """Generate a new instance based on data parsed from a cfg."""
        self._usages = expression_usages
        self._dominator_tree = dominator_tree

    @classmethod
    def from_cfg(cls, cfg: ControlFlowGraph) -> DefinitionGenerator:
        """Initialize a DefinitionGenerator utilizing the data of the given cfg."""
        usages: DefaultDict[Expression, Counter[CfgInstruction]] = defaultdict(Counter)
        for basic_block in cfg:
            for index, instruction in enumerate(basic_block.instructions):
                instruction_with_position = CfgInstruction(instruction, basic_block)
                for subexpression in _subexpression_dfs(instruction):
                    usages[subexpression][instruction_with_position] += 1
        return cls(usages, cfg.dominator_tree)

    @property
    def usages(self) -> DefaultDict[Expression, Counter[CfgInstruction]]:
        """Return a mapping from expressions to a set of instructions using them."""
        return self._usages

    def define(self, expression: Expression, variable: Variable):
        """Eliminate the given expression in the given blocks by inserting an intermediate variable."""
        basic_block, index = self._find_location_for_insertion(expression)
        for usage in self._usages[expression]:
            usage.instruction.substitute(expression, variable.copy())
        self._insert_definition(Assignment(variable, expression), basic_block, index)

    def _find_location_for_insertion(self, expression) -> Tuple[BasicBlock, int]:
        """
        Find a location where an intermediate variable could be inserted to avoid repeating expressions.

        The location should be the postdominator of all values required by the expression to be replaced,
        and a dominator of all blocks utilizing the expression to be replaced.
        """
        usage_blocks: Set[BasicBlock] = {instruction.block for instruction in self._usages[expression]}
        candidate: BasicBlock = next(iter(usage_blocks))
        while not self._is_common_dominator(candidate, usage_blocks) or self._is_invalid_dominator(candidate, expression):
            candidate = self._dominator_tree.get_predecessors(candidate)[0]
        return candidate, self._find_insertion_index(candidate, self._usages[expression].keys())

    def _is_common_dominator(self, candidate: BasicBlock, basic_blocks: Set[BasicBlock]) -> bool:
        """Check if the given candidate is the common dominator all of given basic blocks."""
        return all([self._dominator_tree.has_path(candidate, block) for block in basic_blocks]) or {candidate} == set(basic_blocks)

    def _is_invalid_dominator(self, basic_block: BasicBlock, expression: Expression) -> bool:
        """
        Check if the given dominator candidate is invalid.

        We consider a basic block an invalid dominator if it contains a usage for the given expression in a Phi Function.
        This is due to the fact that we can not find a valid place to insert our definition for the expression.
        """
        usages_in_the_same_block = [usage for usage in self._usages[expression] if usage.block == basic_block]
        return any([isinstance(usage.instruction, Phi) for usage in usages_in_the_same_block])

    def _insert_definition(self, instruction: Instruction, block: BasicBlock, index: int):
        """Insert a new intermediate definition for the given expression at the given location."""
        block.instructions.insert(index, instruction)
        cfg_instruction = CfgInstruction(instruction, block)
        for subexpression in _subexpression_dfs(instruction):
            self._usages[subexpression][cfg_instruction] += 1

    @staticmethod
    def _find_insertion_index(basic_block: BasicBlock, usages: Iterable[CfgInstruction]) -> int:
        """Find the first index in the given basic block where a definition could be inserted."""
        first_usage_index = min((usage.index for usage in usages if usage.block == basic_block), default=None)
        if first_usage_index is not None:
            return first_usage_index
        if not basic_block.instructions:
            return 0
        if isinstance(basic_block.instructions[-1], GenericBranch):
            return len(basic_block.instructions) - 1
        return len(basic_block.instructions)


class CommonSubexpressionElimination(PipelineStage):
    """A pipeline stage identifying subexpressions commonly used to generate a temporary variable in its place."""

    name = "common-subexpression-elimination"

    options = {
        "threshold": "The amount of occurrences a expression must reach to be eliminated.",
        "intra": "When set to yes, also search for duplicates in the same instruction.",
        "string_threshold": "The amount of occurrences a string expression must have to be eliminated",
        "min_string_length": "The amount of characters a string expression must have to be eliminated",
    }

    def __init__(self):
        self._threshold = None
        self._is_elimination_candidate = self._check_inter_instruction
        self._string_threshold = None
        self._min_string_length = None

    def run(self, task: DecompilerTask):
        """Run the stage, eliminating common subexpressions from the control flow graph."""
        self._threshold = max(task.options.getint(f"{self.name}.threshold"), 2)
        self._is_elimination_candidate = (
            self._check_intra_instruction if task.options.getboolean(f"{self.name}.intra") else self._check_inter_instruction
        )
        self._string_threshold = max(task.options.getint(f"{self.name}.string_threshold"), 2)
        self._min_string_length = task.options.getint(f"{self.name}.min_string_length", fallback=8)
        ExistingSubexpressionReplacer(task.graph, task.graph.dominator_tree).replace(task.graph.root)
        definition_generator = DefinitionGenerator.from_cfg(task.graph)
        self.eliminate_common_subexpressions(definition_generator)

    def eliminate_common_subexpressions(self, definition_generator: DefinitionGenerator):
        """Function which does the actual heavy lifting."""
        for index, replacee in enumerate(self._find_elimination_candidates(definition_generator.usages)):
            replacement = Variable(f"c{index}", replacee.type, ssa_label=0)
            try:
                definition_generator.define(replacee, replacement)
                info(f"[{self.name}] Eliminated {replacee} with {replacement}")
            except StopIteration:
                warning(f"[{self.name}] No dominating basic block could be found for {replacee}")

    def _find_elimination_candidates(self, usages: DefaultDict[Expression, Counter[CfgInstruction]]) -> Iterator[Expression]:
        """
        Iterate all expressions, yielding the expressions which should be eliminated.

        Always start with the most complex expressions first, to avoid eliminating their subexpressions first.
        """
        expressions_by_complexity = sorted(usages.keys(), reverse=True, key=lambda x: x.complexity)
        for expression in expressions_by_complexity:
            if self._is_cse_candidate(expression, usages):
                expression_usage = usages[expression]
                for subexpression in _subexpression_dfs(expression):
                    usages[subexpression].subtract(expression_usage)
                yield expression

    def _is_cse_candidate(self, expression: Expression, usages: DefaultDict[Expression, Counter[CfgInstruction]]):
        """Checks that we can add a common subexpression for the given expression."""
        return (
            self._is_elimination_candidate(expression, usages[expression])
            and not isinstance(expression, ListOperation)
            and not _contains_dereference_operation(expression)
            and not _contains_call(expression)
        )

    def _is_complex_string(self, expression: Expression) -> bool:
        """Check if expression is a string constant whose complexity is above the threshold."""
        if isinstance(expression, Constant) and not isinstance(expression, Symbol):
            if expression.pointee:
                return isinstance(expression.pointee.value, str) and len(expression.pointee.value) >= self._min_string_length
            else:
                return isinstance(expression.value, str) and len(expression.value) >= self._min_string_length
        return False

    def _check_inter_instruction(self, expression: Expression, instructions: Counter[CfgInstruction]) -> bool:
        """Check if the given expressions should be eliminated based on its global occurrences."""
        referencing_instructions_count = sum(1 for _, count in instructions.items() if count > 0)
        return (expression.complexity >= 2 and referencing_instructions_count >= self._threshold) or (
            self._is_complex_string(expression) and referencing_instructions_count >= self._string_threshold
        )

    def _check_intra_instruction(self, expression: Expression, instructions: Counter[CfgInstruction]) -> bool:
        """Check if this expression should be eliminated based on the amount of unique instructions utilizing it."""
        referencing_count = instructions.total()
        return (expression.complexity >= 2 and referencing_count >= self._threshold) or (
            self._is_complex_string(expression) and referencing_count >= self._string_threshold
        )
