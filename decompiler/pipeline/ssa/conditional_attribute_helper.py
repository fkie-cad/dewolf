"""
Shared attribute extraction for the conditional out-of-SSA ML pipeline.

Vector layout (indices are fixed and MUST match the `features` list of the weights file, see
conditional_weights.json):

  0  is_strong          rhs is exactly one variable, used once, no constants, no bad ops
  1  is_mid             rhs is one variable (used once) + exactly one constant, no bad ops
  2  same_base_name     both variables have the same name
  3  same_storage       both variables have the same Binary Ninja source_type and storage (Variable.provenance)
  4  def_by_usage       rhs contains exactly one distinct variable, no bad ops
  5  func_call          rhs is a call
  6  same_phi           both variables co-occur in some phi function
  7  usage_1            rhs has exactly 1 distinct variable
  8  usage_2            rhs has exactly 2 distinct variables
  9  usage_3            rhs has exactly 3 distinct variables
  10 usage_4            rhs has exactly 4 distinct variables
  11 usage_5            rhs has exactly 5 distinct variables
  12 usage_6            rhs has exactly 6 distinct variable
  13 usage_7            rhs has exactly 7 distinct variables
  14 usage_8            rhs has exactly 8 distinct variables
  15 usage_9            rhs has exactly 9 distinct variables
  16 following_definitions  the first variable is the last occurrence of a name, the second its next definition
  17 same_rhs_source        both variables are defined as copies of the same variable
"""

from abc import ABC
from collections import defaultdict
from itertools import combinations, permutations, product
from typing import DefaultDict, Dict, Iterator, List, NamedTuple, Set, Tuple

from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, Phi
from decompiler.structures.pseudo.operations import Call, Operation, OperationType

PhiPairs = Set[Tuple[Variable, Variable]]
INDEX_IS_STRONG = 0
INDEX_IS_MID = 1
INDEX_SAME_BASE_NAME = 2
INDEX_SAME_STORAGE = 3
INDEX_DEF_BY_USAGE = 4
INDEX_FUNC_CALL = 5
INDEX_IN_SAME_PHI = 6
INDEX_USAGE_BASE = 7  # usage_1..usage_9 live at INDEX_USAGE_BASE + (n - 1)
INDEX_FOLLOWING_DEFINITIONS = 16
INDEX_SAME_SOURCE = 17
VECTOR_LENGTH = 18
# Feature names in vector order; the weights file (conditional_weights.json) must list exactly these.
FEATURES = (
    "is_strong",
    "is_mid",
    "same_base_name",
    "same_storage",
    "def_by_usage",
    "func_call",
    "same_phi",
    *(f"usage_{n}" for n in range(1, 10)),
    "following_definitions",
    "same_rhs_source",
)
assert len(FEATURES) == VECTOR_LENGTH


def cannot_share_name(interference_graph: InterferenceGraph, variable_1: Variable, variable_2: Variable) -> bool:
    """
    True iff the two variables may not share a name.

    This must stay the same rule as ConditionalVariableRenamer._must_separate (which applies it to contracted nodes): a pair that this
    function lets through becomes a dependency-graph edge and a training pair, so it has to be a pair the renamer is able to merge.
    """
    if interference_graph.are_interfering(variable_1, variable_2):
        return True
    if (variable_1.is_aliased != variable_2.is_aliased) or (
        variable_1.is_aliased and variable_2.is_aliased and variable_1.name != variable_2.name
    ):
        return True
    if isinstance(variable_1, GlobalVariable) != isinstance(variable_2, GlobalVariable):
        return True
    if isinstance(variable_1, GlobalVariable) and isinstance(variable_2, GlobalVariable) and variable_1.name != variable_2.name:
        return True
    if variable_1.type != variable_2.type:
        # The renamer only merges variables of identical type (a class has one type), also if the sizes agree.
        return True
    if variable_1.type is None or variable_2.type is None:
        raise Exception("Encountered a None type variable in the SSA-Stage!")
    return False


def get_phi_pairs(cfg: ControlFlowGraph) -> PhiPairs:
    """Return all ordered pairs of variables that co-occur in the same phi function."""
    phi_pairs: PhiPairs = set()
    for instruction in cfg.instructions:
        if isinstance(instruction, Phi):
            phi_pairs.update(permutations(set(instruction.definitions + instruction.requirements), 2))
    return phi_pairs


class ExpressionInfo(NamedTuple):
    """Summary of an expression that the feature vectors are computed from."""

    constant_count: int
    is_call: bool
    has_bad_operation_strong: bool
    has_bad_operation_mid: bool
    variable_counts: Dict[Variable, int]  # variable -> number of occurrences


class AbstractAttributeHelper(ABC):
    """Feature extraction for variable pairs, shared by the renamer and external training code."""

    _GOOD_OPERATIONS = frozenset(
        {
            OperationType.cast,
        }
    )

    _BAD_OPERATIONS = frozenset(
        {
            OperationType.dereference,
            OperationType.address,
            OperationType.call,
            OperationType.pointer,
            OperationType.ternary,
            OperationType.list_op,
            OperationType.field,
            OperationType.member_access,
        }
    )

    def __init__(self, phi_pairs: PhiPairs) -> None:
        """:param phi_pairs: The ordered pairs of variables that co-occur in a phi function, see get_phi_pairs."""
        self._phi_pairs = phi_pairs

    def _get_expression_info(self, expression: Expression) -> ExpressionInfo:
        """Count the variables and constants of the given expression and check it for operations that weaken a dependency."""
        constant_count = 0
        has_bad_operation_strong = False
        has_bad_operation_mid = False
        variable_counts: Dict[Variable, int] = {}
        for subexpression in expression.subexpressions():
            if isinstance(subexpression, Variable):
                variable_counts[subexpression] = variable_counts.get(subexpression, 0) + 1
            elif isinstance(subexpression, Constant):
                constant_count += 1
            if isinstance(subexpression, Operation) and subexpression.operation not in self._GOOD_OPERATIONS:
                has_bad_operation_strong = True
            if isinstance(subexpression, Operation) and subexpression.operation in self._BAD_OPERATIONS:
                has_bad_operation_mid = True
        return ExpressionInfo(
            constant_count, isinstance(expression, Call), has_bad_operation_strong, has_bad_operation_mid, variable_counts
        )

    def _common_template(
        self, lhs: ExpressionInfo, rhs: ExpressionInfo, is_following_definitions: bool = False, is_same_source: bool = False
    ) -> List[int]:
        """Return the feature vector entries that depend only on the two expressions, not on the variable pair."""
        number_of_rhs_variables = len(rhs.variable_counts)
        single_rhs_variable_once = number_of_rhs_variables == 1 and next(iter(rhs.variable_counts.values())) == 1
        no_bad_operations_strong = not lhs.has_bad_operation_strong and not rhs.has_bad_operation_strong
        no_bad_operations_mid = not lhs.has_bad_operation_mid and not rhs.has_bad_operation_mid

        vector = [0] * VECTOR_LENGTH
        if not (is_following_definitions or is_same_source):
            vector[INDEX_IS_STRONG] = int(single_rhs_variable_once and rhs.constant_count == 0 and no_bad_operations_strong)
            vector[INDEX_IS_MID] = int(single_rhs_variable_once and rhs.constant_count == 1 and no_bad_operations_mid)
            vector[INDEX_DEF_BY_USAGE] = int(number_of_rhs_variables == 1 and no_bad_operations_mid)
            vector[INDEX_FUNC_CALL] = int(rhs.is_call)
            if 1 <= number_of_rhs_variables <= 9:
                vector[INDEX_USAGE_BASE + number_of_rhs_variables - 1] = 1
        vector[INDEX_FOLLOWING_DEFINITIONS] = int(is_following_definitions)
        vector[INDEX_SAME_SOURCE] = int(is_same_source)
        return vector

    def _fill_pair_attrs(self, vector: List[int], variable_1: Variable, variable_2: Variable) -> None:
        """Set the feature vector entries that depend on the variable pair itself."""
        vector[INDEX_SAME_BASE_NAME] = int(variable_1.name == variable_2.name)
        vector[INDEX_SAME_STORAGE] = int(
            variable_1.provenance is not None
            and variable_2.provenance is not None
            and variable_1.provenance.source_type is not None
            and variable_2.provenance.source_type is not None
            and variable_1.provenance.storage is not None
            and variable_2.provenance.storage is not None
            and variable_1.provenance.source_type == variable_2.provenance.source_type
            and variable_1.provenance.storage == variable_2.provenance.storage
        )
        vector[INDEX_IN_SAME_PHI] = int((variable_1, variable_2) in self._phi_pairs)

    def _assignments_in_dominator_order(self, cfg: ControlFlowGraph) -> Iterator[Tuple[Assignment, Dict[str, ExpressionInfo]]]:
        """
        Yield every assignment together with the last dominating definition per variable name.

        The caller updates the dict; changes are only visible to blocks dominated by the current one.
        """
        if cfg.root is None:
            return
        dominator_tree = cfg.dominator_tree
        stack = [(cfg.root, {})]
        while stack:
            basic_block, inherited_definitions = stack.pop()
            last_definition = dict(inherited_definitions)
            for instruction in basic_block:
                if isinstance(instruction, Assignment):
                    yield instruction, last_definition
            for child in dominator_tree.get_successors(basic_block):
                stack.append((child, last_definition))


class ConditionalAttributeHelper(AbstractAttributeHelper):
    """Used during conditional out-of-SSA dependency-graph construction to score every candidate variable pair."""

    def iter_edge_data(self, cfg: ControlFlowGraph) -> Iterator[Tuple[List[int], Tuple[Variable, Variable]]]:
        """Yield the feature vector of every candidate variable pair of the given control flow graph."""
        definitions_of_source: DefaultDict[Variable, List[ExpressionInfo]] = defaultdict(list)
        for assignment, last_definition in self._assignments_in_dominator_order(cfg):
            lhs = self._get_expression_info(assignment.destination)
            rhs = self._get_expression_info(assignment.value)
            if not rhs.has_bad_operation_strong and len(rhs.variable_counts) == 1 and len(lhs.variable_counts) == 1:
                definitions_of_source[next(iter(rhs.variable_counts))].append(lhs)
            if not lhs.has_bad_operation_strong and len(lhs.variable_counts) == 1:
                name = next(iter(lhs.variable_counts)).name
                previous_definition = last_definition.get(name)
                last_definition[name] = lhs
                if previous_definition is not None:
                    yield from self._following_definition_pairs(previous_definition, lhs)
            if lhs.variable_counts and rhs.variable_counts:
                yield from self._assignment_pairs(lhs, rhs)
        yield from self._same_source_pairs(definitions_of_source)

    def _following_definition_pairs(
        self, previous_definition: ExpressionInfo, definition: ExpressionInfo
    ) -> Iterator[Tuple[List[int], Tuple[Variable, Variable]]]:
        """Yield the pairs of a definition and the previous dominating definition of a variable with the same name."""
        template = self._common_template(previous_definition, definition, is_following_definitions=True)
        for variable_1, variable_2 in product(previous_definition.variable_counts, definition.variable_counts):
            vector = template.copy()
            self._fill_pair_attrs(vector, variable_1, variable_2)
            yield vector, (variable_1, variable_2)

    def _assignment_pairs(self, lhs: ExpressionInfo, rhs: ExpressionInfo) -> Iterator[Tuple[List[int], Tuple[Variable, Variable]]]:
        """Yield the pairs of a variable on the left-hand side and a variable on the right-hand side of an assignment."""
        template = self._common_template(lhs, rhs)
        for variable_1, variable_2 in product(lhs.variable_counts, rhs.variable_counts):
            vector = template.copy()
            self._fill_pair_attrs(vector, variable_1, variable_2)
            yield vector, (variable_1, variable_2)

    def _same_source_pairs(
        self, definitions_of_source: DefaultDict[Variable, List[ExpressionInfo]]
    ) -> Iterator[Tuple[List[int], Tuple[Variable, Variable]]]:
        """Yield the pairs of variables that are both defined as a copy of the same variable."""
        for definitions in definitions_of_source.values():
            for definition_1, definition_2 in combinations(definitions, 2):
                variable_1 = next(iter(definition_1.variable_counts))
                variable_2 = next(iter(definition_2.variable_counts))
                vector = self._common_template(definition_1, definition_2, is_same_source=True)
                self._fill_pair_attrs(vector, variable_1, variable_2)
                yield vector, (variable_1, variable_2)
