"""
Feature vectors of the candidate variable pairs of the conditional out-of-SSA.
The order of FEATURES is the order of the coefficients in the weights file (conditional_weights.json).
"""

from abc import ABC
from collections import defaultdict
from itertools import combinations, permutations, product
from typing import DefaultDict, Dict, Iterator, List, NamedTuple, Set, Tuple

from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, FunctionSymbol, GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, Phi
from decompiler.structures.pseudo.operations import Call, Operation, OperationType

PhiPairs = Set[Tuple[Variable, Variable]]

# Feature names in vector order. "rhs variable" is the variable of the pair that occurs in the rhs of an assignment.
FEATURES = (
    "is_strong",  # the destination is a variable, the rhs is exactly the rhs variable (used once, only casts on its path)
    "is_mid",  # the destination is a variable, the rhs is the rhs variable (used once, directly) and exactly one constant
    "same_base_name",  # both variables have the same name
    "same_storage",  # both variables have the same Binary Ninja source type and storage (Variable.provenance)
    "def_by_usage",  # the destination is a variable, the rhs contains exactly one distinct variable, all its uses are direct
    # Use kinds, multi-hot, only for assignment pairs: every kind of operation on the path from the rhs root to an occurrence of the
    # rhs variable is set, so x = f(*a) sets use_call and use_memory, and x = a + f(a) sets use_direct and use_call.
    "use_direct",  # an occurrence has no call, memory access or address-of on its path
    "use_call",  # an occurrence is below a call (argument or call target)
    "use_memory",  # an occurrence is below a dereference, field or member access
    "use_address",  # an occurrence is below an address-of
    "same_phi",  # both variables occur in the same Phi-function
    *(f"usage_{n}" for n in range(1, 10)),  # usage_n: rhs has exactly n distinct variables
    "following_definitions",  # the first variable is the last definition of a name before the second, its next definition
    "same_rhs_source",  # both variables are defined as copies of the same variable
)
VECTOR_LENGTH = len(FEATURES)
INDEX_IS_STRONG = FEATURES.index("is_strong")
INDEX_IS_MID = FEATURES.index("is_mid")
INDEX_SAME_BASE_NAME = FEATURES.index("same_base_name")
INDEX_SAME_STORAGE = FEATURES.index("same_storage")
INDEX_DEF_BY_USAGE = FEATURES.index("def_by_usage")
INDEX_USE_DIRECT = FEATURES.index("use_direct")
INDEX_USE_CALL = FEATURES.index("use_call")
INDEX_USE_MEMORY = FEATURES.index("use_memory")
INDEX_USE_ADDRESS = FEATURES.index("use_address")
INDEX_IN_SAME_PHI = FEATURES.index("same_phi")
INDEX_USAGE_BASE = FEATURES.index("usage_1")  # usage_n is at INDEX_USAGE_BASE + (n - 1)
INDEX_FOLLOWING_DEFINITIONS = FEATURES.index("following_definitions")
INDEX_SAME_SOURCE = FEATURES.index("same_rhs_source")


def cannot_share_name(interference_graph: InterferenceGraph, variable_1: Variable, variable_2: Variable) -> bool:
    """
    True iff the two variables may not share a name.

    This must stay the same rule as ConditionalVariableRenamer._must_separate (which applies it to contracted nodes): a pair that this
    function lets through becomes a dependency-graph edge and a training pair, so it has to be a pair the renamer is able to merge.
    """
    if variable_1.type is None or variable_2.type is None:
        raise Exception("Encountered a None type variable in the SSA-Stage!")
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
    return False


def get_phi_pairs(cfg: ControlFlowGraph) -> PhiPairs:
    """Return all ordered pairs of variables that co-occur in the same phi function."""
    phi_pairs: PhiPairs = set()
    for instruction in cfg.instructions:
        if isinstance(instruction, Phi):
            phi_pairs.update(permutations(set(instruction.definitions + instruction.requirements), 2))
    return phi_pairs


# The use kind that an operation adds to every variable below it; all other operations are transparent.
_USE_KIND_OF_OPERATION = {
    OperationType.call: INDEX_USE_CALL,
    OperationType.dereference: INDEX_USE_MEMORY,
    OperationType.field: INDEX_USE_MEMORY,
    OperationType.member_access: INDEX_USE_MEMORY,
    OperationType.pointer: INDEX_USE_MEMORY,  # unused by the frontend; a pointer access is a memory access
    OperationType.address: INDEX_USE_ADDRESS,
}


def _get_use_kinds(expression: Expression) -> Tuple[Dict[Variable, Set[int]], Set[Variable]]:
    """
    Return the use kinds per variable and the variables that have an operation other than a cast on their path.

    The use kinds are the INDEX_USE_* constants. Every kind of operation on the path from the root to an occurrence is part of the set,
    an occurrence without any such operation is a direct use. The sets of several occurrences are united.
    """
    use_kinds: Dict[Variable, Set[int]] = {}
    variables_below_operations: Set[Variable] = set()
    stack = [(expression, frozenset(), False)]
    while stack:
        subexpression, path_kinds, below_operation = stack.pop()
        if isinstance(subexpression, Variable):
            use_kinds.setdefault(subexpression, set()).update(path_kinds or {INDEX_USE_DIRECT})
            if below_operation:
                variables_below_operations.add(subexpression)
        elif isinstance(subexpression, Operation):
            kinds = path_kinds
            if subexpression.operation in _USE_KIND_OF_OPERATION:
                kinds = path_kinds | {_USE_KIND_OF_OPERATION[subexpression.operation]}
            below = below_operation or subexpression.operation != OperationType.cast
            stack.extend((operand, kinds, below) for operand in subexpression)
    return use_kinds, variables_below_operations


class ExpressionInfo(NamedTuple):
    """Summary of an expression that the feature vectors are computed from."""

    constant_count: int  # the callee of a call is not a constant
    use_kinds: Dict[Variable, Set[int]]  # variable -> INDEX_USE_* of the operations on the paths to its occurrences
    variables_below_operations: Set[Variable]  # variables with an operation other than a cast on the path to an occurrence
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
            if isinstance(subexpression, Call) and isinstance(subexpression.function, FunctionSymbol):
                constant_count -= 1
            if isinstance(subexpression, Operation) and subexpression.operation not in self._GOOD_OPERATIONS:
                has_bad_operation_strong = True
            if isinstance(subexpression, Operation) and subexpression.operation in self._BAD_OPERATIONS:
                has_bad_operation_mid = True
        use_kinds, variables_below_operations = _get_use_kinds(expression)
        return ExpressionInfo(
            constant_count, use_kinds, variables_below_operations, has_bad_operation_strong, has_bad_operation_mid, variable_counts
        )

    def _common_template(
        self, lhs: ExpressionInfo, rhs: ExpressionInfo, is_following_definitions: bool = False, is_same_source: bool = False
    ) -> List[int]:
        """Return the feature vector entries that depend only on the two expressions, not on the variable pair."""
        number_of_rhs_variables = len(rhs.variable_counts)

        vector = [0] * VECTOR_LENGTH
        if not (is_following_definitions or is_same_source):
            if 1 <= number_of_rhs_variables <= 9:
                vector[INDEX_USAGE_BASE + number_of_rhs_variables - 1] = 1
        vector[INDEX_FOLLOWING_DEFINITIONS] = int(is_following_definitions)
        vector[INDEX_SAME_SOURCE] = int(is_same_source)
        return vector

    def fill_assignment_attrs(self, vector: List[int], lhs: ExpressionInfo, rhs: ExpressionInfo, rhs_variable: Variable) -> None:
        """
        Set the feature vector entries that are specific to an assignment pair (lhs variable, rhs_variable).

        These are the use kinds and is_strong, is_mid and def_by_usage; all of them look at the way rhs_variable is used.
        """
        use_kinds = rhs.use_kinds[rhs_variable]
        vector[INDEX_USE_DIRECT] = int(INDEX_USE_DIRECT in use_kinds)
        vector[INDEX_USE_CALL] = int(INDEX_USE_CALL in use_kinds)
        vector[INDEX_USE_MEMORY] = int(INDEX_USE_MEMORY in use_kinds)
        vector[INDEX_USE_ADDRESS] = int(INDEX_USE_ADDRESS in use_kinds)
        if len(rhs.variable_counts) != 1:
            return
        used_once = rhs.variable_counts[rhs_variable] == 1
        used_directly = use_kinds == {INDEX_USE_DIRECT}
        vector[INDEX_IS_STRONG] = int(
            used_once
            and rhs.constant_count == 0
            and rhs_variable not in rhs.variables_below_operations
            and not lhs.has_bad_operation_strong
        )
        vector[INDEX_IS_MID] = int(used_once and rhs.constant_count == 1 and used_directly and not lhs.has_bad_operation_mid)
        vector[INDEX_DEF_BY_USAGE] = int(used_directly and not lhs.has_bad_operation_mid)

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
            self.fill_assignment_attrs(vector, lhs, rhs, variable_2)
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
