"""
Feature vectors of the candidate variable pairs of the conditional out-of-SSA.
"""

from collections import defaultdict
from enum import Enum
from itertools import combinations, permutations, product
from typing import DefaultDict, Dict, Iterator, List, NamedTuple, Set, Tuple

from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, FunctionSymbol, GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, Phi
from decompiler.structures.pseudo.operations import Call, Operation, OperationType

PhiPairs = Set[Tuple[Variable, Variable]]

VariablePair = Tuple[Variable, Variable]


class Feature(Enum):
    """
    The features of a candidate variable pair; the weights file names them by their value.

    "rhs variable" is the variable of the pair that occurs in the rhs of an assignment.
    """

    is_strong = "is_strong"  # the destination is a variable, the rhs is exactly the rhs variable (used once, only casts on its path)
    is_mid = "is_mid"  # the destination is a variable, the rhs is the rhs variable (used once, directly) and exactly one constant
    same_base_name = "same_base_name"  # both variables have the same name
    same_storage = "same_storage"  # both variables have the same Binary Ninja source type and storage (Variable.provenance)
    def_by_usage = "def_by_usage"  # the destination is a variable, the rhs contains exactly one distinct variable, all its uses are direct
    # Use kinds, multi-hot, only for assignment pairs: every kind of operation on the path from the rhs root to an occurrence of the
    # rhs variable is set, so x = f(*a) sets use_call and use_memory, and x = a + f(a) sets use_direct and use_call.
    use_direct = "use_direct"  # an occurrence has no call, memory access or address-of on its path
    use_call = "use_call"  # an occurrence is below a call (argument or call target)
    use_memory = "use_memory"  # an occurrence is below a dereference, field or member access
    use_address = "use_address"  # an occurrence is below an address-of
    same_phi = "same_phi"  # both variables occur in the same Phi-function
    # usage_n: the rhs of an assignment pair has exactly n distinct variables
    usage_1 = "usage_1"
    usage_2 = "usage_2"
    usage_3 = "usage_3"
    usage_4 = "usage_4"
    usage_5 = "usage_5"
    usage_6 = "usage_6"
    usage_7 = "usage_7"
    usage_8 = "usage_8"
    usage_9 = "usage_9"
    following_definitions = "following_definitions"  # the first variable is the previous definition of the second one's name
    same_rhs_source = "same_rhs_source"  # both variables are defined as copies of the same variable

    @staticmethod
    def usage(number_of_variables: int) -> "Feature":
        """Return usage_n for n = number_of_variables (1 to 9)."""
        return Feature(f"usage_{number_of_variables}")


# The features that are set for a pair; a missing feature is 0.
FeatureVector = Dict[Feature, int]


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
    if isinstance(variable_1, GlobalVariable) != isinstance(variable_2, GlobalVariable) or (
        isinstance(variable_1, GlobalVariable) and isinstance(variable_2, GlobalVariable) and variable_1.name != variable_2.name
    ):
        return True
    return variable_1.type != variable_2.type  # The renamer only merges variables of identical type


def get_phi_pairs(cfg: ControlFlowGraph) -> PhiPairs:
    """Return all ordered pairs of variables that co-occur in the same phi function."""
    phi_pairs: PhiPairs = set()
    for instruction in cfg.instructions:
        if isinstance(instruction, Phi):
            phi_pairs.update(permutations(set(instruction.definitions + instruction.requirements), 2))
    return phi_pairs


# The use kind that an operation adds to every variable below it; all other operations are transparent.
_USE_KIND_OF_OPERATION = {
    OperationType.call: Feature.use_call,
    OperationType.dereference: Feature.use_memory,
    OperationType.field: Feature.use_memory,
    OperationType.member_access: Feature.use_memory,
    OperationType.pointer: Feature.use_memory,  # unused by the frontend; a pointer access is a memory access
    OperationType.address: Feature.use_address,
}


def _get_use_kinds(expression: Expression) -> Tuple[Dict[Variable, Set[Feature]], Set[Variable]]:
    """
    Return the use kinds per variable and the variables that have an operation other than a cast on their path.

    Every kind of operation on the path from the root to an occurrence is part of the set, an occurrence without any such operation is
    a direct use. The sets of several occurrences are united.
    """
    use_kinds: Dict[Variable, Set[Feature]] = {}
    variables_below_operations: Set[Variable] = set()
    stack = [(expression, frozenset(), False)]
    while stack:
        subexpression, path_kinds, below_operation = stack.pop()
        if isinstance(subexpression, Variable):
            use_kinds.setdefault(subexpression, set()).update(path_kinds or {Feature.use_direct})
            if below_operation:
                variables_below_operations.add(subexpression)
        elif isinstance(subexpression, Operation):
            kinds = path_kinds
            if subexpression.operation in _USE_KIND_OF_OPERATION:
                kinds = path_kinds | {_USE_KIND_OF_OPERATION[subexpression.operation]}
            below = below_operation or subexpression.operation != OperationType.cast
            stack.extend((operand, kinds, below) for operand in subexpression)
    return use_kinds, variables_below_operations


def _set_features(checks: Dict[Feature, bool]) -> FeatureVector:
    """Return the feature vector that contains the features whose check is true."""
    return {feature: 1 for feature, is_set in checks.items() if is_set}


class ExpressionInfo(NamedTuple):
    """Summary of an expression that the feature vectors are computed from."""

    constant_count: int  # the callee of a call is not a constant
    use_kinds: Dict[Variable, Set[Feature]]  # variable -> use-kind features of the operations on the paths to its occurrences
    variables_below_operations: Set[Variable]  # variables with an operation other than a cast on the path to an occurrence
    has_bad_operation_strong: bool
    has_bad_operation_mid: bool
    variable_counts: Dict[Variable, int]  # variable -> number of occurrences


class ConditionalAttributeHelper:
    """Computes the feature vector of every candidate variable pair for the dependency graph of the conditional out-of-SSA."""

    _GOOD_OPERATIONS = frozenset({OperationType.cast})

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

    def iter_edge_data(self, cfg: ControlFlowGraph) -> Iterator[Tuple[VariablePair, FeatureVector]]:
        """
        Yield every candidate variable pair of the given control flow graph with its feature vector.

        There are three kinds of pairs: (lhs variable, rhs variable) of an assignment, (previous definition, next definition) of a name,
        and two variables that are both defined as a copy of the same variable. A pair may occur several times.
        """
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
                    for variable_1, variable_2 in product(previous_definition.variable_counts, lhs.variable_counts):
                        yield (variable_1, variable_2), {Feature.following_definitions: 1, **self._pair_features(variable_1, variable_2)}
            for variable_1, variable_2 in product(lhs.variable_counts, rhs.variable_counts):
                vector = {**self._assignment_features(lhs, rhs, variable_2), **self._pair_features(variable_1, variable_2)}
                yield (variable_1, variable_2), vector
        for definitions in definitions_of_source.values():
            for definition_1, definition_2 in combinations(definitions, 2):
                variable_1, variable_2 = next(iter(definition_1.variable_counts)), next(iter(definition_2.variable_counts))
                yield (variable_1, variable_2), {Feature.same_rhs_source: 1, **self._pair_features(variable_1, variable_2)}

    def _assignment_features(self, lhs: ExpressionInfo, rhs: ExpressionInfo, rhs_variable: Variable) -> FeatureVector:
        """Return the features of the assignment pair (lhs variable, rhs_variable): use kinds, usage_n, is_strong, is_mid, def_by_usage."""
        use_kinds = rhs.use_kinds[rhs_variable]
        vector: FeatureVector = dict.fromkeys(use_kinds, 1)
        number_of_rhs_variables = len(rhs.variable_counts)
        if number_of_rhs_variables <= 9:
            vector[Feature.usage(number_of_rhs_variables)] = 1
        if number_of_rhs_variables == 1:
            used_once = rhs.variable_counts[rhs_variable] == 1
            used_directly = use_kinds == {Feature.use_direct}
            vector.update(
                _set_features(
                    {
                        Feature.is_strong: used_once
                        and rhs.constant_count == 0
                        and rhs_variable not in rhs.variables_below_operations
                        and not lhs.has_bad_operation_strong,
                        Feature.is_mid: used_once and rhs.constant_count == 1 and used_directly and not lhs.has_bad_operation_mid,
                        Feature.def_by_usage: used_directly and not lhs.has_bad_operation_mid,
                    }
                )
            )
        return vector

    def _pair_features(self, variable_1: Variable, variable_2: Variable) -> FeatureVector:
        """Return the features that depend only on the two variables: same_base_name, same_storage, same_phi."""
        provenance_1, provenance_2 = variable_1.provenance, variable_2.provenance
        return _set_features(
            {
                Feature.same_base_name: variable_1.name == variable_2.name,
                Feature.same_storage: provenance_1 is not None
                and provenance_2 is not None
                and provenance_1.source_type is not None
                and provenance_1.storage is not None
                and provenance_1.source_type == provenance_2.source_type
                and provenance_1.storage == provenance_2.storage,
                Feature.same_phi: (variable_1, variable_2) in self._phi_pairs,
            }
        )

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
