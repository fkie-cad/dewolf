"""
Feature vectors of the candidate variable pairs of the conditional out-of-SSA.
"""

from __future__ import annotations

from collections import defaultdict
from enum import Enum
from itertools import combinations, permutations, product
from typing import DefaultDict, Dict, Iterator, List, NamedTuple, Optional, Set, Tuple

from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, FunctionSymbol, GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, Phi
from decompiler.structures.pseudo.operations import Call, Operation, OperationType, UnaryOperation

PhiPairs = Set[Tuple[Variable, Variable]]

VariablePair = Tuple[Variable, Variable]


class Feature(Enum):
    """
    The features of a candidate variable pair; the weights file names them by their value.

    There are three groups, the comment of each feature starts with its group:
        - pair:       depends only on the two variables, set for every pair (see ConditionalAttributeHelper._edge)
        - assignment: depends on the assignment of the pair, only for assignment pairs (see ConditionalAttributeHelper._assignment_features)
        - kind:       marks the kind of the pair; an assignment pair has no kind feature
    The member order is the column order of the training data, so it is not grouped.
    "rhs variable" is the variable of the pair that occurs in the rhs of the assignment.
    """

    is_strong = "is_strong"  # assignment: the destination is a variable, the rhs is exactly the rhs variable (only casts on its path)
    is_mid = "is_mid"  # assignment: the destination is a variable, the rhs is the rhs variable (used once, directly) and one constant
    same_base_name = "same_base_name"  # pair: both variables have the same name
    same_storage = "same_storage"  # pair: both variables have the same Binary Ninja source type and storage (Variable.provenance)
    def_by_usage = "def_by_usage"  # assignment: the destination is a variable, the rhs has exactly one variable, all its uses are direct
    # assignment, use kinds (multi-hot): every kind of operation on the path from the rhs root to an occurrence of the rhs variable is
    # set, so x = f(*a) sets use_call and use_memory, and x = a + f(a) sets use_direct and use_call.
    use_direct = "use_direct"  # an occurrence has no call, memory access or address-of on its path
    use_call = "use_call"  # an occurrence is below a call (argument or call target)
    use_memory = "use_memory"  # an occurrence is below a dereference, field or member access
    use_address = "use_address"  # an occurrence is below an address-of
    same_phi = "same_phi"  # pair: both variables occurred in the same Phi-function (before the Phi-functions were lifted)
    # assignment: usage_n is set if the rhs has exactly n distinct variables
    usage_1 = "usage_1"
    usage_2 = "usage_2"
    usage_3 = "usage_3"
    usage_4 = "usage_4"
    usage_5 = "usage_5"
    usage_6 = "usage_6"
    usage_7 = "usage_7"
    usage_8 = "usage_8"
    usage_9 = "usage_9"
    following_definitions = "following_definitions"  # kind: the first variable is the previous definition of the second one's name
    same_rhs_source = "same_rhs_source"  # kind: both variables are defined as plain copies of the same variable

    @staticmethod
    def usage(number_of_variables: int) -> Feature:
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

    # The use kind that an operation adds to every variable below it; all other operations are transparent.
    _USE_KIND_OF_OPERATION = {
        OperationType.call: Feature.use_call,
        OperationType.dereference: Feature.use_memory,
        OperationType.field: Feature.use_memory,
        OperationType.member_access: Feature.use_memory,
        OperationType.pointer: Feature.use_memory,  # unused by the frontend; a pointer access is a memory access
        OperationType.address: Feature.use_address,
    }

    def __init__(self, phi_pairs: PhiPairs) -> None:
        """:param phi_pairs: The ordered pairs of variables that co-occur in a phi function, see get_phi_pairs."""
        self._phi_pairs = phi_pairs

    def iter_edge_data(self, cfg: ControlFlowGraph) -> Iterator[Tuple[VariablePair, FeatureVector]]:
        """
        Yield every candidate variable pair of the given control flow graph with its feature vector.

        The candidate pairs:
            - assignment:            x = a + 1            -> (x, a)
            - following definitions: y#1 = ...; y#2 = ... -> (y#1, y#2), y#1 is the last dominating definition of y
            - same source:           x = a; y = a         -> (x, y)
        A pair may occur several times, with different vectors.
        """
        # variable -> the variables defined as a plain copy of it: x = a, y = a  ->  variables_copied_from[a] == [x, y]
        variables_copied_from: DefaultDict[Variable, List[Variable]] = defaultdict(list)
        for assignment, dominating_definition in self._assignments_with_dominating_definition(cfg):
            lhs = self._get_expression_info(assignment.destination)
            rhs = self._get_expression_info(assignment.value)
            definition = self._defined_variable(assignment)
            if definition is not None and isinstance(assignment.value, Variable):
                variables_copied_from[assignment.value].append(definition)
            if dominating_definition is not None:
                yield self._edge(dominating_definition, definition, {Feature.following_definitions: 1})
            for variable_1, variable_2 in product(lhs.variable_counts, rhs.variable_counts):
                yield self._edge(variable_1, variable_2, self._assignment_features(lhs, rhs, variable_2))
        for copies in variables_copied_from.values():
            for variable_1, variable_2 in combinations(copies, 2):  # two copies of the same variable
                yield self._edge(variable_1, variable_2, {Feature.same_rhs_source: 1})

    def _assignments_with_dominating_definition(self, cfg: ControlFlowGraph) -> Iterator[Tuple[Assignment, Optional[Variable]]]:
        """
        Yield every assignment in dominator-tree order, with the last dominating definition of the name it defines (or None).

        y#1 = ...; y#2 = ...  ->  (y#1 = ..., None), (y#2 = ..., y#1)
        """
        if not cfg.nodes:  # an empty function has nothing to rename
            return
        dominator_tree = cfg.dominator_tree
        stack: List[Tuple[BasicBlock, Dict[str, Variable]]] = [(cfg.root, {})]
        while stack:
            basic_block, inherited_definitions = stack.pop()
            last_definition = dict(inherited_definitions)
            for instruction in basic_block:
                if not isinstance(instruction, Assignment):
                    continue
                definition = self._defined_variable(instruction)
                if definition is None:
                    yield instruction, None
                    continue
                yield instruction, last_definition.get(definition.name)
                last_definition[definition.name] = definition
            for child in dominator_tree.get_successors(basic_block):
                stack.append((child, last_definition))

    @staticmethod
    def _defined_variable(assignment: Assignment) -> Optional[Variable]:
        """Return the variable the assignment defines, also through casts: x = ..., (int) x = ...; else None (*p = ..., a.b = ...)."""
        destination = assignment.destination
        while isinstance(destination, UnaryOperation) and destination.operation == OperationType.cast:
            destination = destination.operand
        return destination if isinstance(destination, Variable) else None

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
        use_kinds, variables_below_operations = self._get_use_kinds(expression)
        return ExpressionInfo(
            constant_count, use_kinds, variables_below_operations, has_bad_operation_strong, has_bad_operation_mid, variable_counts
        )

    def _get_use_kinds(self, expression: Expression) -> Tuple[Dict[Variable, Set[Feature]], Set[Variable]]:
        """
        Return the use kinds per variable and the variables that have an operation other than a cast on their path.

        Every kind of operation on the path from the root to an occurrence is part of the set, an occurrence without any such operation
        is a direct use. The sets of several occurrences are united.
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
                if subexpression.operation in self._USE_KIND_OF_OPERATION:
                    kinds = path_kinds | {self._USE_KIND_OF_OPERATION[subexpression.operation]}
                below = below_operation or subexpression.operation != OperationType.cast
                stack.extend((operand, kinds, below) for operand in subexpression)
        return use_kinds, variables_below_operations

    def _edge(self, variable_1: Variable, variable_2: Variable, features: FeatureVector) -> Tuple[VariablePair, FeatureVector]:
        """Return the pair with the given kind or assignment features plus the pair features, which every pair gets."""
        vector = dict(features)
        for feature, check in (
            (Feature.same_base_name, self._same_base_name),
            (Feature.same_storage, self._same_storage),
            (Feature.same_phi, self._same_phi),
        ):
            if check(variable_1, variable_2):
                vector[feature] = 1
        return (variable_1, variable_2), vector

    def _assignment_features(self, lhs: ExpressionInfo, rhs: ExpressionInfo, rhs_variable: Variable) -> FeatureVector:
        """Return the assignment features of the pair (lhs variable, rhs_variable): use kinds, usage_n, is_strong, is_mid, def_by_usage."""
        vector: FeatureVector = dict.fromkeys(rhs.use_kinds[rhs_variable], 1)
        if len(rhs.variable_counts) <= 9:
            vector[Feature.usage(len(rhs.variable_counts))] = 1
        for feature, check in (
            (Feature.is_strong, self._is_strong),
            (Feature.is_mid, self._is_mid),
            (Feature.def_by_usage, self._def_by_usage),
        ):
            if check(lhs, rhs, rhs_variable):
                vector[feature] = 1
        return vector

    def _same_phi(self, variable_1: Variable, variable_2: Variable) -> bool:
        return (variable_1, variable_2) in self._phi_pairs

    @staticmethod
    def _is_strong(lhs: ExpressionInfo, rhs: ExpressionInfo, rhs_variable: Variable) -> bool:
        return (
            len(rhs.variable_counts) == 1
            and rhs.variable_counts[rhs_variable] == 1
            and rhs.constant_count == 0
            and rhs_variable not in rhs.variables_below_operations
            and not lhs.has_bad_operation_strong
        )

    @staticmethod
    def _is_mid(lhs: ExpressionInfo, rhs: ExpressionInfo, rhs_variable: Variable) -> bool:
        return (
            len(rhs.variable_counts) == 1
            and rhs.variable_counts[rhs_variable] == 1
            and rhs.constant_count == 1
            and rhs.use_kinds[rhs_variable] == {Feature.use_direct}
            and not lhs.has_bad_operation_mid
        )

    @staticmethod
    def _def_by_usage(lhs: ExpressionInfo, rhs: ExpressionInfo, rhs_variable: Variable) -> bool:
        return len(rhs.variable_counts) == 1 and rhs.use_kinds[rhs_variable] == {Feature.use_direct} and not lhs.has_bad_operation_mid

    @staticmethod
    def _same_base_name(variable_1: Variable, variable_2: Variable) -> bool:
        return variable_1.name == variable_2.name

    @staticmethod
    def _same_storage(variable_1: Variable, variable_2: Variable) -> bool:
        provenance_1, provenance_2 = variable_1.provenance, variable_2.provenance
        return (
            provenance_1 is not None
            and provenance_2 is not None
            and provenance_1.source_type is not None
            and provenance_1.storage is not None
            and provenance_1.source_type == provenance_2.source_type
            and provenance_1.storage == provenance_2.storage
        )
