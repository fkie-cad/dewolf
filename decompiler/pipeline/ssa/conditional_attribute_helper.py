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
        - pair:       depends only on the two variables, set for every pair (see ConditionalAttributeHelper._pair_features)
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
    # kind: the first variable is the last definition of the second one's name that dominates it, not necessarily one that reaches it
    dominating_definition = "dominating_definition"
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
    """Summary of the rhs of an assignment that the assignment features are computed from."""

    occurrences_per_variable: Dict[Variable, int]  # variable -> number of occurrences
    constant_count: int  # the callee of a call is not a constant
    use_kinds_per_variable: Dict[Variable, Set[Feature]]  # variable -> use-kind features of the operations on the paths to its occurrences
    without_casts: Expression  # the rhs without its outer casts: (int) (short) a -> a


class ConditionalAttributeHelper:
    """Computes the feature vector of every candidate variable pair for the dependency graph of the conditional out-of-SSA."""

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
            - dominating definition: y#1 = ...; y#2 = ... -> (y#1, y#2), y#1 is the last definition of y that dominates y#2
            - same source:           x = a; y = a         -> (x, y)
        A pair may occur several times, with different vectors.
        Every vector consists of the features of its kind plus the pair features (same_base_name, same_storage, same_phi).
        """
        for (variable_1, variable_2), vector in self._iter_pairs_with_own_features(cfg):
            vector.update(self._pair_features(variable_1, variable_2))
            yield (variable_1, variable_2), vector

    def _iter_pairs_with_own_features(self, cfg: ControlFlowGraph) -> Iterator[Tuple[VariablePair, FeatureVector]]:
        """Yield every candidate pair with the features of its kind: the assignment features, dominating_definition or same_rhs_source."""
        # variable -> the variables defined as a plain copy of it: x = a, y = a  ->  variables_copied_from[a] == [x, y]
        variables_copied_from: DefaultDict[Variable, List[Variable]] = defaultdict(list)
        for assignment, dominating_definition in self._assignments_with_dominating_definition(cfg):
            definition = self._defined_variable(assignment)
            rhs_expression_info = self._get_expression_info(assignment.value)
            # plain copy x = a; not (byte) eax = a, which keeps the upper bytes of eax
            if isinstance(assignment.destination, Variable) and isinstance(assignment.value, Variable):
                variables_copied_from[assignment.value].append(assignment.destination)
            if dominating_definition is not None:
                yield (dominating_definition, definition), {Feature.dominating_definition: 1}
            # all variables of the destination, also p of *p = a
            for lhs_variable, rhs_variable in product(assignment.destination.requirements, rhs_expression_info.occurrences_per_variable):
                yield (lhs_variable, rhs_variable), self._assignment_features(
                    isinstance(assignment.destination, Variable), rhs_expression_info, rhs_variable
                )
        for copies in variables_copied_from.values():
            for lhs_variable, rhs_variable in combinations(copies, 2):  # two copies of the same variable
                yield (lhs_variable, rhs_variable), {Feature.same_rhs_source: 1}

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
            for instruction in (instr for instr in basic_block if isinstance(instr, Assignment)):
                definition = self._defined_variable(instruction)
                if definition is None:
                    yield instruction, None
                else:
                    yield instruction, last_definition.get(definition.name)
                    last_definition[definition.name] = definition
            for child in dominator_tree.get_successors(basic_block):
                stack.append((child, last_definition))

    def _defined_variable(self, assignment: Assignment) -> Optional[Variable]:
        """Return the variable the assignment defines, also through casts: x = ..., (int) x = ...; else None (*p = ..., a.b = ...)."""
        destination = self._without_casts(assignment.destination)
        return destination if isinstance(destination, Variable) else None

    @staticmethod
    def _without_casts(expression: Expression) -> Expression:
        """Return the expression without its outer casts: (int) (short) a -> a."""
        while isinstance(expression, UnaryOperation) and expression.operation == OperationType.cast:
            expression = expression.operand
        return expression

    def _get_expression_info(self, expression: Expression) -> ExpressionInfo:
        """Count the variables and constants of the given rhs and find how each variable is used."""
        constant_count = 0
        occurrences_per_variable: Dict[Variable, int] = {}
        stack: List[Expression] = [expression]
        while stack:
            subexpression = stack.pop()
            match subexpression:
                case Variable():  # not into a variable: a global variable has its initial value as child
                    occurrences_per_variable[subexpression] = occurrences_per_variable.get(subexpression, 0) + 1
                case Constant():
                    constant_count += 1
                case Call(function=FunctionSymbol()):  # the callee is no constant
                    stack.extend(subexpression.parameters)
                case _:
                    stack.extend(subexpression)
        return ExpressionInfo(
            occurrences_per_variable, constant_count, self._use_kinds_per_variable(expression), self._without_casts(expression)
        )

    def _use_kinds_per_variable(self, expression: Expression) -> Dict[Variable, Set[Feature]]:
        """
        Return how each variable of the expression is used: the use kinds of all operations on the paths from the root to its occurrences.

        A call, dereference, field, member or pointer access and an address operation add their use kind, all other operations
        (arithmetic, casts) are transparent. A path without any of them is a direct use. The kinds of several occurrences are united:
            f(*p + a) + b  ->  p: {use_call, use_memory}, a: {use_call}, b: {use_direct}
        """
        use_kinds_per_variable: DefaultDict[Variable, Set[Feature]] = defaultdict(set)
        stack = [(expression, frozenset())]
        while stack:
            subexpression, kinds_on_path = stack.pop()
            if isinstance(subexpression, Variable):
                if kinds_on_path:
                    use_kinds_per_variable[subexpression].update(kinds_on_path)
                else:  # only arithmetic and casts on the path
                    use_kinds_per_variable[subexpression].add(Feature.use_direct)
            elif isinstance(subexpression, Operation):
                kinds = kinds_on_path
                if subexpression.operation in self._USE_KIND_OF_OPERATION:
                    kinds = kinds_on_path | {self._USE_KIND_OF_OPERATION[subexpression.operation]}
                stack.extend((operand, kinds) for operand in subexpression)
        return use_kinds_per_variable

    def _pair_features(self, variable_1: Variable, variable_2: Variable) -> FeatureVector:
        """Return the pair features of the two variables, which every pair gets: same_base_name, same_storage, same_phi."""
        return {
            feature: 1
            for feature, check in (
                (Feature.same_base_name, self._same_base_name),
                (Feature.same_storage, self._same_storage),
                (Feature.same_phi, self._same_phi),
            )
            if check(variable_1, variable_2)
        }

    def _assignment_features(self, defines_variable: bool, rhs: ExpressionInfo, rhs_variable: Variable) -> FeatureVector:
        """
        Return the assignment features of the pair (lhs variable, rhs_variable): use kinds, usage_n, is_strong, is_mid, def_by_usage.

        is_strong, is_mid and def_by_usage need a variable as destination (x = ..., not *p = ... or the contraction (byte) eax = ...).
        """
        vector: FeatureVector = dict.fromkeys(rhs.use_kinds_per_variable[rhs_variable], 1)
        if len(rhs.occurrences_per_variable) <= 9:
            vector[Feature.usage(len(rhs.occurrences_per_variable))] = 1
        for feature, check in (
            (Feature.is_strong, self._is_strong),
            (Feature.is_mid, self._is_mid),
            (Feature.def_by_usage, self._def_by_usage),
        ):
            if defines_variable and check(rhs, rhs_variable):
                vector[feature] = 1
        return vector

    def _same_phi(self, variable_1: Variable, variable_2: Variable) -> bool:
        return (variable_1, variable_2) in self._phi_pairs

    @staticmethod
    def _def_by_usage(rhs: ExpressionInfo, rhs_variable: Variable) -> bool:
        """x = a * 2 + a - 3: the rhs variable is the only variable, and all its uses are direct."""
        return len(rhs.occurrences_per_variable) == 1 and rhs.use_kinds_per_variable[rhs_variable] == {Feature.use_direct}

    def _is_mid(self, rhs: ExpressionInfo, rhs_variable: Variable) -> bool:
        """x = a + 1: def_by_usage, and the rhs variable occurs once, with exactly one constant."""
        return self._def_by_usage(rhs, rhs_variable) and rhs.occurrences_per_variable[rhs_variable] == 1 and rhs.constant_count == 1

    @staticmethod
    def _is_strong(rhs: ExpressionInfo, rhs_variable: Variable) -> bool:
        """x = a, x = (int) a: the rhs is the rhs variable, at most cast; this implies def_by_usage."""
        return rhs.without_casts == rhs_variable

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
