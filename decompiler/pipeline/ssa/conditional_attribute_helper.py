"""
Shared attribute extraction for the conditional out-of-SSA ML pipeline.

Vector layout (indices are fixed and MUST match the FEATURES list in
conditionalTrainingRunner.py:

  0  is_strong          rhs is exactly one variable, used once, no constants, no bad ops
  1  is_mid             rhs is one variable (used once) + exactly one constant, no bad ops
  2  same_base_name     x.name == y.name
  3  same_storage       x/y share ssa origin's source_type and storage
  4  def_by_usage       rhs contains exactly one distinct variable, no bad ops
  5  func_call          rhs is a call
  6  same_phi           (x, y) co-occur in some phi function
  7  usage_1            rhs has exactly 1 distinct variable
  8  usage_2            rhs has exactly 2 distinct variables
  9  usage_3            rhs has exactly 3 distinct variables
  10 usage_4            rhs has exactly 4 distinct variables
  11 usage_5            rhs has exactly 5 distinct variables
  12 usage_6            rhs has exactly 6 distinct variable
  13 usage_7            rhs has exactly 7 distinct variables
  14 usage_8            rhs has exactly 8 distinct variables
  15 usage_9            rhs has exactly 9 distinct variables
  16 following_definitions  x is the last occurrence of a variable, y is the next occurrence
  17 same_rhs_source        x and y have the same ssa origin's source_name
"""

from abc import ABC
from collections import defaultdict
from itertools import combinations, permutations, product
from typing import Dict, Iterator, List, NamedTuple, Optional, Set, Tuple

from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.instructions import Assignment, Phi
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, GlobalVariable, Variable
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


def variablesAreInterfering(interference_graph: InterferenceGraph, var_X: Variable,var_Y: Variable) -> bool:
    """True iff the two variables may not share a name. Must stay the same rule as
    ConditionalVariableRenamer._must_separate (which applies it to contracted nodes): a pair this
    function lets through becomes a dependency-graph edge and a training pair, so it has to be a
    pair the renamer is able to merge."""
    if interference_graph.are_interfering(var_X, var_Y):
        return True
    elif (var_X.is_aliased != var_Y.is_aliased) or (var_X.is_aliased and var_Y.is_aliased and (var_X.name != var_Y.name)):
        return True
    elif isinstance(var_X, GlobalVariable) != isinstance(var_Y, GlobalVariable):
        return True
    elif (isinstance(var_X,GlobalVariable) and  isinstance(var_Y,GlobalVariable) and (var_X.name != var_Y.name)):
        return True
    elif var_X.type != var_Y.type:
        # The renamer only merges variables of identical type (a class has one type), also if the sizes agree.
        return True

    if(var_X.type == None) or (var_Y.type == None):
        raise Exception("Encountered a None type variable in the SSA-Stage!")
    
    return False

def get_phi_pairs(cfg: ControlFlowGraph) -> PhiPairs:
    """All ordered pairs of variables that co-occur in the same phi function."""
    phi_pairs: PhiPairs = set()
    for instr in cfg.instructions:
        if isinstance(instr, Phi):
            phi_pairs.update(permutations(set(instr.definitions + instr.requirements), 2))
    return phi_pairs


class AbstractAttributeHelper(ABC):
    """Shared logic between the offline training-data exporter and the live predictor."""

    __slots__ = ("_phi_pairs",)

    _GOOD_OPERATIONS = frozenset({
        OperationType.cast,
    })

    _BAD_OPERATIONS = frozenset({
        OperationType.dereference,
        OperationType.address,
        OperationType.call,
        OperationType.pointer,
        OperationType.ternary,
        OperationType.list_op,
        OperationType.field,
        OperationType.member_access,
    })

    class ExprInfo(NamedTuple):
        c_c: int                    # number of constants
        is_call: bool
        has_bad_op_strong: bool
        has_bad_op_mid: bool
        c_v: Dict[Variable, int]    # variable -> occurrence count

    def __init__(self, phi_pairs: PhiPairs) -> None:
        self._phi_pairs = phi_pairs

    def _get_expression_info(self, expr: Expression) -> ExprInfo:
        c_c = 0
        has_bad_op_strong = False
        has_bad_op_mid = False
        is_call = isinstance(expr, Call)
        c_v: Dict[Variable, int] = {}

        for e in expr.subexpressions():
            if isinstance(e, Variable):
                c_v[e] = c_v.get(e, 0) + 1
            elif isinstance(e, Constant):
                c_c += 1
            if not has_bad_op_strong and isinstance(e, Operation) and e.operation not in self._GOOD_OPERATIONS:
                has_bad_op_strong = True
            if not has_bad_op_mid and isinstance(e, Operation) and e.operation in self._BAD_OPERATIONS:
                has_bad_op_mid = True

        return self.ExprInfo(c_c, is_call,has_bad_op_strong, has_bad_op_mid, c_v)

    def _common_template(self, lhs: ExprInfo, rhs: ExprInfo, is_following_definitions: bool = False, is_same_source: bool = False) -> List[int]:
        n_rhs_vars = len(rhs.c_v)
        single_rhs_var_once = n_rhs_vars == 1 and next(iter(rhs.c_v.values())) == 1
        no_bad_ops_strong = not lhs.has_bad_op_strong and not rhs.has_bad_op_strong
        no_bad_ops_mid = not lhs.has_bad_op_mid and not rhs.has_bad_op_mid

        vec = [0] * VECTOR_LENGTH
        if not (is_following_definitions or is_same_source):
            vec[INDEX_IS_STRONG] = int(single_rhs_var_once and rhs.c_c == 0 and no_bad_ops_strong)
            vec[INDEX_IS_MID] = int(single_rhs_var_once and rhs.c_c == 1 and no_bad_ops_mid)
            vec[INDEX_DEF_BY_USAGE] = int(n_rhs_vars == 1 and no_bad_ops_mid)
            vec[INDEX_FUNC_CALL] = int(rhs.is_call)
            if 1 <= n_rhs_vars <= 9:
                vec[INDEX_USAGE_BASE + n_rhs_vars - 1] = 1

        vec[INDEX_FOLLOWING_DEFINITIONS] = int(is_following_definitions)
        vec[INDEX_SAME_SOURCE] = int(is_same_source)
        return vec

    def _fill_pair_attrs(self, vec: List[int], x: Variable, y: Variable) -> None:
        vec[INDEX_SAME_BASE_NAME] = int(x.name == y.name)
        vec[INDEX_SAME_STORAGE] = int(
            x.origin is not None
            and y.origin is not None
            and x.origin.source_type is not None
            and y.origin.source_type is not None
            and x.origin.storage is not None
            and y.origin.storage is not None
            and x.origin.source_type == y.origin.source_type
            and x.origin.storage == y.origin.storage
        )
        vec[INDEX_IN_SAME_PHI] = int((x, y) in self._phi_pairs)

    def _assignments_in_cfg(self, cfg: ControlFlowGraph) -> Iterator[Assignment]:
        for instr in cfg.instructions:
            if isinstance(instr, Assignment):
                yield instr

    def _assignments_in_dominator_order(self, cfg: ControlFlowGraph) -> Iterator[Tuple[Assignment, Dict[str, ExprInfo]]]:
        """Yields every assignment together with the last dominating definition per variable name.
        The caller updates the dict; changes are only visible to blocks dominated by the current one."""
        if cfg.root is None:
            return
        tree = cfg.dominator_tree
        stack = [(cfg.root, {})]
        while stack:
            block, inherited = stack.pop()
            last_def = dict(inherited)
            for instr in block:
                if isinstance(instr, Assignment):
                    yield instr, last_def
            for child in tree.get_successors(block):
                stack.append((child, last_def))


def source_identity(variable: Variable) -> Optional[Tuple[Optional[int], str]]:
    """The DWARF source variable a variable was matched to, as (source_id, source_name), or None if
    the variable has no complete origin (no label). Two variables come from the same source iff their
    identities are equal (two distinct source variables may share a name, so the name alone is not enough)."""
    origin = variable.origin
    if origin is None or origin.source_name is None or origin.source_type is None or origin.storage is None:
        return None
    return origin.source_id, origin.source_name


class CandidatePair(NamedTuple):
    vector: List[int]
    x: Variable
    y: Variable


class TrainingRecord(NamedTuple):
    vector: List[int]
    training_goal: int
    x_source_name: str
    y_source_name: str

class TrainingAttributeHelper(AbstractAttributeHelper):
    """Used to build (vector, training_goal) training examples."""

    def __init__(self, phi_pairs: PhiPairs, interference_graph: InterferenceGraph):
        self._interference_graph = interference_graph
        super().__init__(phi_pairs)

    def _candidate(self, template: List[int], x: Variable, y: Variable) -> Optional[CandidatePair]:
        """The candidate pair (x, y) with the given assignment-level attributes, or None for a pair the
        renamer never joins: a variable with itself (a self-loop, which it ignores) or two interfering ones."""
        if x == y or variablesAreInterfering(self._interference_graph, x, y):
            return None
        vec = template.copy()
        self._fill_pair_attrs(vec, x, y)
        return CandidatePair(vec, x, y)

    def iter_candidate_pairs(self, cfg: ControlFlowGraph, on_error=None) -> Iterator[CandidatePair]:
        """Every pair the conditional renamer scores (ConditionalAttributeHelper.iter_edge_data minus the
        interfering pairs dependency_graph_from_cfg skips), labeled or not, one per occurrence: the pairs
        of an assignment's two sides, of a definition and the last dominating definition of the same
        name (following_definitions), and of two variables defined as copies of the same variable
        (same_rhs_source). Pairs of a variable with itself are skipped: they only become self-loops,
        which the renamer ignores.
        on_error(assign, exc) is called (if given) when a single assignment (for the same_rhs_source
        pairs: the copied variable) fails to process."""
        sameSourceDict = defaultdict(list)
        for assign, last_def in self._assignments_in_dominator_order(cfg):
            try:
                lhs = self._get_expression_info(assign.destination)
                rhs = self._get_expression_info(assign.value)

                if (not rhs.has_bad_op_strong) and (len(rhs.c_v) == 1) and (len(lhs.c_v) == 1):
                    sameSourceDict[list(rhs.c_v.keys())[0]].append(lhs)

                if (not lhs.has_bad_op_strong) and (len(lhs.c_v) == 1):  # handle last occurrence
                    name = next(iter(lhs.c_v)).name
                    lastOccurence = last_def.get(name)
                    last_def[name] = lhs
                    if lastOccurence is not None:
                        template = self._common_template(lastOccurence, lhs, is_following_definitions=True)
                        for x, y in product(lastOccurence.c_v, lhs.c_v):
                            if (pair := self._candidate(template, x, y)) is not None:
                                yield pair

                if not lhs.c_v or not rhs.c_v:
                    continue
                template = self._common_template(lhs, rhs)
                for x, y in product(lhs.c_v, rhs.c_v):
                    if (pair := self._candidate(template, x, y)) is not None:
                        yield pair

            except Exception as exc:
                if on_error is not None:
                    on_error(assign, exc)
                continue

        for varRight in list(sameSourceDict.keys()):
            try:
                if len(sameSourceDict[varRight]) > 1:
                    for x, y in combinations(sameSourceDict[varRight], 2):
                        var1: Variable = list(x.c_v.keys())[0]
                        var2: Variable = list(y.c_v.keys())[0]
                        template = self._common_template(x, y, is_same_source=True)
                        if (pair := self._candidate(template, var1, var2)) is not None:
                            yield pair
            except Exception as exc:
                if on_error is not None:
                    on_error(varRight, exc)
                continue

    def iter_training_data(self, cfg: ControlFlowGraph, on_error=None) -> Iterator[TrainingRecord]:
        """The labeled candidate pairs (both variables have a DWARF source); goal 1 iff same source."""
        for pair in self.iter_candidate_pairs(cfg, on_error):
            x_source, y_source = source_identity(pair.x), source_identity(pair.y)
            if x_source is None or y_source is None:
                continue
            yield TrainingRecord(pair.vector, int(x_source == y_source), x_source[1], y_source[1])


class ConditionalAttributeHelper(AbstractAttributeHelper):
    """Used during conditional out-of-SSA dependency-graph construction to score every candidate variable pair."""

    def iter_edge_data(self, cfg: ControlFlowGraph) -> Iterator[Tuple[List[int], Tuple[Variable, Variable]]]:
        sameSourceDict = defaultdict(list)

        for assign, last_def in self._assignments_in_dominator_order(cfg):
            lhs = self._get_expression_info(assign.destination)
            rhs = self._get_expression_info(assign.value)

            if (not rhs.has_bad_op_strong) and (len(rhs.c_v) == 1) and (len(lhs.c_v) == 1):
                sameSourceDict[list(rhs.c_v.keys())[0]].append(lhs)

            if (not lhs.has_bad_op_strong) and (len(lhs.c_v) == 1):
                name = next(iter(lhs.c_v)).name
                lastOccurence = last_def.get(name)
                last_def[name] = lhs
                if lastOccurence is not None:
                    template = self._common_template(lastOccurence, lhs, is_following_definitions=True)
                    for x, y in product(lastOccurence.c_v, lhs.c_v):
                        vec = template.copy()
                        self._fill_pair_attrs(vec, x, y)
                        yield vec, (x, y)
            
            if not lhs.c_v or not rhs.c_v:
                continue
            template = self._common_template(lhs, rhs)

            for x, y in product(lhs.c_v, rhs.c_v):
                vec = template.copy()
                self._fill_pair_attrs(vec, x, y)
                yield vec, (x, y)

        for varRight in list(sameSourceDict.keys()):
            if len(sameSourceDict[varRight]) > 1:
                for x,y in combinations(sameSourceDict[varRight],2):
                    var1 : Variable = list(x.c_v.keys())[0]
                    var2 : Variable = list(y.c_v.keys())[0]

                    vec = self._common_template(x,y,is_same_source=True)
                    self._fill_pair_attrs(vec, var1, var2)
                    yield vec, (var1, var2)
