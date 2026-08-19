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
"""

from abc import ABC
from itertools import permutations, product
from typing import Dict, Iterator, List, NamedTuple, Set, Tuple

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
INDEX_USAGE_BASE = 7  # usage_1..usage_5 live at INDEX_USAGE_BASE + (n - 1)
VECTOR_LENGTH = 16 


def variablesAreInterfering(interference_graph: InterferenceGraph, var_X: Variable,var_Y: Variable) -> bool:
    if interference_graph.are_interfering(var_X, var_Y):
        return True
    elif var_X.type != var_Y.type:
        return True
    elif (var_X.is_aliased != var_Y.is_aliased) or (var_X.is_aliased and var_Y.is_aliased and (var_X.name != var_Y.name)):
        return True
    elif isinstance(var_X, GlobalVariable) != isinstance(var_Y, GlobalVariable):
        return True
    elif (isinstance(var_X,GlobalVariable) and  isinstance(var_Y,GlobalVariable) and (var_X.name != var_Y.name)):
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
        has_bad_op: bool
        c_v: Dict[Variable, int]    # variable -> occurrence count

    def __init__(self, phi_pairs: PhiPairs) -> None:
        self._phi_pairs = phi_pairs

    def _get_expression_info(self, expr: Expression) -> ExprInfo:
        c_c = 0
        has_bad_op = False
        is_call = isinstance(expr, Call)
        c_v: Dict[Variable, int] = {}

        for e in expr.subexpressions():
            if isinstance(e, Variable):
                c_v[e] = c_v.get(e, 0) + 1
            elif isinstance(e, Constant):
                c_c += 1
            elif not has_bad_op and isinstance(e, Operation) and e.operation in self._BAD_OPERATIONS:
                has_bad_op = True

        return self.ExprInfo(c_c, is_call, has_bad_op, c_v)

    def _common_template(self, lhs: ExprInfo, rhs: ExprInfo) -> List[int]:
        n_rhs_vars = len(rhs.c_v)
        single_rhs_var_once = n_rhs_vars == 1 and next(iter(rhs.c_v.values())) == 1
        no_bad_ops = not lhs.has_bad_op and not rhs.has_bad_op

        vec = [0] * VECTOR_LENGTH
        vec[INDEX_IS_STRONG] = int(single_rhs_var_once and rhs.c_c == 0 and no_bad_ops)
        vec[INDEX_IS_MID] = int(single_rhs_var_once and rhs.c_c == 1 and no_bad_ops)
        vec[INDEX_DEF_BY_USAGE] = int(n_rhs_vars == 1 and no_bad_ops)
        vec[INDEX_FUNC_CALL] = int(rhs.is_call)
        if 1 <= n_rhs_vars <= 5:
            vec[INDEX_USAGE_BASE + n_rhs_vars - 1] = 1
        return vec

    def _fill_pair_attrs(self, vec: List[int], x: Variable, y: Variable) -> None:
        vec[INDEX_SAME_BASE_NAME] = int(x.name == y.name)
        vec[INDEX_SAME_STORAGE] = int(
            x.origin is not None
            and y.origin is not None
            and x.origin.source_type == y.origin.source_type
            and x.origin.storage == y.origin.storage
        )
        vec[INDEX_IN_SAME_PHI] = int((x, y) in self._phi_pairs)

    def _assignments_in_cfg(self, cfg: ControlFlowGraph) -> Iterator[Assignment]:
        for instr in cfg.instructions:
            if isinstance(instr, Assignment):
                yield instr


class TrainingRecord(NamedTuple):
    vector: List[int]
    training_goal: int
    x_source_name: str
    y_source_name: str

class TrainingAttributeHelper(AbstractAttributeHelper):
    """Used to build (vector, training_goal) training examples. Only yields pairs where"""

    def __init__(self, phi_pairs: PhiPairs, interference_graph: InterferenceGraph):
        self._interference_graph = interference_graph
        super().__init__(phi_pairs)

    def iter_training_data(self, cfg: ControlFlowGraph, on_error=None) -> Iterator[TrainingRecord]:
        """on_error(assign, exc) is called (if given) when a single assignment fails to process"""
        for assign in self._assignments_in_cfg(cfg):
            try:
                lhs = self._get_expression_info(assign.destination)
                rhs = self._get_expression_info(assign.value)

                # skip assignments where either side has no
                template = self._common_template(lhs, rhs)
                for x, y in product(lhs.c_v, rhs.c_v):
                    if (
                        x.origin is None
                        or y.origin is None
                        or x.origin.source_name is None
                        or y.origin.source_name is None
                        or variablesAreInterfering(self._interference_graph, x, y)
                    ):
                        continue

                    vec = template.copy()
                    self._fill_pair_attrs(vec, x, y)
                    t_goal = int(x.origin.source_name == y.origin.source_name)
                    yield TrainingRecord(vec, t_goal, x.origin.source_name, y.origin.source_name)

            except Exception as exc:
                if on_error is not None:
                    on_error(assign, exc)
                continue


class ConditionalAttributeHelper(AbstractAttributeHelper):
    """Used during conditional out-of-SSA dependency-graph construction to score every candidate variable pair."""

    def iter_edge_data(self, cfg: ControlFlowGraph) -> Iterator[Tuple[List[int], Tuple[Variable, Variable]]]:
        for assign in self._assignments_in_cfg(cfg):
            lhs = self._get_expression_info(assign.destination)
            rhs = self._get_expression_info(assign.value)
            if not lhs.c_v or not rhs.c_v:
                continue

            template = self._common_template(lhs, rhs)

            for x, y in product(lhs.c_v, rhs.c_v):
                vec = template.copy()
                self._fill_pair_attrs(vec, x, y)
                yield vec, (x, y)
