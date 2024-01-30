"""Module implementing detection of array element accesses"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import DefaultDict, Dict, Iterator, List, Optional, Set, Tuple, Union

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.pseudo.expressions import Constant, DataflowObject, Expression, Variable
from decompiler.structures.pseudo.operations import ArrayInfo, BinaryOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer, UnknownType
from decompiler.task import DecompilerTask

BYTE_SIZE = 8


@dataclass
class OffsetInfo:
    """
    Pro candidate base, instance of this class contains offset values observed in the cfg, grouped into three classes:
    CONST <- offset value comes from *(base+const)
    MUL <- offset value comes from *(base+i*const) or *(base+i<<const)
    VAR <- offset value comes from *(base+i)

    e.g.
    const={20, 40, 60},
    mul={4},
    var={}

    if there exist some base a, which is used in *(a+20), *(a+40), *(a+60) and *(a+i<<2)
    """

    mul: Set[int] = field(default_factory=set)
    var: Set[int] = field(default_factory=set)
    const: Set[int] = field(default_factory=set)


@dataclass
class Candidate:
    dereference: Expression
    array_base: Variable
    array_index: Union[int, Variable]


class ArrayAccessDetection(PipelineStage):
    name = "array-access-detection"

    def __init__(self):
        """
        We assume that *(base + valid_offset) is a candidate for array element access (base[i])
        Elements of the same array base could be accessed directly via index (base[1]) or via variable (base[i])
        candidates is a mapping of bases to all possible candidates; using such a mapping allows to iterate all instructions only once.
        e.g.
        candidates:
            base1: [*(base1+20), *(base1+i<<3), ... ],
            base2: [...]

        candidate_offset_classes contains accumulated information about classes of offset for the given base
        and offset values collected pro class (CONST, MUL, VAR)
        (so that we do not need to parse a candidate twice, first, to check if a valid candidate, second, get offset value, etc)
        observed for different bases.
        e.g.
        candidates_offset_classes:
            base1: {Offsets(const={20, 40, 60})}
            base1: {Offsets(const={20, 40, 60}, mul={4})}
            ...

        *** in case of only constant offset, we do not know if it is array or struct; and, if array, which type its elements have

        We are CONFIDENT that array element access is detected if:
        - base has non-void pointer type
        - const offsets divisible on size of pointed type in bytes
        - mul or var offset is the same as size of pointed type in bytes

        We are NOT CONFIDENT, but in common cases the following also indicates array element access:
        - in case MUL or VAR offset, we could assume that the offset value/constant is a size of array elements
        (in case this value is consistent over all the candidates for the base).
        This works in common cases (base[i]) and may fail in more exotic cases (base[2*i], base[356+12*i] etc.)
        """
        self._candidates: DefaultDict[Variable[Pointer], List[Candidate]]
        self._candidate_offset_classes: Dict[Variable, OffsetInfo]

    def run(self, task: DecompilerTask) -> None:
        """
        - collect candidates that match the patterns for array element access
        - mark candidates that passed consistency checks as array element access if there is array type information
        with confidence=True
        if no with confidence=False

        :param task: task that contains cfg
        """
        if not task.options.getboolean("array-access-detection.enabled"):
            return
        self._candidates = defaultdict(list)
        self._candidate_offset_classes = defaultdict(OffsetInfo)
        for instr in task.graph.instructions:
            for dereference in self._find_dereference_subexpressions(instr):
                self._add_possible_array_element_access_candidates(dereference)
        self._mark_candidates_as_array_element_accesses()

    def _add_possible_array_element_access_candidates(self, candidate: UnaryOperation) -> None:
        """
        Tries to get base and offset; on success tests
        base is not saved yet, saves it.
        Puts the offset to the corresponding class (constant, variable or multiplication (incl. left-shift))
        :param candidate: unary operation to be tested
        """
        operand = candidate.operand
        if self._is_addition(operand):
            base, offset = self._get_base_and_offset(operand)
            if base and offset:
                if (offset_details := self._parse_offset(offset)) is not None:
                    offset_class, index, element_size = offset_details
                    self._candidates[base].append(Candidate(candidate, array_index=index, array_base=base))
                    self._update_candidate_offsets(base, offset_class, element_size)

    def _mark_candidates_as_array_element_accesses(self) -> None:
        """Iterates over array candidates and if consistency check is successful, set corresponding attributes in unary operation"""
        for base, offset_class in self._candidate_offset_classes.items():
            array_type_size = self._get_array_type_size(base)
            self._mark_candidates_if_consistent_offsets(base, offset_class, array_type_size)

    def _get_array_type_size(self, base: Variable) -> int:
        """
        :param base: variable storing start of array
        :return size of array type; in case of custom/unknown/void pointer returns 0.
        """
        array_type = base.type
        if array_type.type == CustomType.void() or array_type.type == UnknownType() or array_type.size == 0:
            return 0
        return self._size_in_bytes(array_type.type.size)

    def _mark_candidates_if_consistent_offsets(
        self, base: Variable, offset_class: OffsetInfo, available_array_type_size: Optional[int] = None
    ) -> None:
        """
        Mark candidates for the given base if the following conditions are true:
        - there is NOT ONLY constant array accesses as we cannot distinguish between structs and arrays then
        - only MUL or VAR pattern is present, but not both simultaneously
        - in case array_type_size is available, it should be equal to the offset
        - MUL or VAR pattern has consistent offset (always the same value)
        - constant offsets are divisible on array_type_size
        - array_type_size is offset from MUL or VAR pattern (AGGRESSIVE)
        """
        mul = offset_class.mul
        const = offset_class.const
        var = offset_class.var
        if not self._is_valid_offset_class_combination(var, mul):
            return
        if len(var) == 1:
            computed_element_size = var.pop()
        else:
            computed_element_size = mul.pop()
        if available_array_type_size and computed_element_size != available_array_type_size:
            return
        if not const:
            self._set_array_element_access_attributes(base, computed_element_size, available_array_type_size)
            return
        if all([constant % computed_element_size == 0 for constant in const]):
            self._set_array_element_access_attributes(base, computed_element_size, available_array_type_size)

    def _set_array_element_access_attributes(
        self, base_variable: Variable, element_size: int, available_array_type_size: Optional[int]
    ) -> None:
        """Sets for all candidate occurrences of the base field array_accesses to true and their array_type_size to offset value"""
        for candidate in self._candidates[base_variable]:
            confidence = False
            index = candidate.array_index
            if isinstance(index, int):
                index = int(index / element_size)
            if available_array_type_size:
                confidence = True
            array_info = ArrayInfo(base_variable, index, confidence)
            candidate.dereference.array_info = array_info

    def _get_base_and_offset(self, operand: BinaryOperation) -> Tuple[Optional[Variable[Pointer]], Optional[Expression]]:
        """
        Given operand of *(addition), we want to check, if it is of form base+offset or offset+base,
        where base is a variable of type pointer. We return both values and not just True or False
        since we would need them anyway and want to avoid parsing the operand twice.
        :param operand: operand of *(addition)
        :return: tuple of base and offset, in case base is found (offset form is checked later); None,None otherwise
        """
        left = operand.left
        right = operand.right
        base = None
        offset = None
        if self._is_pointer_variable(left):
            base = left
            offset = right
        elif self._is_pointer_variable(right):
            base = right
            offset = left
        return base, offset

    def _parse_offset(self, offset: Expression) -> Optional[Tuple[str, Variable, int]]:
        """
        Checks if in *(base + offset) offset has following form:
        - const - *(base + const) direct access to array element via known index. NON_RELIABLE
        - i - *(base + i) access to CHAR array element via variable index e.g. during for-iteration
        - i*const - *(base + i*const) access to CONST-SIZE array element (e.g. if const == 4, than int array) via variable index
        - i<<const - *(base + i<<const)==*(base + i*2**n) same as above, array elements have size 2**n
        :param offset: offset expression to be tested
        :return: tuple of offset class, parsed index and element size if available
        """
        if isinstance(offset, Constant):
            return "const", offset.value, offset.value
        if isinstance(offset, Variable) and not isinstance(offset.type, Pointer):
            return "var", offset, 1
        if self._is_variable_cast(offset):
            return "var", offset.operand, 1
        if not isinstance(offset, BinaryOperation):
            return None

        constants = [expr for expr in offset if isinstance(expr, Constant)]
        if len(constants) != 1:
            return None
        constant = constants[0]
        vars = [expr for expr in offset if isinstance(expr, Variable) or self._is_variable_cast(expr)]
        if len(vars) == 0:
            return None

        var = vars[0] if isinstance(vars[0], Variable) else vars[0].operand
        if self._is_left_shift(offset) and offset.right == constant:
            return "mul", var, 2**constant.value
        if self._is_multiplication(offset) and constant.value % 2 == 0:  # test % 2 for array of structs
            return "mul", var, constant.value
        return None

    def _update_candidate_offsets(self, base: Variable, offset_class: str, offset_value: int) -> None:
        """
        For the given candidate base, updates its offsets (in candidate_offset_classes) with given offset_class and offset_value
        :param base: candidate base variable
        :param offset_class: class of the offset, can be mul, var or const
        :param offset_value: value of the offset
        """
        if base not in self._candidate_offset_classes:
            self._candidate_offset_classes[base] = OffsetInfo()
        if offset_class == "mul":
            self._candidate_offset_classes[base].mul.add(offset_value)
        elif offset_class == "const":
            self._candidate_offset_classes[base].const.add(offset_value)
        elif offset_class == "var":
            self._candidate_offset_classes[base].var.add(offset_value)
        else:
            logging.warning(f"Unknown offset class {offset_class}")

    @staticmethod
    def _is_pointer_variable(expression: Expression) -> bool:
        """
        :param expression: expression to be checked
        :return: true if expression is a Variable of type Pointer false otherwise
        """
        return isinstance(expression, Variable) and isinstance(expression.type, Pointer)

    @staticmethod
    def _find_dereference_subexpressions(expression: DataflowObject) -> Iterator[UnaryOperation]:
        """Yield all subexpressions of the given expression or instruction if expression is dereference operation"""
        all_subexpressions = [expression]
        while all_subexpressions and (subexpression := all_subexpressions.pop()):
            all_subexpressions.extend(subexpression)
            if isinstance(subexpression, UnaryOperation) and subexpression.operation == OperationType.dereference:
                yield subexpression

    @staticmethod
    def _is_addition(expression: Expression) -> bool:
        """
        :param expression: expression to be checked
        :return: true if expression is addition false otherwise
        """
        return isinstance(expression, BinaryOperation) and expression.operation == OperationType.plus

    @staticmethod
    def _is_multiplication(expression: Expression) -> bool:
        """
        :param expression: expression to be checked
        :return: true if expression is multiplication (signed/unsigned) false otherwise
        """
        return isinstance(expression, BinaryOperation) and expression.operation in {OperationType.multiply_us, OperationType.multiply}

    @staticmethod
    def _is_left_shift(expression: Expression) -> bool:
        """
        :param expression: expression to be checked
        :return: true if expression is left-shift false otherwise
        """
        return isinstance(expression, BinaryOperation) and expression.operation == OperationType.left_shift

    @staticmethod
    def _size_in_bytes(size: int) -> int:
        """
        :param size: size in bits (as we store in types)
        :return: size in bytes
        """
        if size == 1:
            raise RuntimeError(f"Unexpected size {size}")
        return int(size / BYTE_SIZE)

    @staticmethod
    def _is_valid_offset_class_combination(var_offsets: Set[int], mul_offsets: Set[int]) -> bool:
        """
        In case of valid array candidate, only var or only mul offsets should be present.
        Moreover, the present set should contain exactly one element since offset_value should be consistent over array accesses
        :param var_offsets: set of offset_values of var class
        :param mul_offsets: set of offset_values of mul class
        :return: True if conditions above satisfied, False otherwise
        """
        return (len(var_offsets) == 1 and not mul_offsets) ^ (len(mul_offsets) == 1 and not var_offsets)

    @staticmethod
    def _is_variable_cast(expression: Expression) -> bool:
        return (
            isinstance(expression, UnaryOperation)
            and expression.operation == OperationType.cast
            and (expression.type in {Integer.int32_t(), Integer.uint32_t(), Integer.int64_t(), Integer.uint64_t()})
            and isinstance(expression.operand, Variable)
        )
