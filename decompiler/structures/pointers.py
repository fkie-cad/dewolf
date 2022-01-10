from collections import defaultdict
from typing import DefaultDict, Set

from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Assignment, BaseAssignment, BinaryOperation, Instruction, OperationType, Phi, UnaryOperation, Variable
from decompiler.structures.pseudo.typing import Pointer


class Pointers:
    def __init__(self):
        """
        First implementation of pointer information extraction
        points_to contains pointer as a key and set of aliased variable names onto which it points
        is_pointed_by contains aliased variable name as a key and set of pointers that point onto it as a value
        """
        self.points_to: DefaultDict[Variable, Set[str]] = defaultdict(set)
        self.is_pointed_by: DefaultDict[str, Set[Variable]] = defaultdict(set)

    def from_cfg(self, cfg: ControlFlowGraph):
        """Fills points_to and is_pointed_by with the corresponding pointer information for the given control flow graph"""
        self._collect_single_level_pointers(cfg)
        self._revert_points_to()
        return self

    def _collect_single_level_pointers(self, cfg: ControlFlowGraph):
        """
        collect ptrs from ptr = &var

        if there is assignment ptr1 = ptr2
            update set of vars pointed by ptr1 with set of pointed by ptr2
        if there is phi function ptr3 = phi(ptr1, ptr2)
            update set of vars pointed by ptr3 to union of sets pointed by its arguments
        """

        self._initialize_points_to(cfg)
        for instr in cfg.instructions:
            if self._is_copy_assignment(instr):
                if instr.value in self.points_to:
                    self.points_to[instr.destination].update(self.points_to[instr.value])
            if isinstance(instr, Phi):
                points_to_by_phi_target = set()
                for arg in instr.value.operands:
                    points_to_by_phi_target.update(self.points_to.get(arg, set()))
                self.points_to[instr.destination] = points_to_by_phi_target

    def _revert_points_to(self):
        """
        Create is_pointed_by by reverting keys and values of points_to
        """
        for pointer, aliased_variable_names in self.points_to.items():
            for var_name in aliased_variable_names:
                self.is_pointed_by[var_name].add(pointer)

    def _initialize_points_to(self, cfg: ControlFlowGraph):
        """
        Pointer points to variable if exist instruction ptr = &var
        Then add ptr to keys and var to its pointed set

        In case of dynamic arrays, we may have pointers without pointed aliased variables
        Hence, we add these pointers to points-to dict
        """
        for instr in cfg.instructions:
            if self._assigns_to_address_of(instr):
                if not isinstance(instr.value.operand, BinaryOperation):
                    self.points_to[instr.destination].add(instr.value.operand.name)
            self._add_pointers_without_aliased_variables(instr)

    def _add_pointers_without_aliased_variables(self, instr: Instruction):
        """
        Iterates through the requirements of instruction; if requirement has type pointer, adds it to
        the points-to with empty set of associated variables
        """
        for var in instr.requirements:
            if isinstance(var, Variable) and isinstance(var.type, Pointer):
                if var not in self.points_to:
                    self.points_to[var] = set()

    @staticmethod
    def _assigns_to_address_of(instruction: Instruction) -> bool:
        """
        :return: true if instruction looks like x = &y
        """
        return (
            isinstance(instruction, Assignment)
            and isinstance(val := instruction.value, UnaryOperation)
            and val.operation == OperationType.address
        )

    @staticmethod
    def _is_copy_assignment(instruction: Instruction) -> bool:
        """
        :return: true if instruction is an assignment that has variables only on the both sides
        """
        return (
            isinstance(instruction, BaseAssignment)
            and isinstance(instruction.destination, Variable)
            and isinstance(instruction.value, Variable)
        )
