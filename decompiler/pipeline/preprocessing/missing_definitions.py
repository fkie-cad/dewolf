"""Module dedicated to insert definitions for otherwise definitionless values."""
from collections import defaultdict
from logging import error
from typing import DefaultDict, Dict, List, Optional, Set, Tuple, Union

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pointers import Pointers
from decompiler.structures.pseudo.expressions import GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, Instruction, Phi, Relation
from decompiler.structures.pseudo.operations import Call, ListOperation
from decompiler.task import DecompilerTask
from networkx import DiGraph

from .util import _init_basicblocks_of_definition, _init_basicblocks_usages_variable, _init_maps


class _VariableCopyPool:
    """Handles the copies of variables with the same name"""

    def __init__(self, all_variables: Set[Variable]):
        """
        Creates a new VariableCopyPool instance, where the given set of variables is the set of all variables of which we may want to
        handle the copies.

            - self._copies_of_variable: dictionary that maps to each variable name all copies.
            - self._sorted_copies_of: a dictionary that maps to each variable name all copies sorted by their SSA-label, if we already
              sorted them.
        """
        self._copies_of_variable: DefaultDict[str, Set[Variable]] = defaultdict(set)
        self._initialize_copy_dict(all_variables)
        self._sorted_copies_of: Dict[str, List[Variable]] = dict()

    def _initialize_copy_dict(self, all_variables: Set[Variable]):
        """Initializes the attribute _copies_of_variable with the given set of variables."""
        for variable in all_variables:
            self._copies_of_variable[variable.name].add(variable)

    def get_sorted_copies_of(self, variable: Union[str, Variable]) -> List[Variable]:
        """Returns a list of sorted copies of the given variable."""
        variable = self._get_variable_name(variable)
        if variable not in self._sorted_copies_of:
            self.sort_copies_of(variable)
        return self._sorted_copies_of[variable]

    def sort_copies_of(self, *variables: Union[str, Variable]):
        """sorts all copies of the given variables."""
        for variable in variables:
            var_name = self._get_variable_name(variable)
            self._sorted_copies_of[var_name] = sorted(self._copies_of_variable[var_name], key=lambda var: var.ssa_label)
            self._insert_label_zero_for_aliased_if_missing(var_name)

    def _insert_label_zero_for_aliased_if_missing(self, var_name: str):
        """
        If the copy with the smallest SSA-label is an aliased variable whose label is not zero, then we insert a copy with label zero
        at the first position of the sorted list.
        """
        first_copy = self.get_smallest_label_copy(var_name)
        if first_copy.ssa_label > 0 and first_copy.is_aliased:
            first_copy = Variable(var_name, first_copy.type, 0, is_aliased=True)
            self._sorted_copies_of[var_name].insert(0, first_copy)

    def get_smallest_label_copy(self, variable: Union[str, Variable]):
        """Returns the copy with the smallest SSA-label, i.e. the first one."""
        variable = self._get_variable_name(variable)
        if variable in self._sorted_copies_of[variable]:
            return self._sorted_copies_of[variable][0]
        return min(self._copies_of_variable[variable], key=lambda var: var.ssa_label)

    def possible_missing_definitions_for(self, variable: Union[str, Variable]) -> List[Variable]:
        """Returns all variables whose definition may be missing because it is not the first in the order."""
        var_name = self._get_variable_name(variable)
        return self._sorted_copies_of[var_name][1:]

    @staticmethod
    def _get_variable_name(variable_name: Union[str, Variable]) -> str:
        """Returns the name of the given variable."""
        if isinstance(variable_name, Variable):
            variable_name = variable_name.name
        return variable_name


class InsertMissingDefinitions(PipelineStage):
    """
    The InsertMissingDefinitions adds definitions for all undefined variables.

    - For each aliased variable we insert the definition after instruction where the memory-value, that is equal to its SSA-label is set.
    - For each non-aliased variable we have to find a node that dominates all usages.
    - To figure out which variable should be on the right-hand-side of the definition, we have to find a copy, whose SSA-label is smaller
      than the SSA-label of the variable whose definition we want to inserts, and whose definition dominates the definition we insert.
    """

    name = "insert-missing-definitions"

    def run(self, task: DecompilerTask):
        """Insert all missing definitions."""
        self._setup(task.graph)
        self._check_ssa_label_for_all_variables()
        self.insert_missing_definitions()

    def _setup(self, cfg: ControlFlowGraph):
        """Initialize all necessary attributes."""
        self.cfg: ControlFlowGraph = cfg
        self._def_map, self._use_map = _init_maps(self.cfg)
        self._basicblock_usages_variable: DefaultDict[Variable, Set[BasicBlock]] = _init_basicblocks_usages_variable(self.cfg)
        self._basicblock_definition_variable: Dict[Variable, BasicBlock] = _init_basicblocks_of_definition(self.cfg)
        self._node_of_memory_version: Dict[int, Tuple[BasicBlock, Assignment]] = self._compute_node_of_memory_version()
        self._dominator_tree: DiGraph = self.cfg.dominator_tree
        self._pointers_info: Optional[Pointers] = Pointers().from_cfg(self.cfg)

    def insert_missing_definitions(self):
        """
        The function inserts a definition for an undefined aliased variable v#i.

        - We assume that every non-aliased variable is define if for all other copies v#j it holds i<j. Here we assume that v#i is defined
          from the beginning.
        - If variable v#i is an aliased variable then we insert the definition after the instruction where the memory version,
        that corresponds to the SSA-label, is set.
        - Depending whether the memory-changing instruction changes the aliased-variable we insert the definition as an assignment
          (no change) or a relation (change).
        """
        undefined_variables: Set[Variable] = self._get_undefined_variables()
        variable_copies: _VariableCopyPool = _VariableCopyPool(undefined_variables | self._def_map.defined_variables)
        variable_copies.sort_copies_of(*undefined_variables)

        for var_name in {variable.name for variable in undefined_variables}:
            first_copy = variable_copies.get_smallest_label_copy(var_name)
            if first_copy not in self._basicblock_definition_variable.keys():
                self._basicblock_definition_variable[first_copy] = self.cfg.root

            previous_ssa_labels = {first_copy.ssa_label}
            for variable in variable_copies.possible_missing_definitions_for(var_name):
                self._insert_definition_if_undefined(variable, previous_ssa_labels, undefined_variables)
                previous_ssa_labels.add(variable.ssa_label)

    def _get_undefined_variables(self) -> Set[Variable]:
        """
        Compute the set of undefined variables.

        -> We assume that every aliased variable has to be defined for every memory version.
        """
        undefined_variables = self._use_map.used_variables - self._def_map.defined_variables
        all_variables = self._use_map.used_variables | self._def_map.defined_variables

        aliased_names = {(variable.name, variable.type, isinstance(variable, GlobalVariable), variable) for variable in all_variables if variable.is_aliased}

        for memory_version in self._node_of_memory_version.keys():
            for var_name, var_type, is_global, variable in aliased_names:
                if is_global:
                    aliased_variable = variable.copy()
                else:
                    aliased_variable = Variable(var_name, var_type, memory_version, is_aliased=True)
                if aliased_variable not in all_variables:
                    undefined_variables.add(aliased_variable)
        return undefined_variables

    def _insert_definition_if_undefined(self, variable: Variable, previous_ssa_labels: Set[int], undefined_variables: Set[Variable]):
        """Insert definition for the given variable if it is undefined or raises an error when it is a not an aliased variable."""
        if variable in undefined_variables:
            if not variable.is_aliased:
                raise ValueError(f"Every non-aliased variable should be defined, but variable {variable} has no definition.")
            self._insert_definition_of_aliased(variable, previous_ssa_labels)

    def _insert_definition_of_aliased(self, variable: Variable, prev_ssa_labels: Set[int]) -> None:
        """
        This functions inserts the Assignment 'variable = prev_variable' if the value of the aliased variable does not change in the
        memory-changing assignment and the Relation 'variable -> prev_variable' if the value changes.

        - Recall: each SSA-label corresponds to a memory version.
        - The definition of prev_variable must dominate all usages of variable.
        - We insert this Assignment/Relation after the instruction where the memory version changes, that corresponds to the SSA-label of
        'variable', is set.

        :param variable: The variable whose definition we want to insert.
        :param prev_ssa_labels: The labels of the ssa-variables of this aliased-variable that are already defined.
        """
        self._check_definition_is_insertable(variable)
        basicblock_for_definition, memory_instruction = self._node_of_memory_version[variable.ssa_label]

        position_insert_definition = self._find_position_to_insert_aliased_definition(basicblock_for_definition, memory_instruction)
        ssa_label_rhs_variable = self._get_ssa_label_of_rhs_variable(basicblock_for_definition, prev_ssa_labels)
        if isinstance(variable, GlobalVariable):
            rhs_variable = variable.copy()
            rhs_variable.ssa_label = ssa_label_rhs_variable
        else:
            rhs_variable = Variable(variable.name, variable.type, ssa_label_rhs_variable, True)

        if self._memory_instruction_changes_variable(memory_instruction, rhs_variable):
            definition = Relation(variable, rhs_variable)
        else:
            definition = Assignment(variable, rhs_variable)
        basicblock_for_definition.instructions.insert(position_insert_definition, definition)

        self._update_pointer_info_for(definition)
        self._update_usages_and_definitions(definition, basicblock_for_definition)


    def _find_position_to_insert_aliased_definition(self, basicblock: BasicBlock, memory_instruction: Instruction) -> int:
        """
        Find & returns the position in the given basic block where we can add the definition of the undefined variable.
          - We insert the definition directly after the given instruction which changes the memory version.
          - If this would imply that a Phi-function is after the definition, then something went wrong during the ConvertMemPhi functions,
           because a variable with SSA-label that relates to a MemPhi function was not translated to a Phi function.

        :param basicblock: The basic block where we want to insert the definition.
        :param memory_instruction:  The memory_instruction where we 'define' the memory-version that corresponds to the SSA-label of the
        variable that is on the right-hand-side of the definition we want to insert.
        :return: The position in the basic block where we insert the Definition.
        """
        last_phi_instruction = self._find_position_of_last_phi_function_in(basicblock)
        position_insert_definition = self._get_insertion_position(memory_instruction, basicblock)
        if last_phi_instruction < position_insert_definition:
            return position_insert_definition

        error_message = f"Can not insert a definition before the last Phi-function of a basic block."
        error(error_message)
        raise ValueError(error_message)

    @staticmethod
    def _get_insertion_position(memory_instruction: Instruction, basicblock: BasicBlock) -> int:
        """
        Compute the position at which we insert the missing definition in the given basic block that contains the given instruction
        increasing the memory value.
        """
        starting_search = 0
        while starting_search <= len(basicblock):
            position_insert_definition = basicblock.instructions.index(memory_instruction, starting_search) + 1
            if basicblock.instructions[position_insert_definition - 1].writes_memory == memory_instruction.writes_memory:
                return position_insert_definition
            starting_search = position_insert_definition

        raise ValueError(f"We did not find the given instruction in the given Basic Block.")

    def _get_ssa_label_of_rhs_variable(self, basicblock_for_definition: BasicBlock, prev_ssa_labels: Set[int]) -> int:
        """
        Computes the highest memory version that dominates the given basic block where we want to insert the definition.

        :param basicblock_for_definition: The basic block where we want to insert the definition
        :param prev_ssa_labels: All SSA-labels, and thus also all memory-version, that are smaller than the SSA-label of the variable whose
        definition we want to insert and that are used by copies of this variable.
        :return: The memory_version resp. SSA-label of the variable that is assigned to the undefined variable.
        """
        last_known_memory_versions_in: Dict[BasicBlock, int] = self._compute_last_known_memory_version_in_each_basicblock(prev_ssa_labels)

        current_basicblock = basicblock_for_definition
        while current_basicblock not in last_known_memory_versions_in.keys():
            current_basicblock = next(iter(self._dominator_tree.get_predecessors(current_basicblock)), None)
            if current_basicblock is None:
                raise ValueError(
                    f"No definition of a previous copy dominates the basic block {basicblock_for_definition} where we want to insert the "
                    f"definition"
                )

        return last_known_memory_versions_in[current_basicblock]

    def _compute_last_known_memory_version_in_each_basicblock(self, prev_ssa_labels: Set[int]) -> Dict[BasicBlock, int]:
        """
        Computes for each basic block the last memory version among the given set of memory version that is contains.

        :param prev_ssa_labels: All SSA-labels, and thus also all memory-version, that are smaller than the SSA-label of the variable whose
        definition we want to insert and that is used by copies of this variable.
        :return: A dictionary that maps to each basic block that contains a given memory version, the last one it contains.
        """
        last_known_memory_version_in: Dict[BasicBlock, int] = dict()
        for memory_version in prev_ssa_labels:
            basicblock, _ = self._node_of_memory_version[memory_version]
            if basicblock not in last_known_memory_version_in or last_known_memory_version_in[basicblock] < memory_version:
                last_known_memory_version_in[basicblock] = memory_version

        return last_known_memory_version_in

    def _memory_instruction_changes_variable(self, memory_instruction: Instruction, variable: Variable) -> bool:
        """Checks whether the memory instruction may change the value of the given variable."""
        if self._is_printing_call(memory_instruction):
            return False
        return self._uses_variable_related_to_aliased_variable(memory_instruction, variable)

    def _uses_variable_related_to_aliased_variable(self, memory_instruction: Instruction, variable: Variable) -> bool:
        """Checks whether the given instruction, uses the given variable or a variable that is related to it (pointer)."""
        for usage in memory_instruction.requirements:
            if usage == variable or (self._pointers_info and usage in self._pointers_info.is_pointed_by[variable.name]):
                return True
        return False

    def _check_definition_is_insertable(self, variable: Variable) -> None:
        """
        Checks whether we can insert a definition for the given variable, i.e., the memory-version that corresponds to the label exists and
        does not belong to a Phi-function.
        """
        if variable.ssa_label not in self._node_of_memory_version.keys():
            error_message = (
                f"Memory version {variable.ssa_label} does not exist. So we can not insert the definition of the aliased "
                f"variable {variable}."
            )
            error(error_message)
            raise ValueError(error_message)
        _, memory_instruction = self._node_of_memory_version[variable.ssa_label]
        if isinstance(memory_instruction, Phi):
            error_message = (
                f"Variable {variable} should have been defined during 'ExtendPhiFunctions' because memory version {variable.ssa_label} "
                f"depends on the memory versions {[variable.ssa_label for variable in memory_instruction.requirements]}"
            )
            error(error_message)
            raise ValueError(error_message)

    def _check_ssa_label_for_all_variables(self):
        """
        The functions checks whether all variables have an SSA-label and raises an Error if at least one variable has no SSA-label.
        """
        for variable in self._def_map.defined_variables | self._use_map.used_variables:
            if variable.ssa_label is None:
                error_message = f"Something went wrong during lifting. Variable {variable} has no SSA-label"
                error(error_message)
                raise ValueError(error_message)

    def _update_pointer_info_for(self, definition: Union[Assignment, Relation]):
        """Updates the pointer information after adding the given definition to the cfg."""
        assert isinstance(definition.value, Variable) and isinstance(definition.destination, Variable)
        self._pointers_info.points_to[definition.value].update(self._pointers_info.points_to[definition.destination])

    def _update_usages_and_definitions(self, definition: Union[Assignment, Relation], basicblock: BasicBlock) -> None:
        """
        After inserting the given definition in the given basic block we have to update the usage and definition information.
        """
        assert isinstance(definition.value, Variable) and isinstance(definition.destination, Variable)
        self._def_map.add(definition)
        self._use_map.add(definition)
        self._basicblock_usages_variable[definition.value].add(basicblock)
        self._basicblock_definition_variable[definition.destination] = basicblock

    def _compute_node_of_memory_version(self) -> Dict[int, Tuple[BasicBlock, Assignment]]:
        """
        This function computes for each memory-version the node and instruction where the memory-version is 'defined'.
            - For MemPhi functions, that were replaced by multiple Phi functions, we pick the "last" phi-function.
            - Memory version 0 is set at the beginning, but not at a certain assignment.

        :return: A dictionary, where the set of keys is the set of memory-version that belong to an Assignment, and the value for
                each key is a tuple (BasicBlock, Assignment), where the BasicBlock is the basicblock where the Assignment
                where the memory version (key) is set.
        """
        node_of_memory_version: Dict[int, Tuple[BasicBlock, Assignment]] = dict()

        for basicblock in self.cfg.nodes:
            for instruction in basicblock.instructions:
                if isinstance(instruction, Assignment) and instruction.writes_memory is not None:
                    node_of_memory_version[instruction.writes_memory] = (basicblock, instruction)

        node_of_memory_version[0] = (self.cfg.root, Assignment(ListOperation([]), ListOperation([])))
        return node_of_memory_version

    @staticmethod
    def _find_position_of_last_phi_function_in(basicblock: BasicBlock) -> int:
        """
        Returns the position of the last Phi-function in the given basic block.
        """
        last_phi_instruction = -1
        for index, instruction in enumerate(basicblock.instructions):
            if isinstance(instruction, Phi):
                last_phi_instruction = index

        return last_phi_instruction

    @staticmethod
    def _is_printing_call(memory_instruction: Instruction) -> bool:
        """Checks whether the memory instruction is a function call that prints something"""
        return (
            isinstance(memory_instruction, Assignment)
            and isinstance(call := memory_instruction.value, Call)
            and str(call.function) in ["printf", "__printf_chk", "puts"]
        )
