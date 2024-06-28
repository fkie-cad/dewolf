import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Iterator, Optional, Set

from decompiler.pipeline.preprocessing.util import init_maps
from decompiler.pipeline.ssa.phi_cleaner import PhiFunctionCleaner
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.maps import DefMap, UseMap
from decompiler.structures.pointers import Pointers
from decompiler.structures.pseudo import (
    Assignment,
    BaseAssignment,
    Call,
    DataflowObject,
    Expression,
    GlobalVariable,
    Instruction,
    Operation,
    OperationType,
    Phi,
    Relation,
    Return,
    UnaryOperation,
    UnknownExpression,
    Variable,
)
from decompiler.structures.pseudo.locations import InstructionLocation
from decompiler.task import DecompilerTask


class ExpressionPropagationBase(PipelineStage, ABC):
    name = "expression-propagation-base"

    def __init__(self):
        self._use_map: UseMap
        self._def_map: DefMap
        self._pointers_info: Optional[Pointers] = None
        self._cfg: Optional[ControlFlowGraph] = None
        # to collect aliased variables that should be propagated in a separate round after everything else
        # is propagated. For more details, see _is_aliased_postponed_for_propagation method.
        self._postponed_aliased: Set[Variable] = set()

    def run(self, task: DecompilerTask):
        """Execute the expression propagation on the current ControlFlowGraph."""
        iteration = 0
        # execute until there are no more changes
        while self.perform(task.graph, iteration):
            iteration += 1
        logging.info(f"{self.name} took {iteration} iterations")

    def perform(self, graph: ControlFlowGraph, iteration: int) -> bool:
        """expression propagation forward pass:
        initialize defmap and use map
        iterate through all the blocks and all the instructions in the blocks
             for each variable in instruction
                 iterate through uses of all vars and substitute the vars with their definitions
        # cfg and defmap are updated automatically when substituting variables in instructions
        # block map is updated after substitution in EPM, in EP does nothing
        # use map is updated after substitution in EPM, in EP does nothing
        """
        self._remove_redundant_phis(graph)

        self._cfg = graph
        self._initialize_maps(graph)

        is_changed = False
        for basic_block in graph.nodes:
            for index, instruction in enumerate(basic_block.instructions):
                old = str(instruction)
                self._try_to_propagate_contractions(instruction)
                for var in instruction.requirements:
                    if var_definition_location := self._def_map.get(var):
                        var_definition = var_definition_location.instruction
                        assert isinstance(var_definition, BaseAssignment)
                        if self._definition_can_be_propagated_into_target(var_definition_location, InstructionLocation(basic_block, index)):
                            instruction.substitute(var, var_definition.value.copy())
                            self._update_use_map(var, instruction)
                            if not is_changed:
                                is_changed = old != str(instruction)
        return is_changed

    def _remove_redundant_phis(self, graph: ControlFlowGraph):
        phi_functions_of = {node: [i for i in node.instructions if isinstance(i, Phi)] for node in graph.nodes}
        PhiFunctionCleaner(phi_functions_of).clean_up()

    @abstractmethod
    def _definition_can_be_propagated_into_target(self, definition: InstructionLocation, target_location: InstructionLocation) -> bool:
        """
        Tests (based on set of rules) if definition allowed to be propagated into target.
        Child classes EP and EPM should implement this method by deciding which exactly rules are tested in each case

        :param definition: definition to be propagated
        :param target: instruction in which the definition could be propagated
        :return: true if propagation is allowed false otherwise
        """
        pass

    def _initialize_maps(self, cfg: ControlFlowGraph) -> None:
        """
        Fills use and def maps.
        :param cfg: control flow graph for which the maps are computed
        """
        self._def_map, self._use_map = init_maps(cfg)

    def _update_use_map(self, variable: Variable, instruction: Instruction):
        """Do nothing if EP, EPM re-implements this method to update the map when instructions change"""
        pass

    def _propagate_postponed_aliased_definitions(self):
        """Do nothing if EP, EPM: one round of propagating postponed aliased definitions."""
        pass

    def _try_to_propagate_contractions(self, instruction: Instruction):
        """
        In case we have contraction in the instruction, we try to directly replace it in uses if contraction definition is same
        to contraction operand definition

        For instance:
        ebx = (:1) eax#2 <----- instruction
        Definition of eax#2:
        (:1) eax#2 = var_10 <----defines both eax#2 and its lower part, al, expressed as (:1) eax [contraction]

        So we could change ebx = (:1) eax#2 to ebx = var_10
        """
        target = instruction if not isinstance(instruction, Assignment) else instruction.value
        for subexpr in self._find_subexpressions(target):
            if self._is_variable_contraction(subexpr):
                if location := self._def_map.get(subexpr.operand):
                    definition = location.instruction
                    if isinstance(definition, Assignment) and self._is_address_assignment(definition):
                        continue
                    defined_contraction, value = definition.destination, definition.value
                    if subexpr == defined_contraction:
                        instruction.substitute(subexpr, value.copy())

    def _is_aliased_postponed_for_propagation(self, target: Instruction, definition: Assignment) -> bool:
        """
        We are not allowed to always propagate aliased definitions that we insert during missing definition stage
        Consider the following:
        0: a#1 = 0
        1: b#1 = 0
        2: func(&b#1)
        3: b#2 <- b#1 (relation, b - aliased, inserted by us)
        4: a#2 = a#1 (assignment, a - aliased, inserted by us)
        5: func(&a#1) (after 1st propagation round)
        6: a#3 <- a#2
        7: ...
        8: ret a#3

        Propagating a#1 = 0 (line 0) into a#2 = a#1 (line 4) leads to wrong decompiled code, since connection between aliased versions of variable a is removed:
        0: a = 0
        1: b = 0
        2: func(&b)
        3: a1 = 0 // a#2 = 0, since we propagated a#1 = 0 into a#2 = a#1
        4: func(&a)
        5: ...
        6: ret a1

        We can propagate this in case the variable is used once (in the example used twice). This way we revert insertion of redundant missing definition.
        If possible, such propagation is done after everything else is propagated.
        """
        if self._is_aliased_variable(aliased := definition.destination):
            if self._is_aliased_redefinition(aliased, target):
                self._postponed_aliased.add(aliased)
                return True
        return False

    def _is_invalid_propagation_into_address_operation(self, target: Instruction, definition: Assignment) -> bool:
        """
        Check if the given propagation would propagate anything into an address operation.
        e.g. a = &x, a = *(&x), a = cast(&x), a = &x + c
        x = 5 -- Should not be propagated
        x = a -- Should not be propagated
        x = a + 10 -- Should not be propagated
        """

        if isinstance(target, Assignment):
            subexpressions = list(self._find_subexpressions(target.destination))
            subexpressions.extend((expr for expr in self._find_subexpressions(target.value)))
            return any(
                (self._is_address(expr) and expr.operand in self._find_subexpressions(definition.destination) for expr in subexpressions)
            )
        elif isinstance(target, Return):
            subexpressions = list(self._find_subexpressions(target))
            return any(
                (self._is_address(expr) and expr.operand in self._find_subexpressions(definition.destination) for expr in subexpressions)
            )
        return False

    def _operation_is_propagated_in_phi(self, target: Instruction, definition: Assignment) -> bool:
        """Only constants and variables are propagated in Phi,
        do not allow phi arguments to be unary or binary operations"""
        return isinstance(target, Phi) and isinstance(definition.value, Operation)

    def _is_address_assignment(self, definition: Assignment) -> bool:
        """
        Currently propagating a = &x into uses of a causes problems (see test21 in test_memory). So for the moment is not propagated.
        """
        return self._is_address(definition.value)

    def _is_dereference_assignment(self, definition: Assignment) -> bool:
        """
        We do not want to propagate dereference assignments during EP; EPM will check later, if the propagation should be allowed

        We check subexpressions instead of only right hand side of definitions cause e.g. both
        x = *(ptr+...) and x = (int) *(ptr+...) should not be propagated on this stage
        :param definition: assignment to be tested
        :return: true if assignment has dereference on the right-hand-side, e.g. x = *ptr; false ow
        """
        return any([self._is_dereference(x) for x in self._find_subexpressions(definition.value)])

    def _is_address_into_dereference(self, definition: Assignment, target: Instruction) -> bool:
        """
        Potentially we want to propagate a = &x into uses of a, in case uses are not *(a) etc.
        Switch this on when no problems with test21 test_memory occurs.
        """
        if self._is_address(definition.value):
            for subexpr in target:
                for sub in self._find_subexpressions(subexpr):
                    if self._is_dereference(sub) and sub.operand in definition.definitions:
                        return True
        return False

    def _contains_aliased_variables(self, definition: Assignment) -> bool:
        """
        Assignments containing aliased variables should not be propagated during non-memory EP
        :param definition: instruction to be tested
        :return: true if it is assignment with aliased false otherwise
        """
        return any([self._is_aliased_variable(expr) for expr in self._find_subexpressions(definition)])

    def _pointer_value_used_in_definition_could_be_modified_via_memory_access_between_definition_and_target(
        self, definition_location: InstructionLocation, target_location: InstructionLocation
    ) -> bool:
        """Do not propagate definition with dereference on the right-hand-side, if a modification of a value via its pointer
        lies between definition and target

         E.g. here x should not be propagated since func(ptr) may change the pointed value
         x = *(ptr+offset)
         func(ptr)
         use x

         We iterate though subexpressions of definition left hand side cause the definition could be of form:
         x = (int) *(ptr+offset)
         :param definition: instruction to be tested
         :return true if modification is possible false otherwise

        """
        definition = definition_location.instruction
        assert isinstance(definition, Assignment)
        for subexpr in self._find_subexpressions(definition.value):
            if self._is_dereference(subexpr):
                for variable in subexpr.requirements:
                    if variable in self._pointers_info.points_to:
                        dangerous_uses = self._get_dangerous_uses_of_pointer(variable)
                        return self._has_any_of_dangerous_uses_between_definition_and_target(definition_location, target_location, dangerous_uses)
        return False

    def _definition_value_could_be_modified_via_memory_access_between_definition_and_target(
        self, definition_location: InstructionLocation, target_location: InstructionLocation
    ) -> bool:
        """
        Tests for definition containing aliased if a modification of the aliased value is possible, i.e.
        via its pointer (ptr = &aliased) or via use of its reference (aka address) in function calls
        or if a relation is in between.

        :return: true if a modification of the aliased value is possible (hence, the propagation should be avoided) false otherwise
        """
        for aliased_variable in set(self._iter_aliased_variables(definition_location.instruction)):
            dangerous_address_uses = self._get_dangerous_uses_of_variable_address(aliased_variable)
            dangerous_pointer_uses = self._get_dangerous_uses_of_pointer_to_variable(aliased_variable)
            dangerous_alias_uses = self._get_dangerous_relations_between_definition_and_target(aliased_variable)
            dangerous_uses = dangerous_pointer_uses | dangerous_address_uses | dangerous_alias_uses
            if dangerous_uses:
                if self._has_any_of_dangerous_uses_between_definition_and_target(definition_location, target_location, dangerous_uses):
                    return True
        return False

    def _has_any_of_dangerous_uses_between_definition_and_target(
        self, definition_location: InstructionLocation, target_location: InstructionLocation, dangerous_uses: set[InstructionLocation]
    ) -> bool:
        """
        Checks if any instruction from the set of dangerous uses lies on the way between definition and target(s)
        :param definition: definition to be propagated
        :param target: instruction in which it could be propagated (it can happen, that target is not unique, so we check
        for all the occurrences of target)
        :param dangerous_uses: set of instructions that may modify aliased variables from definitions via its pointer or &
        :type dangerous_uses:
        :return: true if there exist at least one path containing any of dangerous instructions  between definition and target, false otherwise
        """
        definition_block = definition_location.block
        definition_index = definition_location.index
        target_block = target_location.block
        target_index = target_location.index

        for use_location in dangerous_uses:
            use_block = use_location.block
            use_index = use_location.index

            # if dangerous use in the same block as target, its index should be less than target index
            if use_block == target_block:
                if use_index < target_index:
                    return True
            # if dangerous use in the same block as definition, its index should be greater than definition index
            elif use_block == definition_block:
                if use_index > definition_index:
                    return True
            else:
                # if dangerous use block is different than target or definition block
                # then it should lie at at least one path between definition and target blocks
                if self._cfg.has_path(definition_block, use_block) and self._cfg.has_path(use_block, target_block):
                    return True
        return False

    def _get_dangerous_uses_of_variable_address(self, var: Variable) -> set[InstructionLocation]:
        """
        Dangerous use of & of x is func(&x) cause it can potentially modify x.
        Another case is an Assignment where the left side is *(&).
        :param var: aliased variable
        :return: set of function call assignments that take &var as parameter
        """
        dangerous_uses = set()
        for use_location in self._use_map.get(var):
            use = use_location.instruction
            if not self._is_call_assignment(use) and not (isinstance(use, Assignment) and self._is_dereference(use.destination)):
                continue
            for subexpr in self._find_subexpressions(use):
                if self._is_address(subexpr):
                    dangerous_uses.add(use_location)
                    break
        return dangerous_uses

    def _get_dangerous_uses_of_pointer_to_variable(self, var: Variable) -> set[InstructionLocation]:
        """
        Dangerous use of pointer is using it in function call cause func(ptr) could potentially
        change value of pointed variable and *ptr = ... cause it changes value of pointed variable,
        but this change is not reflected in use map
        :param var: aliased variable that has pointers on it
        :return: set of instructions that could implicitly change aliased variable via its pointers
        """

        is_pointed_by = self._pointers_info.is_pointed_by.get(var.name, set())
        dangerous_uses = set()
        for pointer in is_pointed_by:
            dangerous_uses.update(self._get_dangerous_uses_of_pointer(pointer))
        return dangerous_uses

    def _get_dangerous_relations_between_definition_and_target(self, alias_variable: Variable) -> set[InstructionLocation]:
        """Return all relations of the alias variable."""
        relations = set()
        # Collect all relations for alias_variable ignoring SSA
        for basic_block in self._cfg:
            for index, instruction in enumerate(basic_block):
                if isinstance(instruction, Relation) and instruction.destination.name == alias_variable.name:
                    relations.add(InstructionLocation(basic_block, index))

        return relations

    def _get_dangerous_uses_of_pointer(self, pointer: Variable) -> set[InstructionLocation]:
        """
        :param pointer to a variable
        :return: set of instructions that may potentially change the value pointed by the given pointer. To such instructions belong:
        - ret_val = func(ptr) - function call may modify value pointed by the ptr
        - *ptr = new_val - pointer dereference assignment may change the value pointed by the ptr
        - *(ptr + offset) = new_val - potential change of structure member or array element
        """
        dangerous_uses = set()
        for use_location in self._use_map.get(pointer):
            use = use_location.instruction
            if not isinstance(use, Assignment):
                continue
            if self._is_dereference(use.destination) and pointer in use.destination.requirements:
                dangerous_uses.add(use_location)
            elif self._is_call_assignment(use) and pointer in use.value.requirements:
                dangerous_uses.add(use_location)
        return dangerous_uses

    def _iter_aliased_variables(self, expression: DataflowObject) -> Iterator[Variable]:
        """iterate all aliased variables in the given exression."""
        for expression in self._find_subexpressions(expression):
            if self._is_aliased_variable(expression):
                yield expression

    @staticmethod
    def _find_subexpressions(expression: DataflowObject) -> Iterator[Expression]:
        """Yield all subexpressions of the given expression."""
        todo = [expression]
        while todo and (subexpression := todo.pop()):
            todo.extend(subexpression)
            yield subexpression

    @staticmethod
    def _is_phi(instruction: Instruction) -> bool:
        """
        :param instruction: instruction to be tested
        :return: true if the instruction is phi-function, false otherwise
        """
        return isinstance(instruction, Phi)

    @staticmethod
    def _is_call_assignment(instruction: Instruction) -> bool:
        """
        :param instruction: instruction to be tested
        :return: true if the instruction is an assignment of function call, e.g.
        a = func() or func() ([] = func())
        """
        return isinstance(instruction, Assignment) and isinstance(instruction.value, Call)

    @staticmethod
    def _defines_unknown_expression(instruction: Instruction) -> bool:
        """
        :param instruction: instruction to be tested
        :return: true if the instruction is an assignment where the RHS is a UnknownExpression, false otherwise
        """
        return isinstance(instruction, Assignment) and isinstance(instruction.value, UnknownExpression)

    @staticmethod
    def _is_address(expression: Expression) -> bool:
        """
        :param expression: expression to be tested
        :return: true if the expression is address operation i.e. &expression false otherwise
        """
        return isinstance(expression, UnaryOperation) and expression.operation == OperationType.address

    @staticmethod
    def _is_dereference(expression: Expression) -> bool:
        """
        :param expression: expression to be tested
        :return: true if the expression is dereference operation i.e. *expression false otherwise
        """
        return isinstance(expression, UnaryOperation) and expression.operation == OperationType.dereference

    @staticmethod
    def _is_aliased_variable(expression: Expression) -> bool:
        """
        :param expression: expression to be tested
        :return: true if the expression is an aliased variable
        """
        return isinstance(expression, Variable) and expression.is_aliased

    @staticmethod
    def _contains_writeable_global_variable(expression: Assignment) -> bool:
        """
        :param expression: Assignment expression to be tested
        :return: true if any requirement of expression is a writeable GlobalVariable
        """
        for expr in expression.destination.requirements:
            if isinstance(expr, GlobalVariable) and not expr.is_constant:
                return True
        for expr in expression.value.requirements:
            if isinstance(expr, GlobalVariable) and not expr.is_constant:
                return True
        return False

    @staticmethod
    def _is_copy_assignment(instruction: Instruction) -> bool:
        """
        :param instruction:  expression to be tested
        :return: true if the expression is a copy assignment (e.g. a = b or a = 10)
        """
        return isinstance(instruction, Assignment) and instruction.value.complexity == 1

    @staticmethod
    def _is_variable_contraction(expression: Expression) -> bool:
        """

        :param expression: expression to be tested
        :return: true if expression is variable contraction, e.g. eax.al
        since those are lifted as cast(eax, char, contraction)
        """
        return (
            isinstance(expression, UnaryOperation)
            and expression.operation == OperationType.cast
            and expression.contraction
            and expression.operand.complexity == 1
        )

    def _is_aliased_redefinition(self, aliased_variable: Variable, instruction: Instruction):
        """
        Given aliased variable check if the instruction is re-definition:
        e.g. variable: a#10,  instruction: a#11 = a#10 redefines aliased variable a#10
        :param aliased_variable: variable to be tested
        :param instruction: instruction to be tested
        """
        return (
            isinstance(instruction, Assignment)
            and self._is_aliased_variable(instruction.destination)
            and self._is_aliased_variable(instruction.value)
            and instruction.destination.name == aliased_variable.name == instruction.value.name
        )
