from decompiler.pipeline.commons.expressionpropagationcommons import ExpressionPropagationBase
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pointers import Pointers
from decompiler.structures.pseudo.expressions import Constant
from decompiler.structures.pseudo.instructions import Assignment, Instruction
from decompiler.structures.pseudo.locations import InstructionLocation
from decompiler.task import DecompilerTask


class ExpressionPropagationFunctionCall(ExpressionPropagationBase):
    name = "expression-propagation-function-call"

    def __init__(self):
        ExpressionPropagationBase.__init__(self)

    def run(self, task: DecompilerTask):
        """
        Calculates pointers (and pointed by) for the cfg
        and runs EP
        :param task: decompiler task containing cfg
        """
        self._initialize_pointers(task.graph)
        super().run(task)

    def perform(self, graph, iteration) -> bool:
        """
        expression propagation forward pass:
            initialize defmap and use map
            iterate through all the blocks and all the instructions in the blocks
                 for each variable in instruction
                     iterate through uses of all vars and substitute the vars with their definitions
            # cfg and defmap are updated automatically when substituting variables in instructions
            # block map is updated after substitution in EPM, in EP does nothing
        """
        is_changed = False
        self._cfg = graph
        self._initialize_maps(graph)
        for basic_block in graph.nodes:
            for index, instruction in enumerate(basic_block.instructions):
                old = str(instruction)
                for var in instruction.requirements:
                    if def_location := self._def_map.get(var):
                        definition = def_location.instruction
                        if self._definition_can_be_propagated_into_target(def_location, InstructionLocation(basic_block, index)):
                            instruction.substitute(var, definition.value.copy())
                            self._replace_call_assignment_with_const(definition)  # differs from base
                            if not is_changed:
                                is_changed = old != str(instruction)
        return is_changed

    def _replace_call_assignment_with_const(self, definition: Assignment):
        """
        Replace Assignment with Constant Assignment e.g.:
        var = f() -->  var = 0x0
        """
        definition.substitute(definition.value, Constant(0x0))

    def _is_call_value_used_exactly_once(self, definition: Assignment) -> bool:
        """
        Check if call assignment is used exactly once.
        True on exactly one use.
        False otherwise, or Call has more than one return value.
        """
        if len(return_values := definition.destination.requirements) != 1:
            return False

        [required_variable] = return_values
        requiring_instructions = list(self._use_map.get(required_variable))

        if len(requiring_instructions) != 1:
            return False

        [requiring_instruction] = requiring_instructions

        usages = 0
        for variable in requiring_instruction.instruction.requirements_iter:
            if variable == required_variable:
                usages += 1
            if usages > 1:
                return False

        return usages == 1

    def _definition_can_be_propagated_into_target(self, definition_location: InstructionLocation, target_location: InstructionLocation):
        """Tests if propagation is allowed based on set of rules, namely
        - definition is call assignment
        - assigned variable is only used once
        - no dangerous uses in between target and definition
        - it is not address assignment <--- possibly subject of change
        - definition's LHS and RHS does not define or use a GlobalVariable <--- possibly subject to change.
        - definition contains aliased variables <--- aliased need special treatment and handled in EPM (memory)
        - it is not phi function as such propagation would violate ssa
        - target is phi function and definition's rhs is something else than constant or variable
        - propagation result is longer than propagation limits in task
        - definition rhs in address of definition's lhs as it leads to incorrect decompilation

        :param definition: definition to be propagated
        :param target: instruction in which definition could be propagated
        :return: true if propagation is allowed false otherwise
        """
        definition = definition_location.instruction
        target = target_location.instruction
        return (
            self._is_call_assignment(definition)
            and self._is_call_value_used_exactly_once(definition)
            and not (
                self._is_phi(definition)
                or self._defines_unknown_expression(definition)
                or self._contains_aliased_variables(definition)
                or self._is_address_assignment(definition)
                or self._contains_writeable_global_variable(definition)
                or self._operation_is_propagated_in_phi(target, definition)
                or self._is_invalid_propagation_into_address_operation(target, definition)
                or self._is_dereference_assignment(definition)
                or self._definition_value_could_be_modified_via_memory_access_between_definition_and_target(definition_location, target_location)
                or self._pointer_value_used_in_definition_could_be_modified_via_memory_access_between_definition_and_target(
                    definition_location, target_location
                )
            )
        )

    def _initialize_pointers(self, cfg: ControlFlowGraph):
        """Initialize pointer information for the given cfg"""
        self._pointers_info = Pointers().from_cfg(cfg)
