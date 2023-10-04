from decompiler.pipeline.commons.expressionpropagationcommons import ExpressionPropagationBase
from decompiler.structures.pseudo.instructions import Assignment, Instruction


class ExpressionPropagation(ExpressionPropagationBase):
    name = "expression-propagation"

    def __init__(self):
        ExpressionPropagationBase.__init__(self)

    def _definition_can_be_propagated_into_target(self, definition: Assignment, target: Instruction):
        """Tests if propagation is allowed based on set of rules, namely
        definition can be propagated into target if:
        - definition is assignment
        - it is not call assignment <--- possibly subject of change
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
        return isinstance(definition, Assignment) and not (
                self._is_phi(definition)
                or self._is_call_assignment(definition)
                or self._defines_unknown_expression(definition)
                or self._contains_aliased_variables(definition)
                or self._is_address_assignment(definition)
                or self._contains_global_variable(definition)
                or self._operation_is_propagated_in_phi(target, definition)
                or self._is_invalid_propagation_into_address_operation(target, definition)
                or self._is_dereference_assignment(definition)
        )
