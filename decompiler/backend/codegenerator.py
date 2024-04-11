"""Module in charge of bundling all classes utilized to generate c-code from an AST."""

from string import Template
from typing import Iterable, List

from decompiler.backend.cexpressiongenerator import CExpressionGenerator
from decompiler.backend.codevisitor import CodeVisitor
from decompiler.backend.variabledeclarations import GlobalDeclarationGenerator, LocalDeclarationGenerator
from decompiler.task import DecompilerTask


class CodeGenerator:
    """Class in charge of emitting C-code from pseudo code."""

    TEMPLATE = Template("""$return_type $name($parameters){$local_declarations$function_body}""")

    def __init__(self, declare_globals: bool = True):
        """
        Initialize a CodeGenerator instance with global settings.

        declare_globals -- whether global variable declarations should be included.
        """
        self._declare_globals = declare_globals
        self._variables_per_line = 1

    def generate(self, tasks: Iterable[DecompilerTask], run_cleanup: bool = True):
        """Generate C-Code for the given list of Tasks sharing global variables."""
        string_blocks: List[str] = []
        if self._declare_globals:
            string_blocks.append(GlobalDeclarationGenerator.from_asts(task.syntax_tree for task in tasks if not task.failed))
        for task in tasks:
            if run_cleanup and not task.failed:
                task.syntax_tree.clean_up()
            string_blocks.append(task.complex_types.declarations())
            string_blocks.append(self.generate_function(task))
        return "\n\n".join(string_blocks)

    def generate_function(self, task: DecompilerTask) -> str:
        """Generate C-Code for the function described in the given DecompilerTask."""
        if task.failed:
            return self.generate_failure_message(task)
        else:
            return self.TEMPLATE.substitute(
                return_type=task.function_return_type,
                name=task.name,
                parameters=", ".join(
                    map(lambda param: CExpressionGenerator.format_variables_declaration(param.type, [param.name]), task.function_parameters)
                ),
                local_declarations=LocalDeclarationGenerator.from_task(task),
                function_body=CodeVisitor(task).visit(task.syntax_tree.root),
            )

    @staticmethod
    def generate_failure_message(task: DecompilerTask):
        """Returns the message to be shown for a failed task."""
        msg = f"Failed to decompile {task.name}"
        if origin := task.failure_origin:  # checks if the string is empty (should never be None when this method is called)
            msg += f" due to error during {origin}."
        return msg
