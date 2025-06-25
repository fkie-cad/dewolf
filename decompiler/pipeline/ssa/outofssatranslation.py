"""Module implementing Out of SSA."""

import logging
from collections import defaultdict
from configparser import NoOptionError
from enum import Enum
from typing import Callable, DefaultDict, List

from decompiler.pipeline.ssa.phi_cleaner import PhiFunctionCleaner
from decompiler.pipeline.ssa.phi_dependency_resolver import PhiDependencyResolver
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.variable_renaming import ConditionalVariableRenamer, MinimalVariableRenamer, SimpleVariableRenamer
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.instructions import Phi
from decompiler.task import DecompilerTask
from decompiler.pipeline.ssa.sreedhar_out_of_ssa import SreedharOutOfSsa


class SSAOptions(Enum):
    """Enumerator for the different optimization options for the variable renaming in out of SSA"""

    simple = "simple"
    minimization = "min"
    lift_minimal = "lift_minimal"
    conditional = "conditional"
    sreedhar = "sreedhar"


class OutOfSsaTranslation(PipelineStage):
    """Implements Out of SSA by first removing the cyclic dependency of the Phi-functions and then renaming the variables.

    Some general remarks:
        - Liveness and Interference graph only work for programs in SSA-form.
        - After lifting the Phi-functions to the predecessor blocks the program is no longer in SSA-from.

    There are many possible modifications, in general every algorithm should contain the following 4 steps:
        - Resolve the circular dependency of the phi-functions
            Attention: This algorithm does not need the interference graph and **does not** update the interference graph.
        - Lift the Phi-functions to the predecessor blocks.
            Attention: This is only correct if there is no circular dependency of the Phi-functions.
            Furthermore, we need the interference graph, and we will update it.
        - Construct a dictionary that maps the each variable its new name.
        - Update the control flow graph according to the renaming.
    """

    name = "out-of-ssa-translation"

    options = {
        SSAOptions.simple.value: "renames a SSA-variable to a non SSA-variable by adding the label to the name",
        SSAOptions.minimization.value: "renames the SSA-variables such that the total number of non SSA-variables is minimal and "
        "then lifts the phi-functions",
        SSAOptions.lift_minimal.value: "first lifts the phi-functions and renames the SSA-variables such that the total number of "
        "non SSA-variables is (almost) minimal",
        SSAOptions.conditional.value: "first lifts the phi-functions and renames the SSA-variables according to their dependencies.",
        SSAOptions.sreedhar.value: "out-of-SSA due to Sreedhar et. al.",
    }

    def __init__(self):
        """Generate a new out-of-ssa-object with the minimum level as default option."""
        self.task = None
        self.interference_graph: InterferenceGraph
        self._optimization = SSAOptions.lift_minimal
        self._phi_functions_of: DefaultDict[BasicBlock, List[Phi]] = defaultdict(list)

    def _setup(self, task: DecompilerTask):
        self.task = task
        self._init_phi_functions_of_block()
        PhiFunctionCleaner(self._phi_functions_of).clean_up()

        try:
            self._optimization = SSAOptions(task.options.getstring(f"{self.name}.mode"))
        except (NoOptionError, ValueError, AttributeError):
            error_message = (
                f"The option [{self.name}] mode = {task.options.getstring(f'{self.name}.mode', fallback='')} does not exist. "
                f"Perhaps you misspelled it. The possible options are {[item.value for item in SSAOptions]}"
            )
            logging.error(error_message)
            raise NameError(error_message)

    def run(self, task: DecompilerTask) -> None:
        """Execute the PipelineStage on the current ControlFlowGraph."""
        self._setup(task)
        self._out_of_ssa()
        pass

    def _init_phi_functions_of_block(self) -> None:
        """This function initializes the dictionary that maps to each basic block the list of its Phi-instructions."""
        for basicblock in self.task.graph.nodes:
            if phi_instructions := [instruction for instruction in basicblock.instructions if isinstance(instruction, Phi)]:
                self._phi_functions_of[basicblock] = phi_instructions

    def _out_of_ssa(self) -> None:
        """
        This function does the overall out of SSA-translation:
            - removes Phi-functions
            - renames the variables

        -> There are different optimization levels
        """
        strategy = self.out_of_ssa_strategy.get(self._optimization, None)
        if strategy is None:
            raise NotImplementedError(
                f"The Out of SSA according to the optimization level {self._optimization.value} is not implemented so far."
            )

        strategy(self)

    def _simple_out_of_ssa(self) -> None:
        """
        This is a very simple version for out of SSA:
            - Remove the circular dependency of the Phi-functions per basic block.
            - Remove the phi-functions by lifting them to their predecessor basic blocks or as an instruction in the same basic block.
            - Easy renaming of the variables and update the instructions accordingly.
        """
        PhiDependencyResolver(self._phi_functions_of).resolve()
        self.interference_graph = InterferenceGraph(self.task.graph)
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift()
        SimpleVariableRenamer(self.task, self.interference_graph).rename()

    def _minimization_out_of_ssa(self) -> None:
        """
        This is a more advanced algorithm for out of SSA:
            - We first rename the variables using coloring. This is optimal since the interference graph is chordal
            - We then remove the circular dependency of the Phi-functions
            - Afterwards, we remove the Phi-functions by lifting them to their predecessor basic blocks.
        """
        self.interference_graph = InterferenceGraph(self.task.graph)
        MinimalVariableRenamer(self.task, self.interference_graph).rename()
        PhiDependencyResolver(self._phi_functions_of).resolve()
        PhiFunctionCleaner(self._phi_functions_of).clean_up()
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift()

    def _lift_minimal_out_of_ssa(self) -> None:
        """
        This is a more advanced algorithm for out of SSA, similar to `_minimization_out_of_ssa`:
            - We first remove the circular dependency of the Phi-functions
            - Then, we remove the Phi-functions by lifting them to their predecessor basic blocks.
            - Afterwards, we rename the variables using coloring. This is not optimal anymore, because the graph is not chordal anymore.
        """
        PhiDependencyResolver(self._phi_functions_of).resolve()
        self.interference_graph = InterferenceGraph(self.task.graph)
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift()
        MinimalVariableRenamer(self.task, self.interference_graph).rename()

    def _precolor_phi_out_of_ssa(self) -> None:
        """
        This is a more advanced algorithm for out of SSA, similar to `_lift_minimal_out_of_ssa`:
            - We first remove the circular dependency of the Phi-functions
            - Then we precolor to variables in the Phi-functions such that we insert a minimum number of copies
            - Then, we remove the Phi-functions by lifting them to their predecessor basic blocks or deleting them.
            - Afterwards, we rename the variables using coloring as well as our precoloring.
              This is not optimal anymore, because the graph is not chordal anymore.
        """
        pass

    def _conditional_out_of_ssa(self) -> None:
        """
        This is a more advanced algorithm for out of SSA:
            - We first remove the circular dependency of the Phi-functions
            - Then, we remove the Phi-functions by lifting them to their predecessor basic blocks.
            - Afterwards, we rename the variables by considering their dependency on each other.
        """
        PhiDependencyResolver(self._phi_functions_of).resolve()
        self.interference_graph = InterferenceGraph(self.task.graph)
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift()
        ConditionalVariableRenamer(self.task, self.interference_graph).rename()

    def _sreedhar_out_of_ssa(self) -> None:
        SreedharOutOfSsa(self.task).perform()

    # This translator maps the optimization levels to the functions.
    out_of_ssa_strategy: dict[SSAOptions, Callable[["OutOfSsaTranslation"], None]] = {
        SSAOptions.simple: _simple_out_of_ssa,
        SSAOptions.minimization: _minimization_out_of_ssa,
        SSAOptions.lift_minimal: _lift_minimal_out_of_ssa,
        SSAOptions.conditional: _conditional_out_of_ssa,
        SSAOptions.sreedhar: _sreedhar_out_of_ssa,
    }
