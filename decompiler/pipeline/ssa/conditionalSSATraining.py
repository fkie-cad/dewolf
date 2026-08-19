import os
import json
import traceback
from typing import DefaultDict, List

from decompiler.pipeline.ssa.conditional_attribute_helper import PhiPairs, TrainingAttributeHelper, TrainingRecord, get_phi_pairs
from decompiler.pipeline.ssa.phi_dependency_resolver import PhiDependencyResolver
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.instructions import Phi 
from decompiler.task import DecompilerTask

# Defines how many distinct SSA source variables should be in a function for it to be
# useful training data
MIN_DISTINCT_SOURCE_NAMES = 2

class ConditionalOutOfSSATraining:
    """
    Custom Out-of-SSA stage which extracts the markedness of the attributes and saves them to a file. """

    def __init__(
        self,
        task: DecompilerTask,
        _phi_fuctions_of: DefaultDict[BasicBlock, List[Phi]],
    ):
        self.task = task
        self.cfg = task.cfg
        self._phi_functions_of = _phi_fuctions_of
        self.error_log_path = str(os.environ["ConditionalErrorLogPath"])
        self.result_path = str(os.environ["ConditionalResultPath"])

    def perform(self) -> None:
        # We need to get the phi_pairs before lifting
        phi_pairs = get_phi_pairs(self.task.cfg)
        #Start as if it would be a normal conditional out of SSA run to achieve the same state of the CFG and Interference graph as in a normal conditional.
        PhiDependencyResolver(self._phi_functions_of).resolve()
        interference_graph = InterferenceGraph(self.task.cfg)
        PhiFunctionLifter(self.task.graph, interference_graph, self._phi_functions_of).lift()
 
        # We always write SOME file for every task (a marker if there's no useful data)
        # so a function is never re-decompiled just to find out again that it has nothing.
        try:
            self._extract_and_write(phi_pairs, interference_graph)
        except Exception as e:
            with open(self.error_log_path, "a") as error_file:
                error_file.write(f"Error while processing task {self.task}: {e}\n")
    
    def _extract_and_write(self, phi_pairs: PhiPairs, interference_graph: InterferenceGraph) -> None:
        helper = TrainingAttributeHelper(phi_pairs, interference_graph)
 
        tmp_path = self.result_path + ".tmp"
        source_names: set = set()
        record_count = 0
 
        def log_instruction_error(assign, _) -> None:
            with open(self.error_log_path, "a") as error_file:
                error_file.write(f"Error while processing instruction {assign}: {traceback.format_exc()}\n")
 
        with open(tmp_path, "w") as f:
            f.write("{")
            first = True
            record: TrainingRecord
            for record in helper.iter_training_data(self.task.cfg, on_error=log_instruction_error):
                if not first:
                    f.write(",")
                key = json.dumps(str(record_count))
                f.write(f"{key}:")
                json.dump({"parameters": record.vector, "goal": record.training_goal}, f)
                first = False
                source_names.add(record.x_source_name)
                source_names.add(record.y_source_name)
                record_count += 1
            f.write("}")
 
        if record_count > 0 and len(source_names) >= MIN_DISTINCT_SOURCE_NAMES:
            os.replace(tmp_path, self.result_path)
        else:
            os.remove(tmp_path)
            open(self.result_path + ".noTrainingData", "w").close()
