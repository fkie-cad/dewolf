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

# A function is useful training data only if it contains an actual decision: at least this many
# records whose variables come from the same source (training goal 1) and at least this many whose
# variables come from different sources (training goal 0). A function with only one kind of pair
# carries no information about how to tell them apart. (A record with goal 0 already involves two
# distinct source names, so the former MIN_DISTINCT_SOURCE_NAMES = 2 criterion is implied.)
MIN_SAME_SOURCE_RECORDS = 1
MIN_DIFFERENT_SOURCE_RECORDS = 1

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

        def log_instruction_error(assign, _) -> None:
            with open(self.error_log_path, "a") as error_file:
                error_file.write(f"Error while processing instruction {assign}: {traceback.format_exc()}\n")

        records: List[TrainingRecord] = list(helper.iter_training_data(self.task.cfg, on_error=log_instruction_error))
        same_source_records = sum(1 for record in records if record.training_goal == 1)
        different_source_records = len(records) - same_source_records

        if same_source_records >= MIN_SAME_SOURCE_RECORDS and different_source_records >= MIN_DIFFERENT_SOURCE_RECORDS:
            tmp_path = self.result_path + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(
                    {str(i): {"parameters": r.vector, "goal": r.training_goal} for i, r in enumerate(records)},
                    f,
                )
            os.replace(tmp_path, self.result_path)
        else:
            # The marker records why the function was dropped, for the pipeline's kept/dropped report.
            with open(self.result_path + ".noTrainingData", "w") as f:
                json.dump(
                    {
                        "same_source": same_source_records,
                        "different_source": different_source_records,
                        "min_same_source": MIN_SAME_SOURCE_RECORDS,
                        "min_different_source": MIN_DIFFERENT_SOURCE_RECORDS,
                    },
                    f,
                )
