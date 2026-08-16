from typing import DefaultDict, List

from decompiler.pipeline.ssa.phi_dependency_resolver import PhiDependencyResolver
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.variable_renaming import ConditionalVariableRenamer
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.instructions import Phi, Assignment, Expression
from decompiler.structures.pseudo.operations import  Operation, OperationType
from decompiler.structures.pseudo.expressions import Variable, Constant
from decompiler.task import DecompilerTask
from itertools import product 
import os
import json
import traceback


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
        self.weightList = []
        
    def perform(self):
        #Start as if it would be a normal conditional out of SSA run to achieve the same state of the CFG and Interference graph as in a normal conditional.
        PhiDependencyResolver(self._phi_functions_of).resolve()
        self.interference_graph = InterferenceGraph(self.task.cfg)
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift() #no more phi functions from this point on

        self.errorLogPath = str(os.environ["ConditionalErrorLogPath"])
        #We save a file for EVERY task, even if there is no training data, to avoid touching that function again. If there is no file, it will get decompiled in each run.
        try:
            self.extractTrainingData()
            if self.weightList is not None:
                result = {i: {"parameters": self.weightList[i][0], "goal": self.weightList[i][1]} for i in range(len(self.weightList))}
                path = f"{os.environ['ConditionalResultPath']}"
                #with open(self.errorLogPath, "a") as error_file:
                #    error_file.write(f"Writing result to {path}\n")
                with open(path, "w") as f:
                    json.dump(result, f)
            else:
                path = f"{os.environ['ConditionalResultPath']}" + ".noTrainingData"
                with open(path, "w") as noData_file:
                    pass
        except Exception as e:
            with open(self.errorLogPath, "a") as error_file:
                error_file.write(f"Error while processing task {self.task}: {e}\n")
            return

    def getVariablesAndConstants(self, expr : Expression) -> tuple[List[Variable], List[Constant], bool]:
        """
        Extracts all variables and constants form the given expression. It also checks if the expression contains and 'bad' operations, which should
        not occur in strong or weak dependencies."""
        badOperations = [OperationType.dereference, OperationType.address, OperationType.dereference, OperationType.call, OperationType.pointer, OperationType.ternary, OperationType.list_op, OperationType.field, OperationType.member_access]
        vars = []
        consts = []
        hasBadOperations = False
        for component in expr.subexpressions():
            if isinstance(component, Variable):
                vars.append(component)
            elif isinstance(component, Constant):
                consts.append(component)
            elif isinstance(component, Operation):
                component:Operation
                if component.operation in badOperations:
                    hasBadOperations = True
        return vars, consts, hasBadOperations


    def extractTrainingData(self):
        """
        Extracts the markedness of the attributes for every assignment in the CFG and saves them to a list. The list is then saved to a file in the perform() function.
        If a new attribute should be added. Add the computation of the attribute in this function inside the for loop OVER the computation of trainingGoal.
        Append the value (0 or 1) to the instructionVector list. The ORDER of the attributes in the instructionVector list is important and
        has to be THE SAME accross the whole training and prediction process. So the order here has to be the same as in the dependency_graph.py file
        and in the FEATURES list in the conditionalTrainingRunner.py file. The training goal is computed at the end of the for loop and is appended 
        to the weightList together with the instructionVector.
        """

        sourceVariableNames = set()
        for block in self.task.cfg:
            for instr in block.instructions:
                if isinstance(instr,Assignment):
                    try:
                        lhs = instr.destination
                        if lhs is None:
                            continue
                        vlhs, _, bO1 = self.getVariablesAndConstants(lhs)
                        rhs = instr.value
                        if rhs is None:
                            continue
                        vrhs, crhs, bO2 = self.getVariablesAndConstants(rhs)
                        vrhs : List[Variable]
                        vlhs : List[Variable]

                        vrhsIter = [var for var in vrhs if var.origin is not None] #Only iterate over variables that have an origin. But we still need the total number of variables contained in lhs/ rhs
                        vlhsIter = [var for var in vlhs if var.origin is not None]

                        if (len(vrhs) == 0) or (len(vrhsIter) == 0) or (len(vlhsIter) == 0) or (len(vlhs) == 0): #only collect data if all variables have an origin, otherwise we cannot use the data for training
                            continue

                        for x, y in product(vlhsIter, vrhsIter):
                            instructionVector = []
                            #Attributes
                            #Attirbute 1: is_strong --> if the assignment has roughly the form x = y with x and y being two variables
                            if (len(vrhs) == 1) and (len(crhs) == 0) and (len(vlhs) == 1) and (not bO1) and (not bO2):
                                instructionVector.append(1)
                            else:
                                instructionVector.append(0)

                            #Attribute 2: is_mid --> if the assignment has roughly the form x = y + c with c being a constant. Further there shouldn't be a cast, a copy or pointer arithmetic in the rhs Expression.
                            if (instructionVector[0] == 0) and (len(vrhs) == 1) and (len(crhs) == 1) and (len(vlhs) == 1) and (not bO1) and (not bO2):
                                instructionVector.append(1)
                            else:
                                instructionVector.append(0)

                            #Attribute 3: same_base_name --> if all participating variables have the same base name (var.name)
                            if x.name == y.name:
                                instructionVector.append(1)
                            else:
                                instructionVector.append(0)

                            #Attribute 4: same_storage --> if all participating variables have the same storage (var.ssa_name.origin)
                            if (x.origin.source_type == y.origin.source_type) and (x.origin.storage == y.origin.storage):
                                instructionVector.append(1)
                            else:
                                instructionVector.append(0)



                            #Training goal:
                            sourceVariableNames.add(x.origin.source_name)
                            sourceVariableNames.add(y.origin.source_name)
                            trainingGoal = 1 if (x.origin.source_name == y.origin.source_name) else 0

                            self.weightList.append([instructionVector, trainingGoal])


                    except Exception as e:
                        with open(self.errorLogPath, "a") as error_file:
                            error_file.write(f"Error while processing instruction {instr}: {traceback.format_exc()}\n")
                        continue

        if len(sourceVariableNames) < 2:
            #Train only on functions that have at least 3 different source variable names. Otherwise the training data is not useful.
            self.weightList = None
                    
                    
