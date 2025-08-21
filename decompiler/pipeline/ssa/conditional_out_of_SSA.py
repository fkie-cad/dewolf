from decompiler.task import DecompilerTask
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.phi_dependency_resolver import PhiDependencyResolver
from collections import defaultdict
from typing import DefaultDict, List
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.pseudo.instructions import Phi
from decompiler.pipeline.ssa.variable_renaming import ConditionalVariableRenamer



class ConditionalOutOfSSA():
    
    def __init__(self, task :DecompilerTask, _phi_fuctions_of ,strong:float  = 1, mid: float = 0.5, weak:float = 0.1,func :float = -2, strategy : int = 1):
        '''
        strong/ weak/ mid: Values for the corresponding edges
        func : Value for edges between assignee and parameters of functions e.g. between a and b in a = foo(b)
            -2 deactivates those edges
            -1 same value as weak dependency  
        '''
        self.task = task
        self.cfg = task.cfg
        self.strongDep = strong
        self.midDep = mid
        self.weakDep = weak
        self._phi_functions_of: DefaultDict[BasicBlock, List[Phi]] = _phi_fuctions_of
        if func == -2: self.funcDep = 0
        elif func == -1: self.funcDep = self.weakDep
        else: self.funcDep = func
        self.strategy = strategy


    def perform(self):
        PhiDependencyResolver(self._phi_functions_of).resolve()
        self.interference_graph = InterferenceGraph(self.task.cfg)
        PhiFunctionLifter(self.task.graph, self.interference_graph, self._phi_functions_of).lift()
        ConditionalVariableRenamer(self.task, self.interference_graph,self.strongDep,self.midDep,self.weakDep,self.funcDep,self.strategy).rename()
