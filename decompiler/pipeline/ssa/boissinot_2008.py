from collections import defaultdict 
from typing import DefaultDict, Iterator, List, Optional, Dict
from copy import deepcopy
import networkx as nx
import traceback
import itertools

from decompiler.pipeline.ssa.value_interferencegraph import ValueInterferenceGraph
from decompiler.pipeline.ssa.parallel_spaces import ParallelSpaces 
from decompiler.structures.graphs.branches import UnconditionalEdge
from decompiler.structures.pseudo.instructions import Assignment, Phi, Relation,Return
from decompiler.task import DecompilerTask
from decompiler.structures.pseudo.expressions import Constant, Expression, Variable, GlobalVariable
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.pipeline.ssa.variable_renaming import VariableRenamer
from decompiler.util.decoration import DecoratedCFG,DecoratedGraph
from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis

class Boissinot2008:
    def __init__(self, task: DecompilerTask, phi_functions: DefaultDict[BasicBlock, List[Phi]]):
        self._task: DecompilerTask = task
        self._cfg: ControlFlowGraph = self._task.cfg #type: ignore
        self._phi_functions_of: DefaultDict[BasicBlock, List[Phi]] = phi_functions

        self.lifted_costant_var_name = "__lifted_constant__"
        self._label_count:DefaultDict[str, int] = defaultdict(int)
        self._parallel_spaces = ParallelSpaces(phi_functions)

    def _compute_label_count(self) -> None:
        """Computes the maximum SSA label for each variable in the CFG and stores it in self._label_count.
           We need this to generate new SSA labels for variables when we lift phi functions out of SSA form."""
        for var in self._cfg.get_variables():
            if not var.ssa_label: continue
            c_var_count = self._label_count.get(var.name)
            if not c_var_count or c_var_count < var.ssa_label:
                self._label_count[var.name] = var.ssa_label

    def _compute_copy_var(self, var: Variable|GlobalVariable, LeftDest: Variable|GlobalVariable) -> Variable | GlobalVariable:
        """Returns a new Variable object suitable to be used as the destination of a copy instruction that copies a variable.
           The function is mainly used for creating variables for phi functions, therefore name, type, is_aliased, and tags are copied form LeftDest."""
        self._label_count[LeftDest.name] += 1
        if (not isinstance(LeftDest,GlobalVariable)) and isinstance(var,Variable):
            copy_var = Variable(
                LeftDest.name,  
                LeftDest.type,
                ssa_label=self._label_count[LeftDest.name],
                is_aliased=LeftDest.is_aliased,
                ssa_name = None,
                tags = LeftDest.tags
            ) 
            return copy_var
        elif isinstance(LeftDest,GlobalVariable) and isinstance(var,Variable): #Global variables stay globals, so they don't get mixed up with normal variables
            LeftDest : GlobalVariable
            #self._label_count[LeftDest.name] += 1
            copy_var = GlobalVariable(
                LeftDest.name,
                LeftDest.type,
                LeftDest.initial_value,
                self._label_count[LeftDest.name],
                LeftDest.is_aliased,
                None,
                LeftDest.is_constant,
                LeftDest.tags
            )
            return copy_var

    def _compute_copy_var_Left(self, var: Variable|GlobalVariable) -> Variable | GlobalVariable:
        """Returns a new Variable object suitable to be used as the new destination of a phi function."""
        self._label_count[var.name] += 1
        if not isinstance(var,GlobalVariable):
            copy_var = Variable(
                var.name,  
                var.type,
                ssa_label=self._label_count[var.name],
                is_aliased=var.is_aliased,
                ssa_name = None,
                tags = var.tags
            ) 
            return copy_var
        elif isinstance(var,GlobalVariable): #Global variables stay globals, so they don't get mixed up with normal variables
            var : GlobalVariable
            self._label_count[var.name] += 1
            copy_var = GlobalVariable(
                var.name,
                var.type,
                var.initial_value,
                self._label_count[var.name],
                var.is_aliased,
                None,
                var.is_constant,
                var.tags
            )
            return copy_var

    def _compute_lifted_constant_var(self, const : Constant,dest : Variable) -> Variable | GlobalVariable:
        """Returns a new Variable object suitable to be used as the destination of a copy instruction that copies a constant.
           The function is mainly used for creating variables for phi functions, therefore name, type, is_aliased, and tags are copied form LeftDest."""
        if isinstance(dest,GlobalVariable):
            self._label_count[dest.name] += 1
            lifted_costant_var = GlobalVariable(
                dest.name,
                dest.type,
                ssa_label=self._label_count[dest.name],
                is_aliased=dest.is_aliased,
                ssa_name = None,
                tags = dest.tags,
                initial_value=dest.initial_value,
                is_constant=dest.is_constant
            ) 
            return lifted_costant_var 
            
        else:
            self._label_count[dest.name] += 1
            lifted_costant_var = Variable(
                dest.name,
                dest.type,
                ssa_label=self._label_count[dest.name],
                is_aliased=dest.is_aliased,
                ssa_name = None,
                tags = dest.tags 
            ) 
            return lifted_costant_var         

    def _get_predecessors(self, basic_block: BasicBlock) -> Iterator[Optional[BasicBlock]]:
        yield from list(self._cfg.get_predecessors(basic_block))
        if self._phi_functions_of[basic_block] and None in self._phi_functions_of[basic_block][0].origin_block:
            yield None

    def _insert_basic_block_before(self, basic_block: BasicBlock) -> BasicBlock:
        """creates a new basic block and inserts it before the given basic block in the CFG. Returns the new basic block."""
        new_basic_block = self._cfg.create_block()
        self._cfg.add_edge(UnconditionalEdge(new_basic_block, basic_block))
        return new_basic_block
    
    def _insert_basic_block_after(self, basic_block: BasicBlock) -> BasicBlock:
        new_basic_block = self._cfg.create_block()
        self._cfg.add_edge(UnconditionalEdge(basic_block,new_basic_block))
        return new_basic_block


    def _clone_cfg(self) -> ControlFlowGraph:
        """
        Clone `cfg` so:
          - each BasicBlock in the clone has a *new list* of instructions (so you may insert/remove
            instructions in the clone without affecting the original),
          - but the Instruction and Variable objects inside the lists are the *same* objects
            (so renaming a Variable in either graph is visible in the other).
        """
        copy_cfg = ControlFlowGraph()
        block_map: Dict[BasicBlock, BasicBlock] = dict() 
    
        for bb in self._cfg:
            new_bb = BasicBlock(bb.address, instructions=list(bb))
            copy_cfg.add_node(new_bb)
            block_map[bb] = new_bb
    
        for edge in self._cfg.edges:
            src = block_map[edge.source]
            dst = block_map[edge.sink]
            new_edge = edge.copy(source=src, sink=dst)
            copy_cfg.add_edge(new_edge)
    
        if self._cfg.root is not None:
            copy_cfg.root = block_map[self._cfg.root]
    
        return copy_cfg

    #TODO prob. move this inside the phi class
    def _substitute_phi_value(self, phi: Phi, predecessor: Optional[BasicBlock], replacee: Expression, replacement: Expression) -> None:
        """Substitutes the value replacee with replacement in the phi function phi for the given predecessor basic block."""
        l: List[Expression] = phi.value.operands #type: ignore 
        if replacee in l:
            l[l.index(replacee)] = replacement
            phi.origin_block[predecessor] = replacement #type: ignore

    #TODO prob. move this inside the phi class
    def _substitute_phi_def(self, phi: Phi, replacee: Expression) -> None:
        phi._destination = replacee

    def _to_cssa(self) -> None:
        """phi functions are lifted out of the CFG and replaced with copy instructions. If necessary, new basic blocks are being inserted."""
        #compute next possible SSA label for each variable
        self._compute_label_count()

        for basic_block in self._phi_functions_of:
            for predecessor in self._get_predecessors(basic_block): #type: ignore
                block: BasicBlock
                edge = self._cfg.get_edge(predecessor, basic_block) #type: ignore 
                if predecessor is not None and isinstance(edge, UnconditionalEdge):
                    block = predecessor
                else:
                    block = self._insert_basic_block_before(basic_block)
                    if predecessor:
                        self._cfg.substitute_edge(edge, edge.copy(sink=block)) #type: ignore
                    else:
                        self._cfg.root = block 

                for phi_inst in self._phi_functions_of[basic_block]:
                    req = phi_inst.origin_block[predecessor]

                    copy_var: Variable
                    leftDest = phi_inst.destination

                    if isinstance(req, Variable): 
                        copy_var = self._compute_copy_var(req,leftDest)
                    elif isinstance(req, Constant):
                        copy_var = self._compute_lifted_constant_var(req,leftDest)
                    else:
                        raise RuntimeError("Unexpected Phi requirement!")

                    self._substitute_phi_value(phi_inst, predecessor, req, copy_var)

                    copy_assign = Assignment(copy_var, req)
                    self._parallel_spaces.add_end_of_block_assign(block.address, copy_assign)


            for phi_inst in self._phi_functions_of[basic_block]:
                dest = phi_inst.definitions[0]
                copy_var = self._compute_copy_var_Left(dest)
                self._substitute_phi_def(phi_inst, copy_var)

                copy_assign = Assignment(dest, copy_var)
                self._parallel_spaces.add_after_phi_assign(basic_block.address, copy_assign)


    def _build_interference_graph(self):
        """Builds the interference graph for the given control flow graph."""
        self._cfg_copy = self._clone_cfg()
        # insert the potentially needed copy instructions form the parallel space into the cfg
        self._parallel_spaces.instert_into_cfg(self._cfg_copy)
        self._interference_graph = ValueInterferenceGraph(self._cfg_copy)


    def step3(self):
        """Step 3 of the Boissinot et al. algorithm: color the interference graph and rename variables accordingly."""
        # We do the coloring on a spearate graph
        self.ifgColoring = deepcopy(self._interference_graph)
        #Ensure that all relations are satisfied and combine all variables mentioned in a Phi function
        self.handle_Relations()
        #Ensure consistency in node names
        self.fsetFix()
        #Construct variable classes based on the interference graph and Methods described in the Paper and the criteria defined in doVarCheckClassTogetherPossible
        self.varClasses = self.constructVariableClasses()

        ttask = deepcopy(self._task)
        ttask.cfg = self._cfg_copy

        #Compute renaming map and rename the variables accordingly
        #TODO: Fix Variable Renamer to work with the new interference graph and variable classes
        self.renamer = self.BoissinotVariableRenamer(ttask,self._interference_graph,self.varClasses)
        self.renamer.rename()

    def constructVariableClasses(self) -> List[List[Variable]]:
        """Creates Variable Classes based on the interference graph and the criteria defined in doVarCheckClassTogetherPossible like described in the paper by Boissinot et al. 2008."""
        #Merge Variables that are connected by a copy assignment into one class, if they do not interfere based on our new criteria.
        varClasses = defaultdict(lambda: [])
        for node in self.ifgColoring.nodes(data=False):
            if isinstance(node,frozenset):
                classVars = list(node)
                for var in node:
                    varClasses[var] = classVars
            else:
                raise Exception("Found a node which is not a frozenset while constructing variable classes!")

        basicBlockList = self.getBasicBlockList()
        for bb in basicBlockList:
            for instr in bb.instructions:
                if isinstance(instr,Assignment):
                    instr: Assignment
                    if isinstance(instr.destination,Variable) and isinstance(instr.value,Variable):
                        if (varClasses[instr.destination] is not varClasses[instr.value]):
                            if not self._interference_graph.are_interfering(*varClasses[instr.destination],*varClasses[instr.value]):
                                newClass = [*varClasses[instr.destination],*varClasses[instr.value]]
                                for var in newClass:
                                    varClasses[var] = newClass

        #Check remaining copys for special criterion of Boissinot et al. 
        # Given two assignments of the form x = y and z = y, if x and z are live at the same time, they can be in the same class

        liveness = LivenessAnalysis(self._cfg_copy)
        liveOuts = liveness._live_out_block.values()
        assignmentsEliminationDict = defaultdict(lambda: [])

        for bb in basicBlockList:
            for instr in bb.instructions:
                if isinstance(instr,Assignment):
                    instr: Assignment
                    if isinstance(instr.destination,Variable) and isinstance(instr.value,Variable) and (varClasses[instr.destination] != varClasses[instr.value]):
                        assignmentsEliminationDict[id(varClasses[instr.value])].append(instr.destination)

        changes=True
        while changes:
            changes = False     
            for varList in assignmentsEliminationDict.values():
                if len(varList) > 1:
                    for var1,var2 in itertools.combinations(varList,2):
                        if (varClasses[var1] is not varClasses[var2]) and self.doVarCheckClassToghetherPossible(var1, var2):
                            for liveOut in liveOuts:
                                if (var1 in liveOut) and (var2 in liveOut): #The two variables are live at the same time, so they can be in the same class
                                    if not self._interference_graph.are_interfering(*varClasses[var1],*varClasses[var2]):
                                        newClass = [*varClasses[var1],*varClasses[var2]]
                                        for var in newClass:
                                            varClasses[var] = newClass
                                        changes = True

                                    break

        return [list(varClasses[x]) for x in varClasses.keys()]

    def getBasicBlockList(self) -> List[BasicBlock]:
        """Returns a list of all basic blocks in the CFG, sorted by the number of loops the basic block is involved in descending order."""

        #idom = self._cfg_copy.dominator_tree
        #print(type(idom),idom)
        #print(idom.)
        #idom : nx.DiGraph
        #idom = {node : idom.predecessors(node)[0] for node in idom.nodes(data=False)}
        idom = nx.immediate_dominators(self._cfg_copy._graph,self._cfg_copy.root)
        idom : Dict[BasicBlock, BasicBlock]
        idom.setdefault(self._cfg_copy.root,self._cfg_copy.root)

        backEdges = []
        for (A, B) in self._cfg_copy._graph.edges():
            if self._dominates(B, A, idom):
                backEdges.append((A, B))

        loops = []
        for (A, B) in backEdges:
            loops.append(self.getLoopInvolvedNodes(B, A)) 

        loops = [y for x in loops for y in x]
        count = {}
        for bb in self._cfg_copy:
            count[bb] = loops.count(bb)

        return sorted(count.keys(), key=lambda bb: count[bb],reverse=True)


    def _dominates(self, dominator: BasicBlock, dominated: BasicBlock, idom: Dict[BasicBlock, BasicBlock]) -> bool:
        """Returns True if dominator dominates dominated in the CFG, False otherwise."""
        current = dominated
        while current != self._cfg_copy.root:
            if current == dominator:
                return True
            current = idom[current]
        return current == dominator  # Check if the root is the dominator
    
    def getLoopInvolvedNodes(self,Head: BasicBlock, B: BasicBlock) -> List[BasicBlock]:
        """Returns a list of all basic blocks involved in the loop with header A and back edge B->A"""
        loop = [Head, B]
        worklist = [B]
        while worklist:
            x = worklist.pop()
            for pred in self._cfg_copy.get_predecessors(x):
                if (pred not in loop) and (pred is not None):
                    loop.append(pred)
                    worklist.append(pred)
        
        return loop

    def areinstances(self, objs : List,classToCheck):
        """Checks if all objects in the list are instances of the given class."""
        for obj in objs:
            if not isinstance(obj,classToCheck):
                return False
        return True


    def handle_Relations(self):
        """Relabels nodes to frozensets of variables, where each frozenset contains all variables that are (transitively) connected by a Relation"""
        map = {}
        for bb in self._cfg:
            for instr in bb.instructions:
                if isinstance(instr,Relation) and self.areinstances([instr.value,instr.destination],Variable) :
                    instr: Phi
                    varList = []
                    if instr.value in map.keys():
                        varList.extend(list(map[instr.value]))
                    else:
                        varList.append(instr.value)
                    if instr.destination in map.keys():
                        varList.extend(list(map[instr.destination]))
                    else:
                        varList.append(instr.destination)
                    for var in varList:
                        map[var] = frozenset(varList)

                elif isinstance(instr,Phi):
                    alle = []
                    for var in [*instr.requirements,*instr.definitions]:
                        if var in map.keys():
                            alle.extend(list(map[var]))
                        else:
                            alle.extend(list([var]))

                    for var in alle:
                        map[var] = frozenset(alle)
                    
                elif isinstance(instr,Relation):
                    raise Exception("Found a suspicious relation, where at least one of the operands is not a variable")
        nx.relabel_nodes(self.ifgColoring,map,False)


    def fsetFix(self):
        """Ensures consistency in node names: all nodes have to be frozensets of variables"""
        map = {}
        for var in self.ifgColoring.nodes():
            if isinstance(var,Variable):
                map[var] = frozenset([var])
            elif not isinstance(var,frozenset):
                raise Exception("Found a 'Variable' that's neither a Variable nor a frozenset.")
        nx.relabel_nodes(self.ifgColoring,map,False)

    def doVarCheckClassToghetherPossible(self, var1: Variable, var2: Variable) -> bool:
        """Returns true, if var1 and var2 do not interfere based on our 'newly' found criteria:
                Global Variable and normal variables do not get mixed.
                Global variables in one class have to have the same name.
                The type of all variables in one class has to be identical.
                The variables either have to be all aliased or all non-aliased.
                If both variables are aliased they have to have the same name.
                """
        if isinstance(var1, GlobalVariable) and isinstance(var2, GlobalVariable) and (var1.name != var2.name):
            return False
        elif isinstance(var1, GlobalVariable) != isinstance(var2, GlobalVariable):
            return False
        elif var1.type != var2.type:
            return False
        elif var1.is_aliased != var2.is_aliased:
            return False
        elif var1.is_aliased and var2.is_aliased and (var1.name != var2.name):
            return False
        return True
        

    class BoissinotVariableRenamer(VariableRenamer):
        def __init__(self, task: DecompilerTask, interference_graph,varClasses:list):
            super().__init__(task,interference_graph)

            self.cfg = task.cfg
            self.interference_graph = interference_graph
            self.varClasses = varClasses

            self.variable_for_function_arg: Dict[str, Variable] = self._get_function_argument_variables(task.function_parameters)
            self.function_arg_for_variable: Dict[Variable, str] = {v: k for k, v in self.variable_for_function_arg.items()}

            self.renaming_map: Dict[Variable, Variable] = dict()
            self._generate_renaming_map()

        def _generate_renaming_map(self):
            
            drop = []
            #If there are classes with variables of different types (which shouldn't occur, but in rare cases it sadly does), we split them into separate classes by their type.
            for i in range(len(self.varClasses)):
                aktClass = self.varClasses[i]
                types = set([x.type for x in aktClass])
                if len(types) <= 1:
                    pass
                else:
                    drop.append(i)
                    for t in types:
                        self.varClasses.append([x for x in aktClass if x.type == t])
            drop = sorted(drop,reverse=True)
            for d in drop:
                self.varClasses.pop(d)

            count = 0
            assignedNames = []

            for varClass in self.varClasses:
                varClass = sorted(varClass,key = lambda x : f"{x.name}{x.ssa_label}") #Determinism
                new_name = ""
                areGlobs = [var for var in varClass if isinstance(var,GlobalVariable)] #Global variables

                if len(areGlobs) == 0: #NO globals
                    fargs = [fa for fa in varClass if fa in self.function_arg_for_variable] #function arguments in varClass

                    #We only want to have at most one function arguement in each class
                    if len(fargs) > 1:
                        raise Exception("Found more than one argument in a PCK")
                    
                    elif len(fargs) == 1: #ONE function argument in PCK
                        #chose a name and check availability
                        new_name = self.function_arg_for_variable[fargs[0]]
                        if new_name in assignedNames:
                            new_name = f"{new_name}__{count}"
                            count += 1
                        assignedNames.append(new_name)
                        
                        #Renaiming
                        for vv in varClass:
                            vv: Variable
                            self.renaming_map[vv] = Variable(new_name,vv.type,None,vv.is_aliased,vv,vv.tags)

                    else: #only ordinary variables, no function arguments, no globals

                        if len(varClass) >= 1:
                            new_name = varClass[0].name
                            i = 1
                            #We do not want our high level variable to be named "__lifted_constant__" because this is a special name
                            while (new_name.find("__lifted_constant__") != -1) & (i < len(varClass)):
                                new_name = varClass[i].name
                                i += 1
                            else:
                                if new_name.find("__lifted_constant__") != -1:
                                    new_name = "var" 
                            
                            #Check availability of the new name and rename the variables in the class accordingly
                            if new_name in assignedNames:
                                new_name = f"{new_name}__{count}"
                                count += 1
                            assignedNames.append(new_name)
                            for vv in varClass:
                                vv: Variable
                                self.renaming_map[vv] = Variable(new_name,vv.type,None,vv.is_aliased,vv,vv.tags)


                elif len(areGlobs) == len(varClass): #only globals
                    new_name = varClass[0].name
                    new_name :str
                    #Check availability of the new name and rename the variables in the class accordingly
                    if new_name in assignedNames:
                        new_name = f'{new_name}__{count}'
                        count += 1
                    assignedNames.append(new_name)
                    for vv in varClass:
                        vv: GlobalVariable
                        self.renaming_map[vv] = GlobalVariable(new_name,vv.type,vv.initial_value,None,vv.is_aliased,vv,vv.is_constant,vv.tags)

                else: #mixed Class with globals and non-globals - Shouldn't occur!!
                    raise Exception("Found a class containing globals and ordinary variables")
                

    def _remove_phis(self, cfg: ControlFlowGraph):
        for bb in cfg: 
            for instr in bb.instructions:
                if isinstance(instr,Phi):
                    bb.replace_instruction(instr,[])

    def _remove_nop_instr(self, cfg: ControlFlowGraph):
        """Remove all instructions of the form x = x and all relations as they have been considered already and are not needed anymore."""
        for bb in cfg:
            for instr in bb.instructions:
                if (
                    isinstance(instr, Assignment) and 
                    isinstance(instr.destination, Variable) and 
                    isinstance(instr.value, Variable) and 
                    instr.destination == instr.value
                ) or isinstance(instr, Relation):
                       bb.replace_instruction(instr,[])

    def perform(self) -> None:
        try:
            self._to_cssa() #Step 1
            self._build_interference_graph() #Step 2
            self.step3() #Step 3

            #manual clean up
            self._remove_nop_instr(self._cfg)

            #Parallel spaces
            self._parallel_spaces.remove_nop_copies() #Clean up
            self._parallel_spaces.sequentialize() #Step 4
            self._parallel_spaces.instert_into_cfg(self._cfg) #Step 4
            self._remove_phis(self._cfg) #Remove Phi functions

        except Exception as e:
            traceback.print_exception(e)
