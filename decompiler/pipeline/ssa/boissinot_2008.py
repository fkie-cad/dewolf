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
        for var in self._cfg.get_variables():
            if not var.ssa_label: continue
            c_var_count = self._label_count.get(var.name)
            if not c_var_count or c_var_count < var.ssa_label:
                self._label_count[var.name] = var.ssa_label

    def _compute_copy_var(self, var: Variable|GlobalVariable) -> Variable:
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

    def _compute_lifted_constant_var(self, const : Constant) -> Variable:
        self._label_count[self.lifted_costant_var_name] += 1
        lifted_costant_var = Variable(
            self.lifted_costant_var_name,
            const.type,
            ssa_label=self._label_count[self.lifted_costant_var_name],
            is_aliased=False,
            ssa_name = None,
            tags = None 
        ) 
        return lifted_costant_var 


    def _get_predecessors(self, basic_block: BasicBlock) -> Iterator[Optional[BasicBlock]]:
        yield from list(self._cfg.get_predecessors(basic_block))
        if self._phi_functions_of[basic_block] and None in self._phi_functions_of[basic_block][0].origin_block:
            yield None

    def _insert_basic_block_before(self, basic_block: BasicBlock) -> BasicBlock:
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
        l: List[Expression] = phi.value.operands #type: ignore 
        if replacee in l:
            l[l.index(replacee)] = replacement
            phi.origin_block[predecessor] = replacement #type: ignore

    #TODO prob. move this inside the phi class
    def _substitute_phi_def(self, phi: Phi, replacee: Expression) -> None:
        phi._destination = replacee

    def _to_cssa(self) -> None:
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
                    if isinstance(req, Variable): 
                        copy_var = self._compute_copy_var(req)
                    elif isinstance(req, Constant):
                        copy_var = self._compute_lifted_constant_var(req)
                    else:
                        raise RuntimeError("Unexpected Phi requirement!")

                    self._substitute_phi_value(phi_inst, predecessor, req, copy_var)

                    copy_assign = Assignment(copy_var, req)
                    self._parallel_spaces.add_end_of_block_assign(block.address, copy_assign)


            for phi_inst in self._phi_functions_of[basic_block]:
                dest = phi_inst.definitions[0]
                copy_var = self._compute_copy_var(dest)
                self._substitute_phi_def(phi_inst, copy_var)

                copy_assign = Assignment(dest, copy_var)
                self._parallel_spaces.add_after_phi_assign(basic_block.address, copy_assign)


    def _build_interference_graph(self):
        self._cfg_copy = self._clone_cfg()
        self._parallel_spaces.instert_into_cfg(self._cfg_copy)
        self._interference_graph = ValueInterferenceGraph(self._cfg_copy)

    def _test_inter(self) -> None:
        for bb in self._cfg_copy:
            for instr in bb:
                if isinstance(instr, Phi):
                    vars = {*instr.requirements, *instr.definitions}
                    if self._interference_graph.are_interfering(*vars):
                        print(instr, bb)
                        for v in itertools.combinations(vars, 2): 
                            if self._interference_graph.are_interfering(v[0], v[1]):
                                print("INTER", v, "interfers")
                                for block, var in instr.origin_block.items():
                                    if var == v[0]:
                                        print("\t (v[0])", var, block) 
                                    elif var == v[1]:
                                        print("\t (v[1])", var, block) 
                        exit(1)


    def _test_none(self) -> None:
        for instr in self._cfg_copy.instructions:
            for subexpression in instr.subexpressions():
                if isinstance(subexpression, Variable) and not subexpression.type:
                    print("NONE", instr,":", subexpression, "is None")
           
    def step3(self):
        self._build_interference_graph()    
        self.ifgColoring = deepcopy(self._interference_graph)
        self.handle_Relations()

        self.fsetFix()
        self.getGlobals()
        
        self.doColoring()
        for x in self.gvars:
            assert not self._interference_graph.are_interfering(*x) and (self.areinstances(x,Variable))
        for x in self.nvars:
            assert not self._interference_graph.are_interfering(*x) and (self.areinstances(x,Variable))

        ttask = deepcopy(self._task)
        ttask.cfg = self._cfg_copy

        self.renamer = self.BoissinotVariableRenamer(ttask,self._interference_graph,self.nvars,self.gvars,True)
        self.renamer.rename()

        

    def getGlobals(self):
        globs = []
        norms = []
        for node in self.ifgColoring.nodes():
            if isinstance(node,frozenset):
                if len([x for x in node if isinstance(x, GlobalVariable)]) >= 1:
                    globs.append(node)
                else: 
                    norms.append(node)
            else:
                raise Exception("Found an object which is not a frozenset while renaming!")

        self.globs = sorted(globs, key = lambda x : ''.join([f"{x.name}{x.ssa_label}" for x in tuple(sorted(x,key = lambda x : f"{x.name}{x.ssa_label}"))]))
        self.norms = sorted(norms, key = lambda x : ''.join([f"{x.name}{x.ssa_label}" for x in tuple(sorted(x,key = lambda x : f"{x.name}{x.ssa_label}"))]))

    def areinstances(self, objs : List,classToCheck):
        for obj in objs:
            if not isinstance(obj,classToCheck):
                return False
        return True


    def handle_Relations(self):
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
                    all = []
                    for var in [*instr.requirements,*instr.definitions]:
                        if var in map.keys():
                            all.extend(list(map[var]))
                        else:
                            all.extend(list([var]))

                    for var in all:
                        map[var] = frozenset(all)
                elif isinstance(instr,Relation):
                    raise Exception("Found a suspicious relation, where at least one of the operands is not a variable")
                
        assert (not self.ifgColoring.are_interfering(*x) for x in map.values())
        nx.relabel_nodes(self.ifgColoring,map,False)


    def fsetFix(self):
        map = {}
        for var in self.ifgColoring.nodes():
            if isinstance(var,Variable):
                map[var] = frozenset([var])
            elif not isinstance(var,frozenset):
                raise Exception("Found a 'Variable' that's neither a Variable nor a List.")
        nx.relabel_nodes(self.ifgColoring,map,False)

    def doColoring(self):
        order = sorted(self.ifgColoring.edges,key = lambda x : f"{tuple(sorted(x[0],key = lambda a : f"{a.name}{a.ssa_label}"))}{tuple(sorted(x[1],key = lambda a : f"{a.name}{a.ssa_label}"))}")
        if len(self.globs) > 0:
            gs = nx.Graph()
            gs.add_nodes_from(self.globs)
            for edge in order :
                if (edge[0] in self.globs) and (edge[1] in self.globs):
                    gs.add_edges_from([edge])
            colors = nx.greedy_color(gs,"largest_first",True)
            colors : Dict
            num = max(list(colors.values())) + 1
            gvars = [[] for _ in range(num)]
            for var, col in colors.items():
                if isinstance(var,frozenset):
                    gvars[col].extend(var)
                else:
                    raise Exception(f"{var} is a {str(type(var))} instead of a frozenset!")
                
            self.gvars = gvars
        else:
            self.gvars = []

        if len(self.norms) > 0:
            gs = nx.Graph()
            gs.add_nodes_from(self.norms)
            for edge in order:
                if (edge[0] in self.norms) and (edge[1] in self.norms):
                    gs.add_edges_from([edge])
            colors = nx.greedy_color(gs,"largest_first",True)
            colors : Dict
            num = max(colors.values()) + 1
            nvars = [[] for _ in range(0,num)]
            for var, col in colors.items():
                if isinstance(var,frozenset):
                    nvars[col].extend(var)
                else:
                    raise Exception(f"{var} is a {str(type(var))} instead of a frozenset!")
                
            self.nvars = nvars
        else:
            self.nvars = []

        

    class BoissinotVariableRenamer(VariableRenamer):
        def __init__(self, task: DecompilerTask, interference_graph,varClassesn:list,varClassesg:list, calcRNM :bool = True):
            super().__init__(task,interference_graph)

            self.cfg = task.cfg
            self.interference_graph = interference_graph
            self.varClasses = varClassesn + varClassesg

            self.variable_for_function_arg: Dict[str, Variable] = self._get_function_argument_variables(task.function_parameters)
            self.function_arg_for_variable: Dict[Variable, str] = {v: k for k, v in self.variable_for_function_arg.items()}

            self.renaming_map: Dict[Variable, Variable] = dict()
            if calcRNM:
                self._generate_renaming_map()

        def _generate_renaming_map(self):
            count = 0
            assignedNames = []

            for varClass in self.varClasses:
                varClass = sorted(varClass,key = lambda x : f"{x.name}{x.ssa_label}")
                new_name = ""
                areGlobs = [var for var in varClass if isinstance(var,GlobalVariable)]
                if len(areGlobs) == 0: #no globals
                    fargs = [fa for fa in varClass if fa in self.function_arg_for_variable]
                    if len(fargs) > 1:
                        raise Exception("Found more than one argument in a PCK")
                    elif len(fargs) == 1: #function argument in PCK
                        new_name = self.function_arg_for_variable[fargs[0]]
                        if new_name in assignedNames:
                            new_name = f"{new_name}__{count}"
                            count += 1
                        assignedNames.append(new_name)
                        for vv in varClass:
                            self.renaming_map[vv] = Variable(new_name,vv.type,None,vv.is_aliased,vv,vv.tags)
                    else: #only ordinary variables
                        new_name = varClass[0].name
                        i = 1
                        while (new_name.find("__lifted_constant__") != -1) & (i < len(varClass)):
                            new_name = varClass[i].name
                            i += 1
                        else:
                            if new_name.find("__lifted_constant__") != -1:
                                new_name = "var" 
                        if new_name in assignedNames:
                            new_name = f"{new_name}__{count}"
                            count += 1
                        assignedNames.append(new_name)
                        for vv in varClass:
                            self.renaming_map[vv] = Variable(new_name,vv.type,None,vv.is_aliased,vv,vv.tags)


                elif len(areGlobs) == len(varClass): #only globals
                    new_name = varClass[0].name
                    new_name :str
                    if new_name.find("data_") != -1:
                        new_name = "global"
                    if new_name in assignedNames:
                        new_name = f'{new_name}__{count}'
                        count += 1
                    assignedNames.append(new_name)
                    for vv in varClass:
                        self.renaming_map[vv] = GlobalVariable(new_name,vv.type,vv.initial_value,None,vv.is_aliased,vv,vv.is_constant,vv.tags)
                else: #mixed PCK with globals and non-globals - Shouldn't occur!!
                    raise Exception("Found a class containing globals and ordinary variables")
                
    def eliminateDeadAssignments(self):
        allVars = self._cfg.get_variables()
        for bb in self._cfg:
            for instr in bb.instructions:
                for x in instr.requirements:
                    if x in allVars:
                        allVars.remove(x)
        for bb in self._cfg:
            for instr in bb.instructions:
                instr: Assignment
                if isinstance(instr, Assignment) and (instr.destination in allVars):
                    bb.replace_instruction(instr,[])

    def perform(self) -> None:
        try:
            #DecoratedCFG.from_cfg(self._cfg).export_plot("./voralles")
            self.eliminateDeadAssignments()
            #DecoratedCFG.from_cfg(self._cfg).export_plot("./vor1")
            self._to_cssa() #Step 1
            self._build_interference_graph() #Step 2

            #for x in self._interference_graph.edges():
            #    print(x)

            self._test_inter()
            self._test_none()
            #DecoratedCFG.from_cfg(self._cfg).export_plot("./nach2norm")
            #DecoratedCFG.from_cfg(self._cfg_copy).export_plot("./nach2")
            self._build_interference_graph()
            self.step3() #Step 3
            #print(self.gvars)
            #print(self.nvars)
            #DecoratedCFG.from_cfg(self._cfg).export_plot("./nach3")

            self._parallel_spaces.remove_nop_copies()
            self._parallel_spaces.sequentialize() #Step 4
            self._parallel_spaces.instert_into_cfg(self._cfg) #Step 4
            #DecoratedCFG.from_cfg(self._cfg).export_plot("./nach4")
            
            for bb in self._cfg: #Phi-functions are not getting removed earlier, so we are doing it here
                for instr in bb.instructions:
                    if isinstance(instr,Phi):
                        bb.replace_instruction(instr,[])
                    #To the best of my knowledge this part is not necessary:
                    #elif isinstance(instr,Assignment) and isinstance(instr.value,GlobalVariable) and isinstance(instr.destination,GlobalVariable):
                    #    if instr.value == instr.destination:
                    #        bb.replace_instruction(instr,[])

            #self._build_interference_graph() #renaming with an empty renaming maps cleans the code of None instructions :)
            self.renamer = self.BoissinotVariableRenamer(self._task,self._interference_graph,self.nvars,self.gvars,False)
            self.renamer.renaming_map = {}
            self.renamer.rename()
            
        except Exception as e:
            traceback.print_exception(e)


