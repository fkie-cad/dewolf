from collections import defaultdict
from typing import DefaultDict, Iterator, List, Optional, Dict
from copy import deepcopy
import networkx as nx
import traceback

from decompiler.pipeline.ssa.value_interferencegraph import ValueInterferenceGraph
from decompiler.pipeline.ssa.parallel_spaces import ParallelSpaces 
from decompiler.structures.graphs.branches import UnconditionalEdge
from decompiler.structures.pseudo.instructions import Assignment, Phi, Relation
from decompiler.task import DecompilerTask
from decompiler.structures.pseudo.expressions import Constant, Variable, GlobalVariable
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.pipeline.ssa.variable_renaming import VariableRenamer
from decompiler.util.decoration import DecoratedCFG

class Boissinot2008:
    def __init__(self, task: DecompilerTask, phi_functions: DefaultDict[BasicBlock, List[Phi]]):
        self._task: DecompilerTask = task
        self._cfg: ControlFlowGraph = self._task.cfg #type: ignore
        self._phi_functions_of: DefaultDict[BasicBlock, List[Phi]] = phi_functions

        self.lifted_costant_var_name = "__lifted_constat__"
        self._label_count:DefaultDict[str, int] = defaultdict(int)
        self._parallel_spaces = ParallelSpaces(phi_functions)

    def _compute_label_count(self) -> None:
        for var in self._cfg.get_variables():
            if not var.ssa_label: continue
            c_var_count = self._label_count.get(var.name)
            if not c_var_count or c_var_count < var.ssa_label:
                self._label_count[var.name] = var.ssa_label

    def _compute_copy_var(self, var: Variable) -> Variable:
        self._label_count[var.name] += 1
        copy_var = Variable(
            var.name,  
            ssa_label=self._label_count[var.name],
            is_aliased=var.is_aliased,
            ssa_name = None,
            tags = var.tags
        ) 
        return copy_var

    def _compute_lifted_constant_var(self) -> Variable:
        self._label_count[self.lifted_costant_var_name] += 1
        lifted_costant_var = Variable(
            self.lifted_costant_var_name,
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

    def _to_cssa(self) -> None:
        self._compute_label_count()

        for basic_block in self._phi_functions_of:
            for phi_inst in self._phi_functions_of[basic_block]:
                req = phi_inst.definitions[0]
                copy_var = self._compute_copy_var(req)
                copy_assign = Assignment(req, copy_var)
                self._parallel_spaces.add_after_phi_assign(basic_block.address, copy_assign)
                phi_inst.substitute(req, copy_var)

                predecessor: BasicBlock
                for predecessor in self._get_predecessors(basic_block): #type: ignore
                    req = phi_inst.origin_block[predecessor]

                    copy_var: Variable
                    if isinstance(req, Variable): 
                        copy_var = self._compute_copy_var(req)
                    elif isinstance(req, Constant):
                        copy_var = self._compute_lifted_constant_var()
                    else:
                        raise RuntimeError("Unexpected Phi requirement!")

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

                    copy_assign = Assignment(copy_var, req)
                    self._parallel_spaces.add_end_of_block_assign(predecessor.address, copy_assign)
                    phi_inst.substitute(req, copy_var)

    def _build_interference_graph(self):
        cfg_copy = self._clone_cfg()
        self._parallel_spaces.instert_into_cfg(cfg_copy)
        self._interference_graph = ValueInterferenceGraph(cfg_copy)


    def step3(self):
        self.ifgColoring = deepcopy(self._interference_graph)
        self.handle_Relations()
        for bb in self._cfg:
            for instr in bb:
                if isinstance(instr,Phi):
                    bb.replace_instruction(instr,[])
        self.fsetFix()
        self.getGlobals()
        
        self.doColoring()
        for x in self.gvars:
            assert not self._interference_graph.are_interfering(*x)
        for x in self.nvars:
            assert not self._interference_graph.are_interfering(*x)

        self.BoissinotVariableRenamer(self._task,self._interference_graph,self.nvars,self.gvars).rename()


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

        self.globs = globs
        self.norms = norms

    def handle_Relations(self):
        map = {}
        for bb in self._cfg:
            for instr in bb.instructions:
                if isinstance(instr,Relation) and isinstance(instr.value,Variable) and isinstance(instr.destination,Variable):
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
                    for var in [*instr.requirements,instr.destination]:
                        if var in map.keys():
                            all.extend(list(map[var]))
                        else:
                            all.extend(list([var]))

                    for var in all:
                        map[var] = frozenset(all)
                elif isinstance(instr,Relation):
                    raise Exception("Found a suspicious relation, where the operands are not variables")
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
        if len(self.globs) > 0:
            gs = nx.Graph()
            gs.add_nodes_from(self.globs)
            for edge in self.ifgColoring.edges:
                if (edge[0] in self.globs) and (edge[1] in self.globs):
                    gs.add_edges_from([edge])
            colors = nx.greedy_color(gs,"largest_first",True)
            colors : Dict
            nums = [x + 1 for x in colors.values()]
            nums.append(0)
            num = max(nums)
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
            for edge in self.ifgColoring.edges:
                if (edge[0] in self.norms) and (edge[1] in self.norms):
                    gs.add_edges_from([edge])
            colors = nx.greedy_color(gs,"largest_first",True)
            colors : Dict
            nums = [x + 1 for x in colors.values()]
            nums.append(0)
            num = max(nums)
            nvars = [[] for _ in range(num)]
            for var, col in colors.items():
                if isinstance(var,frozenset):
                    nvars[col].extend(var)
                else:
                    raise Exception(f"{var} is a {str(type(var))} instead of a frozenset!")
                
            self.nvars = nvars
        else:
            self.nvars = []

    class BoissinotVariableRenamer(VariableRenamer):
        def __init__(self, task: DecompilerTask, interference_graph,varClassesn:list,varClassesg:list):
            super().__init__(task,interference_graph)

            self.cfg = task.cfg
            self.interference_graph = interference_graph
            self.varClasses = varClassesn + varClassesg

            self.variable_for_function_arg: Dict[str, Variable] = self._get_function_argument_variables(task.function_parameters)
            self.function_arg_for_variable: Dict[Variable, str] = {v: k for k, v in self.variable_for_function_arg.items()}
            #self._add_interference_for_function_args()

            self.renaming_map: Dict[Variable, Variable] = dict()
            self._generate_renaming_map()

        def _generate_renaming_map(self):
            count = 0
            assignedNames = []

            for varClass in self.varClasses:
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
                        if new_name in assignedNames:
                            new_name = f"{new_name}__{count}"
                            count += 1
                        assignedNames.append(new_name)
                        for vv in varClass:
                            self.renaming_map[vv] = Variable(new_name,vv.type,None,vv.is_aliased,vv,vv.tags)


                elif len(areGlobs) == len(varClass): #only globals
                    new_name = varClass[0].name
                    if new_name in assignedNames:
                        new_name = f'{new_name}__{count}'
                        count += 1
                    assignedNames.append(new_name)
                    for vv in varClass:
                        self.renaming_map[vv] = GlobalVariable(new_name,vv.type,vv.initial_value,None,vv.is_aliased,vv,vv.is_constant,vv.tags)
                else: #let's hope this case does not occur
                    raise Exception("Found a class containing globals and ordinary variables")
                    new_name = varClass[0].name
                    if new_name in assignedNames:
                        new_name = f'{new_name}__{count}'
                        count += 1
                    assignedNames.append(new_name)
                    for vv in varClass:
                        if isinstance(vv,GlobalVariable):
                            self.renaming_map[vv] = GlobalVariable(new_name,vv.type,vv.initial_value,None,vv.is_aliased,vv,vv.is_constant,vv.tags)
                        else:
                            self.renaming_map[vv] = GlobalVariable(new_name,vv.type,areGlobs[0].initial_value,None,vv.is_aliased,vv,areGlobs[0].is_constant,vv.tags)
                            #Variable(new_name,vv.type,None,vv.is_aliased,vv,vv.tags)

    def perform(self) -> None:
        try:
            self._to_cssa()
            self._build_interference_graph()
            self.step3()

            self._parallel_spaces.sequentialize()
            self._parallel_spaces.instert_into_cfg(self._cfg)
        except Exception as e:
            traceback.print_exception(e)


