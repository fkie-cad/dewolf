from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, DefaultDict, Iterator, List, Optional, Dict
from copy import deepcopy
import networkx as nx

from decompiler.pipeline.ssa.value_interferencegraph import ValueInterferenceGraph
from decompiler.structures.graphs.branches import UnconditionalEdge
from decompiler.task import DecompilerTask
from decompiler.structures.pseudo.expressions import Constant, Variable, GlobalVariable
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo.instructions import Assignment, Phi, Instruction, Relation
from decompiler.util.decoration import DecoratedCFG, DecoratedGraph 
from decompiler.pipeline.ssa.variable_renaming import VariableRenamer


class RevistingOutOfSSa:
    # TODO: these names are stupid
    @dataclass
    class _ParellSpace:
        begin_start_idx: Optional[int] = None
        begin_end_idx: Optional[int] = None

        end_start_idx: Optional[int] = None
        end_end_idx: Optional[int] = None

    class _CongruenceClassHelper:
        pass

    def __init__(self, task: DecompilerTask, phi_functions: DefaultDict[BasicBlock, List[Phi]]):
        self._task: DecompilerTask = task
        self._cfg: ControlFlowGraph = self._task.cfg #type: ignore
        self._phi_functions_of: DefaultDict[BasicBlock, List[Phi]] = phi_functions

        self.lifted_costant_var_name = "__lifted_constat__"
        self._label_count:DefaultDict[str, int] = defaultdict(int)
        self._parell_space_map: DefaultDict[Any[None,BasicBlock], RevistingOutOfSSa._ParellSpace] = defaultdict(RevistingOutOfSSa._ParellSpace)


        self._interference_graph: ValueInterferenceGraph

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

    def _to_cssa(self) -> None:
        self._compute_label_count()

        end_instructions_for_bb: DefaultDict[BasicBlock, List[Instruction]] = defaultdict(list)
        for basic_block in self._phi_functions_of:
            instructions_beginning = list()
            for phi_inst in self._phi_functions_of[basic_block]:
                req = phi_inst.definitions[0]
                copy_var = self._compute_copy_var(req)
                copy_assign = Assignment(req, copy_var)
                instructions_beginning.append(copy_assign)
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
                    end_instructions_for_bb[predecessor].append(copy_assign) 
                    phi_inst.substitute(req, copy_var)


            phi_count = len(self._phi_functions_of[basic_block])
            parallel_space = self._parell_space_map[basic_block]
            parallel_space.begin_start_idx = phi_count
            parallel_space.begin_end_idx = phi_count + len(instructions_beginning) 
            basic_block.instructions = basic_block.instructions[:phi_count] + instructions_beginning + basic_block.instructions[phi_count:]

        for basic_block, instructions in end_instructions_for_bb.items():
            parallel_space = self._parell_space_map[basic_block]
            parallel_space.end_start_idx = len(basic_block.instructions)
            parallel_space.end_end_idx = len(basic_block.instructions) + len(instructions)
            basic_block.instructions.extend(instructions)

    def step3(self):
        self.ifgColoring = deepcopy(self._interference_graph)
        self.handle_Relations()
        for bb in self._cfg:
            for instr in bb:
                if isinstance(instr,Phi):
                    bb.replace_instruction(instr,[])
        self.fsetFix()
        self.doColoring()
        self.renamer = self.BoissinotVariableRenamer(self._task,self._interference_graph,self.vars)
        self.renamer.rename()


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
        colors = nx.greedy_color(self.ifgColoring,"largest_first",True)
        colors : Dict
        nums = [x + 1 for x in colors.values()]
        nums.append(0)
        num = max(nums)
        vars = [[] for _ in range(num)]
        for var, col in colors.items():
            if isinstance(var,frozenset):
                vars[col].extend(var)
            else:
                raise Exception(f"{var} is a {str(type(var))} instead of a frozenset!")
            
        self.vars = vars

    class BoissinotVariableRenamer(VariableRenamer):
        def __init__(self, task: DecompilerTask, interference_graph,varClasses):
            super().__init__(task,interference_graph)

            self.cfg = task.cfg
            self.interference_graph = interference_graph
            self.varClases = varClasses

            self.variable_for_function_arg: Dict[str, Variable] = self._get_function_argument_variables(task.function_parameters)
            self.function_arg_for_variable: Dict[Variable, str] = {v: k for k, v in self.variable_for_function_arg.items()}
            #self._add_interference_for_function_args()

            self.renaming_map: Dict[Variable, Variable] = dict()
            self._generate_renaming_map()

        def _generate_renaming_map(self):
            count = 0
            assignedNames = []

            for varClass in self.varClases:
                new_name = ""
                argcount = 0
                for varin in varClass:
                    if isinstance(varin,GlobalVariable):
                        if len(varClass) > 1:
                            raise Exception("Lenght of Class containing Global Variable greater than 1")  
                        new_name = varin.name
                        if new_name in assignedNames:
                            new_name = f'{new_name}__{count}'
                            count += 1
                        assignedNames.append(new_name)
                        self.renaming_map[varin] = GlobalVariable(new_name,varin.type,varin.initial_value,None,varin.is_aliased,varin,varin.is_constant,varin.tags)
                    elif varin in self.function_arg_for_variable.keys():
                        varin : Variable
                        argcount += 1
                        if argcount > 1:
                            raise Exception("We have more than one Argument in a PCK!")
                        new_name = self.function_arg_for_variable[varin]
                        assignedNames.append(new_name)
                        self.renaming_map[varin] = Variable(new_name,varin.type,None,varin.is_aliased,varin,varin.tags)

                    elif isinstance(varin,Variable):
                        if new_name == "":
                            new_name = varin.name
                            if new_name in assignedNames:
                                new_name = f"{new_name}__{count}"
                                count += 1
                            assignedNames.append(new_name)

                        self.renaming_map[varin] = Variable(new_name,varin.type,None,varin.is_aliased,varin,varin.tags)

                    else:
                        raise Exception(f"Unexpected Type: {str(type(varin))} instead of Variable or Globalvariable")

        def rename(self):
            """
            This function replaces in each instruction a variable by the variable in replacement_for_variable[variable].
            The fuction is overridden here bc we do not want to remove redundant assignments at the end. We need them for Step 4
            """
            for instruction in self.cfg.instructions:
                for variable in instruction.requirements + instruction.definitions:
                    self._replace_variable_in_instruction(variable, instruction)

            

    def perform(self) -> None:
        self._to_cssa()
        self._interference_graph = ValueInterferenceGraph(self._cfg)
        #Note: before this step is executed Constants have to be moved out of the Phi-Functions
        self.step3()
        #insert Step4 beneath ▼

        #insert Step4 above ▲
        self.renamer._remove_redundant_assignments()
