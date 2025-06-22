import itertools

from networkx import intersection
from typing import DefaultDict, List

from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.structures.graphs import cfg
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import expressions
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Phi, Assignment, Comment, Relation, Return,Branch
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.variable_renaming import SimpleVariableRenamer
from decompiler.task import DecompilerTask
from decompiler.frontend.binaryninja.handlers.symbols import GLOBAL_VARIABLE_PREFIX

from copy import deepcopy


class SreedharOutOfSsa:
#: DefaultDict[BasicBlock, List[Phi]]
    def __init__(self, task :DecompilerTask, interference_graph: InterferenceGraph, phi_fuctions):
        self.task = task
        self.cfg =  task.cfg
        self._interference_graph = interference_graph
        self._phi_congruence_class = {}
        self.liveness = LivenessAnalysis(self.cfg)
        self._live_in = {} 
        self._live_out = {} 
        self._inst_to_block_map = {}
        for bb in self.cfg:
            self._live_in[bb] = self.liveness.live_in_of(bb)
            self._live_out[bb] = self.liveness.live_out_of(bb)
            #TODO find a good way to do this
            for instr in bb.instructions:
                self._inst_to_block_map[instr] = bb


    def _get_orig_block(self, phi_instr: Phi, phi_arg):
        #TODO check if this works
        inv_block = {v: k for k, v in phi_instr.origin_block.items() if v != None}
        if x:= inv_block.get(phi_arg):
            return x
        return self._inst_to_block_map[phi_instr]
            

    def _merge_phi_congruence_classes(self, *phi_resources):
        merged_set = set()
        for a in phi_resources:
            merged_set.update(self._get_phi_congruence_class(a))

        rep = phi_resources[0]
        self._phi_congruence_class[rep] = merged_set
        for a in phi_resources[1:]:
            self._phi_congruence_class[a] = rep


    def _init_phi_congruence_classes(self):
        for instr in self.cfg.instructions:
            if isinstance(instr, Phi):
                self._phi_congruence_class[instr.definitions[0]] = set([instr.definitions[0]])
                for x in instr.requirements:
                    self._phi_congruence_class[x] = set([x])

    def _phi_congruence_classes_interfere(self, i, j):
        cc_i = self._get_phi_congruence_class(i)
        cc_j = self._get_phi_congruence_class(j)
        if isinstance(i,set) and isinstance(j,set):
            cc_i = i
            cc_j = j
        for y_i, y_j in itertools.product(cc_i, cc_j, repeat=1):
            if self._interference_graph.are_interfering(y_i, y_j): 
                return True
        return False

    def _used_in_phi(self, var, j):
        for i in self.cfg.instructions:
            if isinstance(i, Phi):
                if var == i.definitions[0] or var in i.requirements:
                    return True
        return False

    def _insert_copy(self, x, instr: Phi):
        if x in instr.requirements:
            orig_block: BasicBlock= self._get_orig_block(instr, x)
            x_new = expressions.Variable(x.name + "_new", x.type)
            x_new_copy_ass = Assignment(x_new, x)
            orig_block.instructions.append(x_new_copy_ass)
            instr.substitute(x, x_new) 
            self._phi_congruence_class[x_new] = set([x_new])
            self._live_out[orig_block].add(x_new)
            for s in self.cfg.get_successors(orig_block):
                if x not in self._live_in[s] and not self._used_in_phi(x, s):
                    self._live_out[orig_block].discard(x)

            for e in self._live_out[orig_block]:
                self._interference_graph.add_edge(x_new, e)
            
        else:
            x_new = expressions.Variable(x.name+"_new", x.type)
            x_new_copy_ass = Assignment(x, x_new)
            current_block = self._get_orig_block(instr, x)
            instructions = current_block.instructions
            index = 0
            for i in range(len(instructions)):
                if not isinstance(instructions[i], Phi):
                    index = i
                    break
            current_block.instructions.insert(index, x_new_copy_ass)
            instr.rename_destination(x, x_new)
            self._phi_congruence_class[x_new] = set([x_new])
            self._live_in[current_block].discard(x)
            self._live_in[current_block].add(x_new)

            for e in self._live_out[current_block]:
                self._interference_graph.add_edge(x_new, e)

            self._inst_to_block_map[x_new_copy_ass] = current_block

 
    def _eliminate_phi_resource_interference(self):
        self._init_phi_congruence_classes()
        for instr in self.cfg.instructions:
            if isinstance(instr, Phi):
                candidate_resource_set = set()
                unresolved_neighbor_map = {} 

                phi_resources = [instr.definitions[0]]
                phi_resources.extend(instr.requirements)
                for x in phi_resources:
                    unresolved_neighbor_map[x] = set()

                for x_i, x_j, in itertools.combinations(phi_resources, 2):
                    if self._phi_congruence_classes_interfere(x_i, x_j):
                        l_i = self._get_orig_block(instr, x_i)
                        l_j = self._get_orig_block(instr, x_j)

                        # handle the 4 cases
                        if x_j == phi_resources[0]: 
                            a = self._get_phi_congruence_class(x_i).intersection(self._live_in[l_j])
                        else:
                            a = self._get_phi_congruence_class(x_i).intersection(self._live_out[l_j])

                        if x_i == phi_resources[0]: 
                            b = self._get_phi_congruence_class(x_j).intersection(self._live_in[l_i])
                        else:
                            b = self._get_phi_congruence_class(x_j).intersection(self._live_out[l_i])

                        if a and not b:
                            candidate_resource_set.add(x_i)
                        elif not a and b:
                            candidate_resource_set.add(x_j)
                        elif a and b:
                            candidate_resource_set.add(x_i)
                            candidate_resource_set.add(x_j)
                        else:
                            unresolved_neighbor_map[x_i].add(x_j)
                            unresolved_neighbor_map[x_j].add(x_i)

                # process unresolved neighbors
                resolved_resources = set()
                sorted_resources = sorted(
                    unresolved_neighbor_map.keys(),
                    key = lambda x: len(unresolved_neighbor_map[x]),
                    reverse=True
                )
                for x in sorted_resources:
                    # if has_unresolved_neighbor  
                    if not unresolved_neighbor_map[x].issubset(resolved_resources):
                        candidate_resource_set.add(x)
                        resolved_resources.add(x)

                # discard all candidates which are now resolved
                for x in list(resolved_resources):
                    if unresolved_neighbor_map[x].issubset(resolved_resources):
                        candidate_resource_set.discard(x)

                for x in candidate_resource_set:
                    self._insert_copy(x, instr) 

                # merge phi congruence classes
                phi_resources = [instr.definitions[0]]
                phi_resources.extend(instr.requirements)
                self._merge_phi_congruence_classes(*phi_resources)


        # Nullify phi congruence classes that contain only singleton resources
        for x, cls in list(self._phi_congruence_class.items()):
            if isinstance(cls,set) and len(cls) == 1:

                del self._phi_congruence_class[x]

    def _get_phi_congruence_class(self,a): #returns the Set
        try:
            if isinstance(x := (self._phi_congruence_class[a]),set):
                return x
            else: return self._phi_congruence_class[x]
        except KeyError:
            return -1

    def _handle_Relations(self):
        for bb in self.cfg:
            for inst in bb.instructions:
                if isinstance(inst,Relation) and isinstance(inst.value,Variable) and isinstance(inst.destination,Variable):
                    if (self._get_phi_congruence_class(inst.value) == -1) and isinstance(inst.value,Variable):
                        self._phi_congruence_class[inst.value] = set(inst.value)
                    if (self._get_phi_congruence_class(inst.destination) == -1) and isinstance(inst.value,Variable):
                        self._phi_congruence_class[inst.destination] = set(inst.destination)
                    self._merge_phi_congruence_classes(inst.value,inst.destination)
                        
    def _remove_unnecessary_copies(self):
        self._interference_graph = InterferenceGraph(self.cfg)
        self.liveness = LivenessAnalysis(self.cfg)
        self._handle_Relations()
        for bb in self.cfg:
            for inst in bb:
                if isinstance(inst,Assignment) and (isinstance(inst.definitions,Variable)) and (isinstance(inst.destination,Variable)):
                    destv = inst.destination
                    defiv = inst.definitions

                    try: 
                        dest = self._get_phi_congruence_class(destv)
                    except KeyError:
                        dest = set()
                    try:
                        defi = self._get_phi_congruence_class(defiv)
                    except:
                        defi = set()
                    
                    if dest == defi:   #Case 1 --> Variables are not refrred to in any Phi-instruction or they're in the same Phi-Congruence-Class
                        bb.replace_instruction(inst,[])
                        self._phi_congruence_class[destv] = set([destv])
                        self._phi_congruence_class[defiv] = set([defiv])
                        self._merge_phi_congruence_classes(destv,defiv)
                    elif (dest == set()) and (defi != set()): #Case 2a
                        defic = deepcopy(defi).remove(defiv)
                        if not (self._phi_congruence_classes_interfere(set(destv),defic)):
                            bb.replace_instruction(inst,[])
                            self._phi_congruence_class[destv] = set([destv])
                            self._merge_phi_congruence_classes(destv,defiv)
                    
                    elif (dest != set()) and (defi == set()): #Case 2b
                        destc = deepcopy(dest).remove(destv)
                        if not (self._phi_congruence_classes_interfere(set(defiv),destc)):
                            bb.replace_instruction(inst,[])
                            self._phi_congruence_class[defiv] = set([defiv])
                            self._merge_phi_congruence_classes(destv,defiv)

                    elif (dest != set()) and (defi != set()): #Case 3
                        destc = deepcopy(dest).remove(destv)
                        defic = deepcopy(defi).remove(defiv)
                        if (not (self._phi_congruence_classes_interfere(dest,defic))) and (not (self._phi_congruence_classes_interfere(defi,destc))):
                            bb.replace_instruction(inst,[])
                            self._merge_phi_congruence_classes(destv,defiv)
        self._interference_graph = InterferenceGraph(self.cfg)


    def _leave_CSSA(self):
        #for x in self._phi_congruence_class:
        #    if isinstance(self._phi_congruence_class[x],set):
        #        print(self._phi_congruence_class[x])
        for bb in self.cfg: #remove Phi-Instructions
            for inst in bb:
                if isinstance(inst,Phi):
                    bb.replace_instruction(inst,[])                    
    
        renamer = SimpleVariableRenamer(self.task,self._interference_graph)
        realocation = DefaultDict(lambda: -1)
        newName = DefaultDict(lambda: -1)
        count = 1
        for pck in self._phi_congruence_class:
            if isinstance(self._phi_congruence_class[pck],set):
                for var in self._phi_congruence_class[pck]:
                    newName[var] = f"{renamer.new_variable_name}{count}"
                count += 1

        for var in renamer.renaming_map:
            if (newName[var] != -1):  
                renamer.renaming_map[var] = Variable(newName[var],renamer.renaming_map[var].type)
            elif renamer.renaming_map[var].name.count(renamer.new_variable_name) != 0:
                if realocation[renamer.renaming_map[var].name] == -1:
                    realocation[renamer.renaming_map[var].name] = f"{renamer.new_variable_name}{count}"
                    renamer.renaming_map[var] = Variable(f"{renamer.new_variable_name}{count}",renamer.renaming_map[var].type)
                    count += 1
                else:
                    renamer.renaming_map[var] = Variable(realocation[renamer.renaming_map[var].name],renamer.renaming_map[var].type)

        #for bb in self.cfg:
        #    for inst in bb:
        #        if isinstance(inst,Relation):
        #            print(newName[inst.value] == newName[inst.destination])
        #            if(newName[inst.value] != newName[inst.destination]):
        #                print(inst)
        #                print(inst.value)
        #                print(inst.destination)
        #                print(self._get_phi_congruence_class(inst.value))
        #                print(self._get_phi_congruence_class(inst.destination))
        renamer.rename()
        #TODO: fix Error in the Relation-Class
        #TODO: fix Error in the Rlation-Class

    def perform(self):
        self._eliminate_phi_resource_interference() #Step 1: Translation to CSSA
        self._remove_unnecessary_copies()           #Step 2: Eliminate redundant copies
        self._leave_CSSA()                          #Step 3: Eliminate phi instructions and use phi-congruence-property
