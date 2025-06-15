import itertools
from copy import deepcopy


from networkx import intersection
from typing import DefaultDict, List

from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import instructions
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Phi, Assignment, Comment, Relation, Return,Branch
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.outofssatranslation import SimpleVariableRenamer
from decompiler.task import DecompilerTask


class SreedharOutOfSsa:
    def __init__(self, task :DecompilerTask, interference_graph: InterferenceGraph, liveness: LivenessAnalysis, phi_fuctions: DefaultDict[BasicBlock, List[Phi]]):
        self.task = task
        self.cfg = task.cfg
        self._interference_graph = interference_graph
        self.phi_functions_of = phi_fuctions
        self._phi_congruence_class = {}
        self.liveness = liveness
        self._live_in = []
        self._live_out = []
        for bb in self.cfg:
            self._live_in.append(liveness.live_in_of(bb))
            self._live_out.append(liveness.live_out_of(bb))

    def _init_phi_congruence_classes(self):
        for instr in self.cfg.instructions:
            if isinstance(instr, Phi):
                self._phi_congruence_class[instr.definitions[0]] = set([instr.definitions[0]])
                for x in instr.requirements:
                 self._phi_congruence_class[x] = set([x])

    def _phi_congruence_classes_interfere(self, i, j):
        cc_i = self._get_phi_congruence_class[i]
        cc_j = self._get_phi_congruence_class[j]
        if isinstance(i,set) and isinstance(j,set):
            cc_i = i
            cc_j = j
        for y_i, y_j in itertools.product(cc_i, cc_j, repeat=1):
            if self._interference_graph.are_interfering(y_i, y_j): return True
        return False
        

    def _get_orig_block(self, phi_instr: Phi, phi_arg):
        #TODO check if this works
        inv_block = {v: k for k, v in phi_instr.origin_block.items() if v != None}
        return inv_block[phi_arg] 


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
                        l_j = self._get_orig_block(instr, x_i)

                        # handle the 4 cases
                        a = self._phi_congruence_class[x_i].intersection(self._live_out[l_j])
                        b = self._phi_congruence_class[x_j].intersection(self._live_out[l_i])

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


    def _init_phi_congruence_in_CSSA(self): #Set phi congruence classes to the variables involved in a phi instruction; NOTE: use only when cfg is in CSSA-Form
        self._phi_congruence_class = {}
        for instr in self.cfg.instructions:
            if isinstance(instr,Phi):
                self._phi_congruence_class[instr.definitions[0]] = set(s for s in instr.requirements)
                self._phi_congruence_class[instr.definitions[0]].add(instr.definitions[0])
                for s in instr.requirements:
                    self._phi_congruence_class[s] = instr.definitions[0]
    
    def _get_phi_congruence_class(self,a): #returns the Set
        if isinstance(x := (self._phi_congruence_class[a]),set):
            return x
        else: return self._phi_congruence_class[x]

    def _merge_phi_congruence_classes(self,a,b):
        aset = self._get_phi_congruence_class(self,a)
        bset = self._get_phi_congruence_class(self,b)
        aset = aset.union(bset)
        for x in aset:
            self._phi_congruence_class[x] = a
        self._phi_congruence_class[a] = aset
                        
    def _remove_unnecessary_copies(self):
        self._init_phi_congruence_in_CSSA(self)
        self._interference_graph = InterferenceGraph(self.cfg)
        self.liveness = LivenessAnalysis(self.cfg)
        for inst in self.cfg.instructions:
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
                
                if dest == defi:   #Case 1 --> Variables are not reffrred in any Phi-instruction or they're in the same Phi-Congruence-Class
                    self.cfg.remove_instruction(inst)
                    self._merge_phi_congruence_classes(destv,defiv)
                elif (dest == set()) and (defi != set()): #Case 2a
                    defic = deepcopy(defi).remove(defiv)
                    if not (self._phi_congruence_classes_interfere(set(destv),defic)):
                        self.cfg.remove_instruction(inst)
                        self._merge_phi_congruence_classes(destv,defiv)
                
                elif (dest != set()) and (defi == set()): #Case 2b
                    destc = deepcopy(dest).remove(destv)
                    if not (self._phi_congruence_classes_interfere(set(defiv),destc)):
                        self.cfg.remove_instruction(inst)
                        self._merge_phi_congruence_classes(destv,defiv)

                elif (dest != set()) and (defi != set()): #Case 3
                    destc = deepcopy(dest).remove(destv)
                    defic = deepcopy(defi).remove(defiv)
                    if (not (self._phi_congruence_classes_interfere(dest,defic))) and (not (self._phi_congruence_classes_interfere(defi,destc))):
                        self.cfg.remove_instruction(inst)
                        self._merge_phi_congruence_classes(destv,defiv)
        self._interference_graph = InterferenceGraph(self.cfg)


    def _leave_CSSA(self):
        PhiFunctionLifter(self.cfg,self._interference_graph,self.phi_functions_of)
        renamer = SimpleVariableRenamer(self.task,self._interference_graph)
        max = 0
        for x in renamer.renaming_map:
            if x := int(x.name.split("_")[1]) > max: max = x
        max += 1    

        for var in self._phi_congruence_class:
            if isinstance(self._phi_congruence_class[var],set):
                for entry in self._phi_congruence_class[var]:
                    renamer.renaming_map[entry] = Variable(f"{renamer.new_variable_name}{max}",entry.type)
                max += 1

        renamer.rename()
                        

    def perform(self):
        self._eliminate_phi_resource_interference()     #Step 1: Translation to CSSA
        self._remove_unnecessary_copies(self)           #Step 2: Eliminate redundant copies
        self._leave_CSSA(self)                          #Step 3: Eliminate phi instructions and use phi-congruence-property


