import itertools


from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.structures.graphs import cfg
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import expressions
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.instructions import Phi, Assignment 
from copy import deepcopy


class SreedharOutOfSsa:
    def __init__(self, cfg: ControlFlowGraph, interference_graph: InterferenceGraph, liveness: LivenessAnalysis):
        self.cfg = cfg
        self._interference_graph = interference_graph
        self._phi_congruence_class = {}
        self.liveness = liveness
        self._live_in = {} 
        self._live_out = {} 
        self._inst_to_block_map = {}
        for bb in self.cfg:
            self._live_in[bb] = liveness.live_in_of(bb)
            self._live_out[bb] = liveness.live_out_of(bb)
            #TODO find a good way to do this
            for instr in bb.instructions:
                self._inst_to_block_map[instr] = bb


    def _get_orig_block(self, phi_instr: Phi, phi_arg):
        #TODO check if this works
        inv_block = {v: k for k, v in phi_instr.origin_block.items() if v != None}
        return inv_block[phi_arg] 

    def _get_phi_congruence_class(self, a):
        x = self._phi_congruence_class[a]
        if isinstance(x, set):
            return x
        return self._phi_congruence_class[x]

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
            copy = expressions.Variable(instr.definitions[0].name + "_new", instr.definitions[0].type)
            copy_instr = Assignment(copy, x)
            orig_block.instructions.append(copy_instr)
            instr.requirements.remove(x)
            instr.requirements.append(copy)
            self._phi_congruence_class[copy] = set([copy])
            self._live_out[orig_block].append(copy)
            for s in self.cfg.get_successors(orig_block):
                if x not in self._live_in[s] and not self._used_in_phi(x, s):
                    # consider discard
                    if x in self._live_out[orig_block]:
                        self._live_out[orig_block].remove(x)
            for e in self._live_out[orig_block]:
                self._interference_graph.add_edge(copy, e)
            
        else:
            current_block = self._inst_to_block_map[instr]
            xnew = expressions.Variable(x.name, x.type)
            xnew_copy = Assignment(x, xnew)
            instructions = current_block.instructions
            index = 0
            for i in range(len(instructions)):
                if not isinstance(instructions[i], Phi):
                    index = i
                    break
            current_block.instructions.insert(index, xnew_copy)
            # is this the correct way
            instr.definitions[0] = xnew
            self._phi_congruence_class[xnew] = set([xnew])
            # does discard work?
            self._live_in[current_block].discard(x)
            self._live_in[current_block].add(xnew)

            for e in self._live_out[current_block]:
                self._interference_graph.add_edge(xnew, e)

            self._inst_to_block_map[xnew_copy] = current_block

 
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
                for x in list(candidate_resource_set):
                    if unresolved_neighbor_map[x].issubset(resolved_resources):
                        candidate_resource_set.discard(x)

                for x in candidate_resource_set:
                    self._insert_copy(x, instr) 
                
                # merge phi congruence classes
                self._merge_phi_congruence_classes(*phi_resources)

        # Nullify phi congruence classes that contain only singleton resources
        for x, cls in list(self._phi_congruence_class.items()):
            if len(cls) == 1:
                del self._phi_congruence_class[x]
                        
    def _remove_unnecessary_copies(self):
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


    def _leave_CSSA(self):
        pass
                        

    def perform(self):
        self._eliminate_phi_resource_interference() #Step 1: Translation to CSSA
        self._remove_unnecessary_copies()           #Step 2: Eliminate redundant copies
        self._leave_CSSA()                          #Step 3: Eliminate phi instructions and use phi-congruence-property


