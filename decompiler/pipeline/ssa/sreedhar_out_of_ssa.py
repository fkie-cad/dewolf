import itertools

from networkx import intersection
from typing import DefaultDict, List, Set

from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.structures.graphs import cfg
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import expressions
from decompiler.structures.pseudo.expressions import Variable, Constant
from decompiler.structures.pseudo.instructions import GenericBranch, Phi, Assignment, Comment, Relation, Return,Branch
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.pipeline.ssa.variable_renaming import SimpleVariableRenamer
from decompiler.task import DecompilerTask

from copy import deepcopy

class SreedharOutOfSsa:
    def __init__(self, task :DecompilerTask):
        self.task = task
        self.cfg =  task.cfg
        self._phi_congruence_class = {}
        self._live_in = {} 
        self._live_out = {} 
        self._new_name_map = {}
        self._interference_graph = InterferenceGraph(self.cfg) 

        liveness = LivenessAnalysis(self.cfg)
        for bb in self.cfg:
            self._live_in[bb] = liveness.live_in_of(bb)
            self._live_out[bb] = liveness.live_out_of(bb)

        #TODO is this correct or should it be all vars
        self._live_out[None] = liveness.live_out_of(None) 

    #TODO find a better way 
    def _get_orig_block(self, phi_instr: Phi, phi_arg):
        blocks = []
        for block, var in phi_instr.origin_block.items():
            if var == phi_arg:
                blocks.append(block)

        if len(blocks) != 0: 
            return blocks
        
        for bb in self.cfg:
            for instr in bb:
                if instr is phi_instr:
                    return [bb]

    def _init_phi_congruence_classes(self):
        for instr in self.cfg.instructions:
            if isinstance(instr, Phi):
                self._phi_congruence_class[instr.destination] = set([instr.destination])
                for x in instr.requirements:
                    self._phi_congruence_class[x] = set([x])

    def _get_phi_congruence_class(self,a): #returns the Set
        try:
            if isinstance((self._phi_congruence_class[a]),set):
                return self._phi_congruence_class[a]
            else: return self._phi_congruence_class[self._phi_congruence_class[a]]
        except KeyError:
            return -1

    def _phi_congruence_classes_interfere(self, i, j):
        if isinstance(i, Variable) and isinstance(j, Variable):
            i, j = self._get_phi_congruence_class(i), self._get_phi_congruence_class(j)
        for y_i, y_j in itertools.product(i, j):
            if self._interference_graph.are_interfering(y_i, y_j):
                return True
        return False

    def _merge_phi_congruence_classes(self, *phi_resources):
        merged_set = set()
        for a in phi_resources:
            merged_set.update(self._get_phi_congruence_class(a))

        rep = phi_resources[0]
        for a in merged_set:
            self._phi_congruence_class[a] = rep
        self._phi_congruence_class[rep] = merged_set
        
    def _init_phi_congruence_classes(self):
        for instr in self.cfg.instructions:
            if isinstance(instr, Phi):
                self._phi_congruence_class[instr.definitions[0]] = set([instr.definitions[0]])
                for x in instr.requirements:
                    self._phi_congruence_class[x] = set([x])

    def _phi_congruence_classes_interfere(self, i, j):
        
        if isinstance(i,set) and isinstance(j,set):
            cc_i = i
            cc_j = j
        else:
            cc_i = self._get_phi_congruence_class(i)
            cc_j = self._get_phi_congruence_class(j)
        for y_i, y_j in itertools.product(cc_i, cc_j, repeat=1):
            if self._interference_graph.are_interfering(y_i, y_j): 
                return True
        return False
    
    def _gen_new_name(self, x: Variable):
        t = x.name + (str(x.ssa_label) if x.ssa_label else "")
        c = self._new_name_map.get(t, 0) + 1
        self._new_name_map[t] = c
        return t + "\'" * c

    def _insert_before_branch(self, instrs, instr):
        for i in range(len(instrs)-1, -1, -1):
            if isinstance(instrs[i], GenericBranch):
                instrs.insert(i, instr)
                return
        instrs.append(instr)

    def _insert_after_phis(self, instrs, new_inst):
        # find first non-Phi
        for idx, ins in enumerate(instrs):
            if not isinstance(ins, Phi):
                instrs.insert(idx, new_inst)
                return
        instrs.append(new_inst)

    #TODO is this now correct?
    def _used_in_phi(self, var, orig, j):
        for instr in j.instructions:
            if isinstance(instr, Phi):
                if var is instr.destination or var in instr.requirements:
                    if orig in self._get_orig_block(instr, var):
                        return True
        return False

    #TODO is this now correct?
    def _prune_dead_out(self, var, block):
        is_live_out = False
        for succ in self.cfg.get_successors(block):
            if var in self._live_in[succ] or self._used_in_phi(var, block, succ):
                is_live_out = True
                break

        if not is_live_out:
            self._live_out[block].discard(var)

    def _insert_copy(self, x, instr: Phi):
        is_req = x in instr.requirements
        x_new = expressions.Variable(self._gen_new_name(x), x.type, ssa_label=1)
        copy_instr = Assignment(x_new, x) if is_req else Assignment(x, x_new)

        if is_req:
            for orig_block in self._get_orig_block(instr, x): 
                if orig_block == None:
                    # create new block
                    orig_block = self.cfg.create_block([]) 
                    block_of_instr = self._get_orig_block(instr, instr.definitions[0])[0]
                    self.cfg.add_edge(UnconditionalEdge(orig_block, block_of_instr))

                block_instrs = orig_block.instructions
                self._insert_before_branch(block_instrs, copy_instr)
                if self._live_out.get(orig_block):
                    self._live_out[orig_block].add(x_new)
                else :
                    self._live_out[orig_block] = set(x_new)
                self._prune_dead_out(x, orig_block)

            instr.substitute(x, x_new)
        else:
            orig_block = self._get_orig_block(instr, x)[0]
            block_instrs = orig_block.instructions
            self._insert_after_phis(block_instrs, copy_instr)
            instr.rename_destination(x, x_new)
            self._live_in[orig_block].discard(x)
            self._live_in[orig_block].add(x_new)

        self._interference_graph = InterferenceGraph(self.cfg)
        self._phi_congruence_class[x_new] = {x_new}
    
    def _classify_pair(self, instr, x_i, x_j, dest, candidates, unresolved):
        l_i = self._get_orig_block(instr, x_i)[0]
        l_j = self._get_orig_block(instr, x_j)[0]

        if x_j is dest:
            cond_1 = self._get_phi_congruence_class(x_i) & self._live_in[l_j]
            cond_2 = self._get_phi_congruence_class(x_j) & self._live_out[l_i]
        else:
            cond_1 = self._get_phi_congruence_class(x_i) & self._live_out[l_j]
            if x_i is dest:
                cond_2 = self._get_phi_congruence_class(x_j) & self._live_in[l_i]
            else:
                cond_2 = self._get_phi_congruence_class(x_j) & self._live_out[l_i]

        # case 1
        if cond_1 and not cond_2:
            candidates.add(x_i)
        # case 2
        elif not cond_1 and cond_2:
            candidates.add(x_j)
        # case 3
        elif cond_1 and cond_2:
            candidates.update((x_i, x_j))
        # case 4
        else:
            unresolved[x_i].add(x_j)
            unresolved[x_j].add(x_i)

    def _resolve_unresolved_neighbors(self, candidates, unresolved):
        resolved = set()
        for x in sorted(unresolved.keys(), 
                        key = lambda x: len(unresolved[x]),
                        reverse = True):

            # if has_unresolved_neighbor  
            if not unresolved[x].issubset(resolved):
                candidates.add(x)
                resolved.add(x)

        # discard all candidates which are now resolved
        for x in list(resolved):
            if unresolved[x].issubset(resolved):
                candidates.discard(x)

    def _nullify_singleton_phi_classes(self):
        self._phi_congruence_class = {
            k: v for k, v in  self._phi_congruence_class.items()
            if not (isinstance(v, set) and len(v) == 1)
        }

    def _eliminate_phi_resource_interference(self):
        self._init_phi_congruence_classes()
        for instr in self.cfg.instructions:
            if not isinstance(instr, Phi):
                continue

            candidates = set()
            dest = instr.destination
            resources = [dest, *instr.requirements]
            unresolved = {x: set() for x in resources}

            for x_i, x_j, in itertools.combinations(resources, 2):
                if self._phi_congruence_classes_interfere(x_i, x_j):
                    self._classify_pair(instr, x_i, x_j, dest, candidates, unresolved)

            self._resolve_unresolved_neighbors(candidates, unresolved)
            for x in candidates:
                self._insert_copy(x, instr) 

            # merge phi congruence classes
            # Note phi_resources has changed due to _insert_copy
            self._merge_phi_congruence_classes(instr.destination, *instr.requirements)

        self._nullify_singleton_phi_classes()


    def _handle_Relations(self):
        for bb in self.cfg:
            for instr in bb.instructions:
                if isinstance(instr,Relation) and isinstance(instr.value,Variable) and isinstance(instr.destination,Variable):
                    if (self._get_phi_congruence_class(instr.value) == -1):
                        self._phi_congruence_class[instr.value] = set([instr.value])
                    if (self._get_phi_congruence_class(instr.destination) == -1):
                        self._phi_congruence_class[instr.destination] = set([instr.destination])
                    self._merge_phi_congruence_classes(instr.value,instr.destination)
        
    def _handle_constants_in_Phi(self):
        for bb in self.cfg:
            for instr in bb.instructions:
                if type(instr) == Phi:
                    for par in instr.value:
                        if type(par) == Constant:
                            assig = Assignment(instr.destination,par)
                            origblock = self._get_orig_block(instr,par)[0]
                            if type(origblock.instructions[-1]) == Branch:
                                origblock.add_instruction(assig, -2)
                            else: origblock.add_instruction(assig,-1)

                        
    def _remove_unnecessary_copies(self):
        self._interference_graph = InterferenceGraph(self.cfg)
        self._handle_Relations()
        for bb in self.cfg:
            for inst in bb:
                if isinstance(inst,Assignment) and (isinstance(inst.value,Variable)) and (isinstance(inst.destination,Variable)):
                    inst : Assignment
                    leftv = inst.destination
                    rightv = inst.value
                    
                    leftpck = self._get_phi_congruence_class(leftv)
                    if leftpck == -1:
                        leftpck = set()
                    rightpck = self._get_phi_congruence_class(rightv)
                    if rightpck == -1:
                        rightpck = set()
                    
                    if (leftpck == rightpck) and (leftpck == set()):   #Case 1 --> Variables are not refrred to in any Phi-instruction or they're in the same Phi-Congruence-Class
                        bb.replace_instruction(inst,[])
                        self._phi_congruence_class[leftv] = set([leftv])
                        self._phi_congruence_class[rightv] = set([rightv])
                        self._merge_phi_congruence_classes(leftv,rightv)

                    elif (leftpck == set()) and (rightpck != set()): #Case 2a
                        rightrem = deepcopy(rightpck)
                        rightrem.remove(rightv)
                        if not (self._phi_congruence_classes_interfere(set([leftv]),rightrem)):
                            bb.replace_instruction(inst,[])
                            self._phi_congruence_class[leftv] = set([leftv])
                            self._merge_phi_congruence_classes(leftv,rightv)
                    
                    elif (leftpck != set()) and (rightpck == set()): #Case 2b
                        leftrem = deepcopy(leftpck)
                        leftrem.remove(leftv)
                        if not (self._phi_congruence_classes_interfere(set([rightv]),leftrem)):
                            bb.replace_instruction(inst,[])
                            self._phi_congruence_class[rightv] = set([rightv])
                            self._merge_phi_congruence_classes(leftv,rightv)

                    elif (leftpck != set()) and (rightpck != set()): #Case 3
                        leftrem = deepcopy(leftpck)
                        leftrem.remove(leftv)
                        rightrem = deepcopy(rightpck)
                        rightrem.remove(rightv)
                        if (not (self._phi_congruence_classes_interfere(leftpck,rightrem))) and (not (self._phi_congruence_classes_interfere(rightpck,leftrem))):
                            bb.replace_instruction(inst,[])
                            self._merge_phi_congruence_classes(leftv,rightv)
                            
        self._handle_constants_in_Phi()


    def _leave_CSSA(self):
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
                renamer.renaming_map[var] = Variable(newName[var],renamer.renaming_map[var].type,ssa_name=var)
            elif renamer.renaming_map[var].name.count(renamer.new_variable_name) != 0 or ((renamer.renaming_map[var].name.count("_") != 0) and renamer.renaming_map[var].name.count("data") == 0):
                if realocation[renamer.renaming_map[var].name] == -1:
                    realocation[renamer.renaming_map[var].name] = f"{renamer.new_variable_name}{count}"
                    renamer.renaming_map[var] = Variable(f"{renamer.new_variable_name}{count}",renamer.renaming_map[var].type,ssa_name=var)
                    count += 1
                else:
                    renamer.renaming_map[var] = Variable(realocation[renamer.renaming_map[var].name],renamer.renaming_map[var].type,ssa_name=var)

        renamer.rename()

    def perform(self):
        self._eliminate_phi_resource_interference() #Step 1: Translation to CSSA
        self._remove_unnecessary_copies()           #Step 3: Eliminate redundant copies
        self._leave_CSSA()                          #Step 3: Eliminate phi instructions and use phi-congruence-property
