import itertools

from networkx import intersection

from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import instructions
from decompiler.structures.pseudo.instructions import Phi


class SreedharOutOfSsa:
    def __init__(self, cfg: ControlFlowGraph, interference_graph: InterferenceGraph, liveness: LivenessAnalysis):
        self.cfg = cfg
        self._interference_graph = interference_graph
        self._phi_congruence_class = {}
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
        cc_i = self._phi_congruence_class[i]
        cc_j = self._phi_congruence_class[j]
        for y_i, y_j in itertools.product(cc_i, cc_j, repeat=1):
            if self._interference_graph.are_interfering(y_i, y_j): return True

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
                        

                        



    def perform(self):
        self._eliminate_phi_resource_interference()
