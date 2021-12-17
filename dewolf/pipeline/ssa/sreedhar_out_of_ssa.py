import itertools
import logging

import dewolf.structures.pseudo.expressions as expressions
import dewolf.utils as utils

"""Sreedhar et. al. "Translating Out Of Static Single Assignment Form"""


# TODO: "here we consider dst of phi live at the beginnin of the block"
class OutOfSsaTranslation(object):
    def __init__(self):
        self.cfg = None
        self._live_in = None
        self._live_out = None
        self._interference_graph = None
        self._phi_congruence_class = None
        self._stmt_block_map = None
        self._use_map = None
        self._def_map = None
        self._copy_counter = 0

    def __call__(self, cfg, liveness):
        self.cfg = cfg
        self._interference_graph = liveness.interference_graph
        self._live_out = liveness._live_out_block
        self._live_in = liveness._live_in_block
        self._stmt_block_map = {}
        self._use_map = liveness._use_map
        self._def_map = liveness._def_map
        self._phi_congruence_class = {}
        for bb in self.cfg:
            for instr in self.cfg.get_node_instructions(bb):
                self._stmt_block_map[instr] = bb
        self.perform()

    def perform(self):
        logging.debug("out of ssa")

        for i in self.cfg.instructions:
            if isinstance(i, expressions.Phi):
                self._live_in[self._stmt_block_map[i]].add(i.dst)
        self._break_phi_interference()

        utils.show_flow_graph(self.cfg, "out ssa copies")
        for i in self.cfg.instructions:
            for d in i.defs:
                d.unsubscribe()
            for u in i.uses:
                u.unsubscribe()

        for bb in self.cfg:
            instructions = self.cfg.get_node_instructions(bb)
            new_instructions = []
            for i in instructions:
                if not (self._is_copy(i) or isinstance(i, expressions.Phi)):
                    new_instructions.append(i)
            self.cfg.set_node_instructions(bb, new_instructions)

    def perform2(self):
        logging.info("perform")
        self._eliminate_phi_resource_interference()
        utils.show_flow_graph(self.cfg, "out ssa copies")
        for i in self.cfg.instructions:
            for d in i.defs:
                d.unsubscribe()
            for u in i.uses:
                u.unsubscribe()

        for bb in self.cfg:
            instructions = self.cfg.get_node_instructions(bb)
            new_instructions = []
            for i in instructions:
                if not (self._is_copy(i) or isinstance(i, expressions.Phi)):
                    new_instructions.append(i)
            self.cfg.set_node_instructions(bb, new_instructions)

    def _is_copy(self, instr):
        return isinstance(instr, expressions.Assignment) and instr.src == instr.dst

    def _eliminate_phi_resource_interference(self):
        self._init_phi_congruence_classes()
        for instr in self.cfg.instructions:
            if isinstance(instr, expressions.Phi):
                current_block = self._stmt_block_map[instr]
                candidate_resource_set = set()
                unresolved_neighbor_map = {}
                phi_resources = [instr.dst]
                phi_resources.extend(instr.src)
                for x in phi_resources:
                    unresolved_neighbor_map[x] = set()

                for pair in itertools.combinations(phi_resources, 2):
                    x_i, x_j = pair
                    if self._phi_congruence_classes_interfere(x_i, x_j):
                        li = self._get_orig_block(current_block, x_i, instr)
                        lj = self._get_orig_block(current_block, x_j, instr)

                        self._determine_copies(x_i, li, x_j, lj, candidate_resource_set)
                # self._process_unresolved()

                for x in candidate_resource_set:
                    self._insert_copy(x, instr)
                # merge phi congruence class
                current_phi_congruence_class = set()
                for x in phi_resources:
                    current_phi_congruence_class.update(self._phi_congruence_class[x])
                    self._phi_congruence_class[x] = current_phi_congruence_class
                    # self.nullify_congruence_classes_with_singleton_resources()

    def _insert_copy(self, x, instr):
        logging.info(instr)
        current_block = self._stmt_block_map[instr]

        if x in instr.src:
            orig_block = self._get_orig_block(current_block, x, instr)
            copy = expressions.Var(instr.dst.name, instr.dst.type)

            copy_instr = expressions.Assignment(copy, x)
            self._copy_counter += 1
            self.cfg.get_node_instructions(orig_block).append(copy_instr)
            self._stmt_block_map[copy_instr] = instr

            instr.src.remove(x)
            instr.src.append(copy)
            self._phi_congruence_class[copy] = set([copy])
            change = False
            for s in self.cfg.successors(orig_block):
                if x not in self._live_in[s] and not self._used_in_phi_k_j(x, s):
                    change = True
            if change:
                if x in self._live_out[orig_block]:
                    self._live_out[orig_block].remove(x)
            for e in self._live_out[orig_block]:
                self._interference_graph.add_edge(copy, e)
            self._stmt_block_map[instr] = current_block

        else:

            xnew = expressions.Var(x.name, x.type)
            self._copy_counter += 1
            xnew_copy = expressions.Assignment(x, xnew)
            instructions = self.cfg.get_node_instructions(current_block)
            index = 0
            for i in xrange(len(instructions)):
                if not isinstance(instructions[i], expressions.Phi):
                    index = i
                    break
            self.cfg.get_node_instructions(current_block).insert(index, xnew_copy)
            instr.dst = xnew
            self._phi_congruence_class[xnew] = set([xnew])
            self._live_in[current_block].add(xnew)
            for e in self._live_in[current_block]:
                self._interference_graph.add_edge(xnew, e)

            self._stmt_block_map[instr] = current_block
            self._stmt_block_map[xnew_copy] = current_block

    def _get_orig_block(self, current_block, phi_arg, phi_instr):
        predecessors = self.cfg.predecessors(current_block)
        for p in predecessors:
            if phi_arg in self._live_out[p]:
                return p
        # TODO it wont't work if body block in predecessors before loop entry block
        return 0

    def _used_in_phi_k_j(self, var, j):
        instructions = self.cfg.get_node_instructions(j)
        for i in instructions:
            if not isinstance(i, expressions.Phi):
                continue
            if var == i.dst or var in i.src:
                return True
        return False

    def _init_phi_congruence_classes(self):
        for instr in self.cfg.instructions:
            if isinstance(instr, expressions.Phi):
                self._phi_congruence_class[instr.dst] = set([instr.dst])
                for x in instr.src:
                    self._phi_congruence_class[x] = set([x])

    def _phi_congruence_classes_interfere(self, i, j):
        cc_i = self._phi_congruence_class[i]
        cc_j = self._phi_congruence_class[j]
        interfere = False
        for pair in itertools.product(cc_i, cc_j, repeat=1):
            y_i, y_j = pair
            if self._interference_graph.are_interfering(y_i, y_j):
                interfere = True

        return interfere

    def _determine_copies(self, i, li, j, lj, candidates):
        if self._interference_graph.are_interfering(i, j):
            candidates.add(i)
            candidates.add(j)
            res1 = self._intersection_of_phi_and_live_out(i, lj)
            res2 = self._intersection_of_phi_and_live_out(j, li)
            if res1 and not res2:
                logging.info("case1")
                candidates.add(i)
            elif not res2 and res1:
                logging.info("case2")
                candidates.add(j)
            elif not res1 and not res2:
                logging.info("case3")
                candidates.add(i)
                candidates.add(j)
            else:
                logging.info("case4")
                candidates.add(i)
                candidates.add(j)
                #
                # candidates.add(x)
                # candidates.add(y)
                # if self._interference_graph.interfere(i, j):
                #     candidates.add(i)
                #     candidates.add(j)

    def _intersection_of_phi_and_live_out(self, x, ly):
        phi = self._phi_congruence_class[x]
        live = self._live_out[ly]
        return phi.intersection(live)

    def _break_phi_interference(self):
        self._initialize_phi_congruence_classes()
        for instr in self.cfg.instructions:
            if not isinstance(instr, expressions.Phi):
                continue
            phi = instr
            candidate_resource_set = set()
            unresolved_neighbor_map = {x: set() for x in phi.resources}
            self._add_basic_block_information_to_phi(phi)
            for xi, xj in self._pairs(phi.resources):
                if self._congruence_classes_interfere(xi, xj):
                    self._determine_candidates(xi, xj, phi, candidate_resource_set, unresolved_neighbor_map)
            self._process_unresolved_resources(candidate_resource_set)
            for rsc in candidate_resource_set:
                self._insert_copy2(rsc, phi)
            self._merge_phi_congruence_class(phi)
        self._nullify_singleton_phi_congruence_classes()

    def _initialize_phi_congruence_classes(self):
        for i in self.cfg.instructions:
            if isinstance(i, expressions.Phi):
                for r in i.resources:
                    self._phi_congruence_class[r] = {r}

    def _process_unresolved_resources(self, candidate_resource_set):
        pass

    def _merge_phi_congruence_class(self, phi):
        current_phi_congruence_class = set()
        for r in phi.resources:
            current_phi_congruence_class.update(self._phi_congruence_class[r])
        for r in phi.resources:
            self._phi_congruence_class[r] = current_phi_congruence_class

    def _nullify_singleton_phi_congruence_classes(self):
        to_delete = set()
        for resource, congruence_class in self._phi_congruence_class.items():
            if len(congruence_class) == 1:
                to_delete.add(resource)
        for d in to_delete:
            del self._phi_congruence_class[d]

    def _insert_copy2(self, resource, phi):
        if resource != phi.dst:
            new_var = self._create_copy_var(resource)
            copy = self._make_copy(new_var, resource)
            resource_block = phi.get_resource_basic_block(resource)
            self._replace_phi_argument(resource, new_var, phi)
            self._insert_copy_at_the_end(resource_block, copy)
            self._phi_congruence_class[new_var] = {new_var}
            live_out = self._live_out[resource_block]
            self._try_to_remove_old_argument_from_live_out(resource_block, resource)
            self._build_interference_edges(new_var, live_out)
        else:
            new_var = self._create_copy_var(resource)
            copy = self._make_copy(resource, new_var)

            current_block = self._stmt_block_map[phi]
            self._insert_phi_target_copy(copy, current_block)
            phi.dst = new_var
            self._phi_congruence_class[new_var] = {new_var}
            self._live_in[current_block].remove(resource)
            self._live_in[current_block].add(new_var)
            self._build_interference_edges(new_var, self._live_in[current_block])

    def _insert_phi_target_copy(self, copy, block):
        instructions = self.cfg.get_node_instructions(block)
        last_phi_index = 0
        for i in instructions:
            if isinstance(i, expressions.Phi):
                last_phi_index += 1
        instructions.insert(last_phi_index, copy)

    def _insert_copy_at_the_end(self, block, copy):
        instructions = self.cfg.get_node_instructions(block)
        instructions.append(copy)

    def _try_to_remove_old_argument_from_live_out(self, resource_block, resource):
        can_remove = True
        for s in self.cfg.successors(resource_block):
            if resource in self._live_in[s] or self._is_used_in_phi_in_block(resource, resource_block):
                can_remove = True
        if can_remove:
            self._live_out[resource_block].remove(resource)

    def _is_used_in_phi_in_block(self, resource, block):
        instructions = self.cfg.get_node_instructions(block)
        for i in instructions:
            if isinstance(i, expressions.Phi) and resource in i.src:
                return True
        return False

    @staticmethod
    def _create_copy_var(original):
        # TODO do we need to mark it as a copy?
        # TODO now it is diff from original as it does not have subscript
        # TODO it makes copy removal easier, but is it valid?
        return expressions.Var(original.name, original.type)

    @staticmethod
    def _make_copy(dst, src):
        return expressions.Assignment(dst, src)

    def _build_interference_edges(self, var, live_set):
        for s in live_set:
            if not self._interference_graph.are_interfering(var, s):
                self._interference_graph.add_edge(var, s)

    @staticmethod
    def _replace_phi_argument(old, new, phi):
        old_index = phi.src.index(old)
        phi.src.insert(old_index, new)
        phi.src.remove(old)

    def _determine_candidates(self, i, j, phi, candidate_resource_set, unresolved_neighbor_map):
        if i != phi.dst and j != phi.dst:
            self._determine_candidates_for_sources(i, j, phi, candidate_resource_set, unresolved_neighbor_map)

        else:
            self._determine_candidates_for_target_and_source(i, j, phi, candidate_resource_set, unresolved_neighbor_map)

    def _determine_candidates_for_sources(self, i, j, phi, candidate_resource_set, unresolved_neighbor_map):
        phi_i = self._phi_congruence_class[i]
        phi_j = self._phi_congruence_class[j]
        live_out_i = self._live_out[phi.get_resource_basic_block(i)]
        live_out_j = self._live_out[phi.get_resource_basic_block(j)]
        intersection_empty_ij = self._intersection_empty(phi_i, live_out_j)
        intersection_empty_ji = self._intersection_empty(phi_j, live_out_i)
        if intersection_empty_ij and not intersection_empty_ji:
            candidate_resource_set.add(i)
        elif not intersection_empty_ij and intersection_empty_ji:
            candidate_resource_set.add(j)
        elif intersection_empty_ij and intersection_empty_ij:
            unresolved_neighbor_map[i].add(j)
            unresolved_neighbor_map[j].add(i)
        elif not intersection_empty_ij and not intersection_empty_ji:
            candidate_resource_set.add(i)
            candidate_resource_set.add(j)

    def _determine_candidates_for_target_and_source(self, t, s, phi, candidate_resource_set, unresolved_neighbor_map):
        phi_t = self._phi_congruence_class[t]
        phi_s = self._phi_congruence_class[s]
        live_out_t = self._live_out[phi.get_resource_basic_block(t)]
        live_in_s = self._live_in[phi.get_resource_basic_block(t)]
        intersection_empty_ij = self._intersection_empty(phi_t, live_in_s)
        intersection_empty_ji = self._intersection_empty(phi_s, live_out_t)
        if intersection_empty_ij and not intersection_empty_ji:
            candidate_resource_set.add(t)
        elif not intersection_empty_ij and intersection_empty_ji:
            candidate_resource_set.add(s)
        elif intersection_empty_ij and intersection_empty_ij:
            unresolved_neighbor_map[s].add(t)
            unresolved_neighbor_map[t].add(s)
        elif not intersection_empty_ij and not intersection_empty_ji:
            candidate_resource_set.add(s)
            candidate_resource_set.add(t)

    def _intersection_empty(self, x, y):
        return x.intersection(y)

    def _congruence_classes_interfere(self, xi, xj):
        for yi in self._phi_congruence_class[xi]:
            for yj in self._phi_congruence_class[xj]:
                if self._interference_graph.are_interfering(yi, yj):
                    return True
        return False

    def _add_basic_block_information_to_phi(self, phi):
        phi_target_block = self._stmt_block_map[phi]
        phi.set_resource_basic_block(phi.dst, phi_target_block)
        predesessors = self.cfg.predecessors(phi_target_block)
        for arg in phi.src:
            orig_block = self._get_phi_argument_block(arg, predesessors)
            phi.set_resource_basic_block(arg, orig_block)

    @staticmethod
    def _pairs(iterable):
        return itertools.combinations(iterable, 2)

    def _get_phi_argument_block(self, phi_argument, phi_block_predecessors):
        for p in phi_block_predecessors:
            if phi_argument in self._live_out[p]:
                return p
        return None

    def _rename_congruence_classes(self):
        pass

    def _remove_copies(self):
        pass
