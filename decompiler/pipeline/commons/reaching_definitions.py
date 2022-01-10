from collections import defaultdict, namedtuple
from typing import Dict, Set

from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo import Assignment, Instruction, ListOperation, OperationType, UnaryOperation, Variable

StmtId = namedtuple("StatementId", ["block", "index"])


class ReachingDefinitions:
    def __init__(self, cfg: ControlFlowGraph):
        """
        The data structures used:

        stmt_id - unique identifier of an instruction,
        pair of block and index of instruction in this block

        stmts - mapping from stmt_id to stmt (instruction)
        the latter is not unique
        defs - mapping from variable to the set of its definitions
        kill_block - mapping from basic block to the set of definitions "killed" by that block
        gen_block - mapping from basic block to the set of definitions "generated" by that block
        kill_stmt - mapping from stmt_id to the set of definitions "killed" by that statement
        gen_stmt - mapping from stmt_id to the set of definitions "generated" by that statement

        out_block - mapping from basic block to the set of definitions reaching the end of the block
        in_block - mapping from basic block to the set of definitions reaching the beginning of the block
        out_stmt - mapping from stmt_id to the set of definitions reaching the end of the statement
        in_stmt - mapping from stmt_id to the set of definitions reaching the beginning of the statement


        """
        self.cfg: ControlFlowGraph = cfg

        # this stuff remains the same after being initialized once
        self._stmts: Dict[StmtId, Instruction] = dict()
        self._defs: Dict[Variable, Set[Assignment]] = defaultdict(set)
        self._gen_block: Dict[BasicBlock, Set[Assignment]] = defaultdict(set)
        self._kill_block: Dict[BasicBlock, Set[Assignment]] = defaultdict(set)
        self._gen_stmt: Dict[StmtId, Set[Assignment]] = defaultdict(set)
        self._kill_stmt: Dict[StmtId, Set[Assignment]] = defaultdict(set)

        # this stuff keeps intermediate and final results
        # during computing data-flow equations
        self._out_block: Dict[BasicBlock, Set[Assignment]] = defaultdict(set)
        self._in_block: Dict[BasicBlock, Set[Assignment]] = defaultdict(set)
        self._in_stmt: Dict[StmtId, Set[Assignment]] = defaultdict(set)
        self._out_stmt: Dict[StmtId, Set[Assignment]] = defaultdict(set)
        self._compute()

    def _compute(self) -> None:
        """
        Computes:
        for each basic block:
        - set of definitions that reach the beginning of the block
        - set of definitions that reach the end of the block
        for each point in function, aka statement:
        - set of definitions that reach the beginning of the statement
        - set of definitions that reach the end of the statement

        :param task: decompiler task that contains the cfg
        """
        self._initialize_defs()
        self._initialize_stmts_gens_kills()
        self._compute_reaching_definitions_for_blocks()
        self._compute_reaching_definitions_for_statements()

    def reach_out_block(self, block: BasicBlock) -> Set[Assignment]:
        """
        :param block: basic block
        :return: a set of the definitions that reach the end of the basic block
        """
        return self._out_block[block]

    def reach_in_block(self, block: BasicBlock) -> Set[Assignment]:
        """
        :param block: basic block
        :return: a set of the definitions that reach the beginning of the basic block
        """
        return self._in_block[block]

    def reach_out_stmt(self, block: BasicBlock, index: int) -> Set[Assignment]:
        """
        Returns a set of definitions that reach the end of the statement. A statement is uniquely defined
        through its basic block and the index within the basic block
        :param block: basic block that contains the statement
        :param index: index/position of the statement within the block
        :return: a set of definitions that reach the end of the statement
        """
        return self._out_stmt[StmtId(block=block, index=index)]

    def reach_in_stmt(self, block: BasicBlock, index: int) -> Set[Assignment]:
        """
        Returns a set of definitions that reach the beginning of the statement. A statement is uniquely defined
        through its basic block and the index within the basic block
        :param block: basic block that contains the statement
        :param index: index/position of the statement within the block
        :return: a set of definitions that reach the beginning of the statement
        """
        return self._in_stmt[StmtId(block=block, index=index)]

    def _compute_reaching_definitions_for_blocks(self):
        """
        Algorithm:
        1) initialize gen/kill sets for blocks.
        2) Add all the nodes to worklist (actually, it is a set)
        3) For speeding up we can initialize definitions that reach the end of the block (out_block) with a set of
         definitions generated by that block (gen_block)
        4) Remove(pick) a basic block from the worklist
        5) Apply dataflow equations (in- and out-equations) to this basic block
        6) In case the out-block of the node changes, it causes the in-sets of successor nodes to be changed.
        Therefore, each time the out-block of the currently processed node changes, we put its successors to the worklist.
        7) The algorithm terminates when there are no more nodes in the worklist
        """
        self._initialize_gens_and_kills()
        worklist = set()

        for block in self.cfg.iter_preorder():
            self._out_block[block] = self._gen_block[block]
            worklist.add(block)

        while worklist:
            current = worklist.pop()
            old_out_block = set(self._out_block[current])
            self._in_block[current] = self._in_block_equation(current)
            self._out_block[current] = self._out_block_equation(current)
            if old_out_block != self._out_block[current]:
                for s in self.cfg.get_successors(current):
                    worklist.add(s)

    def _compute_reaching_definitions_for_statements(self):
        """
        Computes reaching definitions (in-/out-) for each statement.
        Algorithm:
        0) In- and out- sets for the basic blocks are assumed to be known
        In this case, in- and out-sets for all statements in the block can be computed in
        a single forward pass
        1) For each basic block, initialize in-set of the first statement with the in-set of the block
        2) For each statement, compute in- and out-set as following:
        - out-set via out-equation for statements
        - in-set as an out-set of the preceding statement
            Equation: in[s] = out[pred] - since within the basic block a statement has 1 or 0 predecessors
        """
        for block in self.cfg.nodes:
            in_set: Set[Assignment] = self._in_block[block]
            for index in range(len(block.instructions)):
                current_stmt = StmtId(block, index)
                self._in_stmt[current_stmt] = set(in_set)
                out_set = self._out_stmt_equation(current_stmt, in_set)
                self._out_stmt[current_stmt] = out_set
                in_set = set(self._out_stmt[current_stmt])

    def _in_block_equation(self, block: BasicBlock) -> Set[Assignment]:
        """
        Computes reaching definitions reaching the beginning of the block as the union of
        sets of definitions that reach the end of its predecessors:
        in[n] = U(p in preds[n]) out[p]
        :param block: basic block
        :return set of definitions reaching the beginning of the block
        """
        in_set = set()
        for p in self.cfg.get_predecessors(block):
            in_set = in_set | self._out_block[p]
        return in_set

    def _out_block_equation(self, block: BasicBlock) -> Set[Assignment]:
        """
        Computes definitions reaching the end of the basic block as the union of definitions generated within the block
        and the difference between those reaching the beginning of the block and killed within the block:
        out[n] = gen[n] U (in[n] - kill[n])
        :param block: basic block
        :return set of definitions reaching the end of the block
        """
        return self._gen_block[block] | (self._in_block[block] - self._kill_block[block])

    def _out_stmt_equation(self, stmt_id: StmtId, in_stmts: Set[Assignment]) -> Set[Assignment]:
        """
        Computes a set of definitions that reach the end of the statement. Those are the definitions generated
        by the statement summed up to the difference of definitions reaching the beginning of the statement and killed by the statement
        Equation: out[s] = gen[s] U (in[s] - kill[s])
        :param stmt_id: id of the statement
        :param in_stmts: set of statements that reach the beginning of the statement
        :return: a set of definitions that reach the end of the statement
        """
        return self._gen_stmt[stmt_id] | (in_stmts - self._kill_stmt[stmt_id])

    def _gen_block_equation(self, block: BasicBlock) -> Set[Assignment]:
        """
        Computes a gen-set of a block: accumulates gen-sets of block's statement by combining gen-set
        of a current statement with gen-set of predecessor minus kill-set of current statement, for all
        the statements in the block
        gen[pred, n] = gen[n] U (gen[p] - kill[n])
        :param block: basic block
        :return: set of definitions generated by that block
        """
        gens = set()
        if not block.instructions:
            return gens

        gens = gens | self._gen_stmt[StmtId(block, 0)]
        for i in range(len(block.instructions) - 1):
            stmt_id = StmtId(block, i + 1)
            gens = self._gen_stmt[stmt_id] | (gens - self._kill_stmt[stmt_id])
        return gens

    def _kill_block_equation(self, block: BasicBlock) -> Set[Assignment]:
        """
        Computes a kill-set of a basic block: union of definitions, killed by each statement of the block

        The definitions what is killed inside the block vary among different sources. The one currently used (above)
        is from Tiger Book. In this case can happen that a definition from gen set of the block is also in kill set.
        Consider:
        s1: a = 1
        s2: a = 2
        Both statements kill each other so the kill set contains both: {s1, s2}
        This is not a problem for out set computation, as out = gen union (in - kill), in this case:
        {s2} union ({} - {s1, s2}) = {s2}

        If the other definition of kill set is desired (everything that killed in block and not generated in block),
        the commented lines could be used for kills computation.

        :param block: basic block
        :return: set of definitions that are killed in that block
        """
        kills = set()
        for index in range(len(block.instructions)):
            kills = kills | self._kill_stmt[StmtId(block, index)]
        # for index, instr in enumerate(block.instructions):
        #     kills = (kills - {instr}) | self._kill_stmt[StmtId(block, index)]
        return kills

    def _compute_gen_stmt(self, stmt: Instruction) -> Set[Assignment]:
        """
        Computes gen-set of a statement
        Gen-set of a statement contains itself if the statement defines or "generates" a variable;
        is empty set otherwise
        :param stmt: given stmt(instruction)
        :return set of definitions generated by that statement
        s: a = b: gen(s) = {s}
        s: a > b: gen(s) = {}
        s: ret a: gen(s) = {}
        s: *a = b: gen(s) = {}
        s: a = *b: gen(s) = {s}
        s: a = func(b): gen(s) = {s}
        s: func(b): gen(s) = {}
        """
        if self._is_definition(stmt):
            return {stmt}
        return set()

    def _compute_kill_stmt(self, stmt: Instruction) -> Set[Assignment]:
        """
        Computes kill-set of a statement
        Kill-set of a statement d = c is all the definitions of d that are invalidated by the current statement,
        if it is a definition;
        otherwise, kill-set is an empty set
        :param stmt: given statement(instruction)
        :return set of definitions killed by the statement

        s: a = b: kill(s) = defs(a) - {s}
        s: a > b: kill(s) = {}
        s: ret a: kill(s) = {}
        s: *a = b: kill(s) = {}
        s: a = *b: kill(s) = defs(a) - {s}
        s: a = func(b): kill(s) = defs(a) - {s}
        s: func(b): kill(s) = {}
        """
        kills = set()
        if self._is_definition(stmt):
            for defined_variable in stmt.definitions:
                kills.update(self._defs[defined_variable])
            kills = kills - {stmt}
        return kills

    def _initialize_gens_and_kills(self) -> None:
        """
        gen-set: set of definitions, generated in a block/statement
        kill-set: set of definitions, killed in a block/statement

        Initializes the mapping from blocks to their kill-/gen-sets (explicitly)
        Initializes the mapping from statement ids to the kill-/gen-sets of the
        corresponding statements (implicitly), during calling gen- and kill-equations for the blocks
        """
        for block in self.cfg.nodes:
            self._gen_block[block] = self._gen_block_equation(block)
            self._kill_block[block] = self._kill_block_equation(block)

    def _initialize_defs(self) -> None:
        """
        Initializes a mapping from variables to their definitions. We make a mapping since the set of definitions
        remains the same for a variable and we want to avoid recomputing it each time when kill(stmt) is computed
        """
        for instr in self.cfg.instructions:
            if self._is_definition(instr):
                for defined_var in instr.definitions:
                    self._defs[defined_var].add(instr)

    def _initialize_stmts_gens_kills(self) -> None:
        """
        Initializes stmts, kill_stmt and gen_stmt mappings.

        We need statement ids and not the statements itself
        because we won't be able otherwise to differentiate between statements
        that look the same but are in the different points of the program:
        0: a = 5
        1: b = a - reaching-in definition is a = 5
        2: a = 6
        3: b = a - reaching-in definition is a = 6
        """
        for block in self.cfg.nodes:
            for index, instr in enumerate(block.instructions):
                stmt_id = StmtId(block, index)
                self._stmts[stmt_id] = instr
                self._kill_stmt[stmt_id] = self._compute_kill_stmt(instr)
                self._gen_stmt[stmt_id] = self._compute_gen_stmt(instr)

    def _is_definition(self, instruction: Instruction) -> bool:
        """
        Checks if a given instruction defines a variable.
        Only assignments can define their left-hand-side in case it is now a write of memory location(dereference)
        We also want to avoid marking calls without return values as definitions

        :param instruction: instruction to be check if it defines a variable
        :return: true if definition false otherwise
        """
        return (
            isinstance(instruction, Assignment)
            and not self._is_dereference(instruction.destination)
            and not self._is_empty_list(instruction.destination)
        )

    @staticmethod
    def _is_empty_list(expression) -> bool:
        """
        Tests if a given expression is an empty list [operation]
        :param expression: expression to be tested
        :return: true if empty list else otherwise
        """
        return isinstance(expression, ListOperation) and not expression.operands

    @staticmethod
    def _is_dereference(expression) -> bool:
        """
        Tests if a given expression is a dereference (e.g. in *a = b *a is dereference)
        :param expression: expression to be tested
        :return: true if dereference false otherwise
        """
        return isinstance(expression, UnaryOperation) and expression.operation == OperationType.dereference
