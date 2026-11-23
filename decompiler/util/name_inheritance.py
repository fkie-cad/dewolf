"""Evaluation-only helpers for source-name inheritance (Variable.origin.source_name / name_via).

When a pipeline stage *replaces* a variable that carries a DWARF source name by another variable (or by a
temporary holding the same value), the replacement may take over that name. These helpers implement the
shared mechanics: conflict-aware candidate collection, never-overwrite application to every occurrence of
an SSA variable, and the per-task registry of propagated values that lets CSE recover the name of an
eliminated variable whose value it re-materializes.

Nothing here may influence any decompiler decision: the helpers only read the IR and (re)bind
`Variable.origin`, which is not part of Variable identity (__eq__/__hash__) and is never rendered.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from typing import Callable, DefaultDict, Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple

from decompiler.structures.pseudo.expressions import DataflowObject, Expression, Variable, VariableProvenance
from decompiler.structures.pseudo.instructions import Phi
from decompiler.structures.pseudo.operations import Call, OperationType, UnaryOperation

SsaKey = Tuple[str, Optional[int]]
NameChain = Tuple[str, Tuple[str, ...]]  # (source_name, name_via)


def ssa_key(variable: Variable) -> SsaKey:
    """The SSA identity used for naming: name + ssa_label (type is irrelevant for the source name)."""
    return variable.name, variable.ssa_label


def name_chain_of(variable: Variable) -> Optional[NameChain]:
    """(source_name, name_via) of the variable, or None if it carries no source name."""
    origin = variable.origin
    if origin is None or origin.source_name is None:
        return None
    return origin.source_name, origin.name_via


def is_name_target(expression: DataflowObject) -> bool:
    """A variable that may inherit a name: a plain, non-aliased local Variable (no GlobalVariable / RegisterPair)."""
    return type(expression) is Variable and not expression.is_aliased


def iter_subexpressions(obj: DataflowObject) -> Iterator[DataflowObject]:
    """All nested DataflowObjects of obj (obj included). Unlike DataflowObject.subexpressions, does not stop at falsy objects."""
    pending: List[DataflowObject] = [obj]
    while pending:
        expression = pending.pop()
        yield expression
        pending.extend(expression)


def iter_variable_occurrences(instructions: Iterable) -> Iterator[Variable]:
    """Every Variable object in the given instructions (deduplicated by identity), including Phi.origin_block values."""
    seen: Set[int] = set()
    for instruction in instructions:
        roots: List[DataflowObject] = [instruction]
        if isinstance(instruction, Phi):
            roots.extend(value for value in instruction.origin_block.values() if value is not None)
        for root in roots:
            for expression in iter_subexpressions(root):
                if isinstance(expression, Variable) and id(expression) not in seen:
                    seen.add(id(expression))
                    yield expression


def collect_occurrences(instructions: Iterable) -> Dict[SsaKey, List[Variable]]:
    occurrences: Dict[SsaKey, List[Variable]] = defaultdict(list)
    for variable in iter_variable_occurrences(instructions):
        occurrences[ssa_key(variable)].append(variable)
    return occurrences


def synthesized_version_origin(
    key: SsaKey,
    existing: Dict[SsaKey, VariableProvenance],
    lifted: Dict[SsaKey, VariableProvenance],
    names: Set[str],
    fallback: Optional[VariableProvenance]
) -> Optional[VariableProvenance]:
    """Provenance for an aliased SSA version created in preprocessing (mem-phi conversion, missing definitions).

    - the version occurs named in the cfg: it is that SSA variable, so its origin;
    - the lifter's DWARF lookup at this memory version found a name: that origin;
    - all named versions of the variable agree on one name: the Coherence rule, tagged ("coherence",),
      unless DWARF was ambiguous at this version or places several source variables in its storage;
    - otherwise (none named, or they disagree): unnamed.
    """
    if (origin := existing.get(key)) is not None:
        return origin
    unnamed = lifted.get(key)
    if unnamed is not None and unnamed.source_name is not None:
        return unnamed
    if unnamed is None and fallback is not None:  # another version's origin: keep storage, drop its value_address and name
        unnamed = replace(fallback, value_address=None, source_name=None, name_via=(), dwarf_ambiguous=False)
    if len(names) == 1 and not (unnamed is not None and (unnamed.dwarf_ambiguous or len(unnamed.dwarf_storage_names) > 1)):
        return replace(unnamed or VariableProvenance(), source_name=next(iter(names)), name_via=("coherence",))
    return unnamed


def pick_chain(chains: Iterable[Tuple[str, ...]]) -> Tuple[str, ...]:
    """Deterministic choice among chains for one agreed name: prefer an observed ('dwarf') root, then the shortest chain."""
    return min(chains, key=lambda chain: (chain[:1] != ("dwarf",), len(chain), chain))


class NameCandidates:
    """Collects name candidates per SSA variable; a variable is named only if all its candidates agree on one name."""

    def __init__(self):
        self._candidates: DefaultDict[SsaKey, Set[NameChain]] = defaultdict(set)

    def add(self, target: SsaKey, name_chain: NameChain) -> None:
        self._candidates[target].add(name_chain)

    def __bool__(self) -> bool:
        return bool(self._candidates)

    def resolve(self) -> Dict[SsaKey, NameChain]:
        return {target: name_chain for target, candidates in self._candidates.items() if (name_chain := resolve_candidates(candidates))}

    def conflicts(self) -> Set[SsaKey]:
        """Targets with candidates that disagree on the name."""
        return {target for target, candidates in self._candidates.items() if len({name for name, _ in candidates}) > 1}


def resolve_candidates(candidates: Iterable[NameChain]) -> Optional[NameChain]:
    """The unique name among the candidates (with a deterministically chosen chain), or None on conflict / no candidate."""
    candidates = list(candidates)
    names = {name for name, _ in candidates}
    if len(names) != 1:
        return None
    (name,) = names
    return name, pick_chain(chain for _, chain in candidates)


def apply_names(instructions: Iterable, names: Dict[SsaKey, NameChain], blocked: Iterable[SsaKey] = ()) -> List[SsaKey]:
    """
    Bind each given name to all occurrences of the SSA variable. Never overwrites: an SSA variable of which any
    occurrence already carries a source name is skipped, as are aliased / global variables, blocked keys (known conflicts)
    and versions where the DWARF lookup was ambiguous.
    The origin object may be shared (Variable.copy() shares it by reference), so it is never mutated: one fresh
    record per SSA variable (a dataclasses.replace of an existing origin, keeping its location fields, or a
    minimal VariableProvenance) is bound to all its occurrences. Returns the keys actually named.
    """
    if not names:
        return []
    occurrences = collect_occurrences(instructions)
    blocked = set(blocked)
    named: List[SsaKey] = []
    for key, (source_name, chain) in names.items():
        if key in blocked:
            continue
        instances = occurrences.get(key, [])
        if not instances or not all(is_name_target(instance) for instance in instances):
            continue
        if any(name_chain_of(instance) is not None for instance in instances):
            continue
        if any(instance.origin is not None and instance.origin.dwarf_ambiguous for instance in instances):
            continue  # DWARF saw several source variables here
        base = next((instance.origin for instance in instances if instance.origin is not None), None)
        if base is None:
            origin = VariableProvenance(source_name=source_name, name_via=chain)
        else:
            origin = replace(base, source_name=source_name, name_via=chain)
        for instance in instances:
            instance.origin = origin
        named.append(key)
    return named


def is_registrable_value(expression: Expression) -> bool:
    """
    A propagated compound value is value-equal wherever it appears (in SSA) only if it does not depend on memory or
    side effects: no aliased / global variables, no dereference, no address-of, no call.
    """
    for sub in iter_subexpressions(expression):
        if isinstance(sub, Variable) and (sub.is_aliased or type(sub) is not Variable):
            return False
        if isinstance(sub, Call):
            return False
        if isinstance(sub, UnaryOperation) and sub.operation in (OperationType.dereference, OperationType.address):
            return False
    return True


class PropagatedValueRegistry:
    """
    Per-task, evaluation-only record of compound values that expression propagation substituted for a variable
    (`x = E`, every use of x replaced by a copy of E): each such copy is registered as "the value of x".

    Entries are keyed by object identity of the inserted copies, so in-place updates of those copies by later stages
    (propagation into E, identity elimination, ...) keep the association, and value-equal expressions that never stood
    for a variable are not confused with ones that did. An object may stand for several variables (copy chains
    `x = E; y = x` make the propagated copy the value of both). Registrations are carried over to copies made by
    propagation (transfer()) and to value-preserving rewrites of a registered expression (same_value(), used by
    expression simplification). Strong references are held so ids are never reused.

    `names` holds the (source_name, name_via) of a replaced variable as known to propagation (its own name, or a name it
    inherited at the end of a propagation stage). `conflicts` holds variables for which a stage found conflicting name
    candidates; later stages must not name them (a known conflict is not resolved by a later, partial view).
    """

    def __init__(self):
        self._entries: Dict[int, Tuple[DataflowObject, FrozenSet[SsaKey]]] = {}
        self.names: Dict[SsaKey, NameChain] = {}
        self.conflicts: Set[SsaKey] = set()

    def __len__(self) -> int:
        return len(self._entries)

    def register(self, expression: DataflowObject, replaced: Iterable[SsaKey]) -> None:
        replaced = frozenset(replaced) | self.replaced_variables_of(expression)
        if replaced:
            self._entries[id(expression)] = (expression, replaced)

    def replaced_variables_of(self, expression: DataflowObject) -> FrozenSet[SsaKey]:
        entry = self._entries.get(id(expression))
        return entry[1] if entry is not None and entry[0] is expression else frozenset()

    def transfer(self, original: DataflowObject, copy: DataflowObject) -> None:
        """Register every subexpression of copy whose structural counterpart in original is registered."""
        if not self._entries:
            return
        for orig_sub, copy_sub in zip(iter_subexpressions(original), iter_subexpressions(copy)):
            if replaced := self.replaced_variables_of(orig_sub):
                self.register(copy_sub, replaced)

    def same_value(self, replacee: DataflowObject, replacement: DataflowObject) -> None:
        """replacement is a value-preserving rewrite of replacee: it stands for the same variables."""
        if self._entries and replacement is not replacee and (replaced := self.replaced_variables_of(replacee)):
            self.register(replacement, replaced)

    def name_candidates_of(self, occurrences: Iterable[DataflowObject], vanished: Callable[[SsaKey], bool]) -> List[NameChain]:
        """Names of the eliminated variables (vanished(key) is True) whose registered values are among the occurrences."""
        result = []
        for occurrence in occurrences:
            for replaced in self.replaced_variables_of(occurrence):
                if vanished(replaced) and (name_chain := self.names.get(replaced)) is not None:
                    result.append(name_chain)
        return result
