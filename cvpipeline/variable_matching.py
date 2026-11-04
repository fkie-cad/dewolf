"""Matching dewolf's post-out-of-SSA variables to the C source variables from DWARF.

Ported from legacy/report_variable_matching.py (matching and collision analysis only; the code
snapshots and CFG edges that script also stored are not needed for the metrics and are dropped
to keep the evaluation files small).

The unit of record is the (output name, lifted SSA variable) pair: one out-of-SSA name merges a
whole renaming class of SSA variables, and every occurrence keeps the provenance of the SSA
variable it replaced. That way a name standing for several source variables (an over-merge)
stays visible instead of being collapsed to its first occurrence.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, DefaultDict, Dict, Iterator, List, Sequence, Set, Tuple


class MatchKind(Enum):
    DWARF_LOCAL = "dwarf-local"  # DWARF local/parameter, matched via provenance
    DWARF_GLOBAL = "dwarf-global"  # DWARF global, matched by address
    CONST_STRING = "const-string"  # read-only global; its constant value is the ground truth
    UNMATCHED = "unmatched"  # no source could be attributed ("inserted" variable)


@dataclass(frozen=True)
class VariableMatch:
    variable: str  # output (post-out-of-SSA) name
    lifted: str | None  # "name#ssa_label" of the SSA variable this occurrence replaced
    source: str | None  # matched source variable (unique key, see source_key) / constant value, None if unmatched
    kind: MatchKind
    source_name: str | None = None  # the matched source variable's C name, for display

    def to_json(self) -> Dict[str, Any]:
        return {
            "variable": self.variable,
            "lifted": self.lifted,
            "source": self.source,
            "source_name": self.source_name,
            "kind": self.kind.value,
        }


def source_key(origin) -> str:
    """The key identifying a matched DWARF source variable: its name plus its identity (DIE offset),
    so two distinct source variables sharing a name (e.g. two loops' ``i``) stay distinct."""
    if origin.source_id is None:
        return origin.source_name
    return f"{origin.source_name}@{origin.source_id:#x}"


def classify_source(variable) -> Tuple[str | None, MatchKind]:
    """The (source, kind) an out-of-SSA variable was matched to. variable_renaming copies the
    lifted variable's origin onto its replacement, so the source is read directly off it."""
    from decompiler.structures.pseudo import Constant, GlobalVariable

    if variable.origin is not None and variable.origin.source_name is not None:
        # Globals are matched by address and are not renamed like locals, so they get their own
        # kind and stay out of the over-/under-merge analysis.
        kind = MatchKind.DWARF_GLOBAL if isinstance(variable, GlobalVariable) else MatchKind.DWARF_LOCAL
        return source_key(variable.origin), kind
    if isinstance(variable, GlobalVariable) and variable.is_constant:
        initial = variable.initial_value
        value = initial.value if isinstance(initial, Constant) else initial
        # string literals are stored as a list of single characters
        text = "".join(str(character) for character in value) if isinstance(value, list) else str(value)
        return text, MatchKind.CONST_STRING
    return None, MatchKind.UNMATCHED


def _variables_of(instruction) -> Iterator:
    from decompiler.structures.pseudo import Variable

    for variable in instruction.definitions + instruction.requirements:
        if isinstance(variable, Variable):
            yield variable


def _lifted_id(variable) -> str | None:
    lifted = variable.ssa_name
    return f"{lifted.name}#{lifted.ssa_label}" if lifted is not None else None


def collect_matches(graph) -> List[VariableMatch]:
    """Distinct VariableMatch records over the CFG, sorted. Deduplicating by the whole record
    collapses repeated occurrences of the same SSA variable but keeps the same identity with a
    different source, which the collision analyses below must see."""
    matches: Set[VariableMatch] = set()
    for instruction in graph.instructions:
        for variable in _variables_of(instruction):
            source, kind = classify_source(variable)
            source_name = variable.origin.source_name if kind in (MatchKind.DWARF_LOCAL, MatchKind.DWARF_GLOBAL) else None
            matches.add(VariableMatch(variable=str(variable), lifted=_lifted_id(variable), source=source, kind=kind, source_name=source_name))
    return sorted(matches, key=lambda match: (match.variable, match.lifted or "", match.source or ""))


def _grouped_locals(
    matches: Sequence[VariableMatch], key: Callable[[VariableMatch], str], value: Callable[[VariableMatch], str]
) -> DefaultDict[str, Set[str]]:
    """Group matched DWARF locals only: a string constant living under two globals is not a split
    variable and must not count as a collision."""
    grouped: DefaultDict[str, Set[str]] = defaultdict(set)
    for match in matches:
        if match.kind is MatchKind.DWARF_LOCAL and match.source is not None:
            grouped[key(match)].add(value(match))
    return grouped


def overmerged(matches: Sequence[VariableMatch]) -> Dict[str, List[str]]:
    """Output names mapping to several sources via *different* SSA variables (precision error)."""
    sources = _grouped_locals(matches, key=lambda m: m.variable, value=lambda m: m.source or "")
    lifted = _grouped_locals(matches, key=lambda m: m.variable, value=lambda m: m.lifted or "")
    return {name: sorted(values) for name, values in sources.items() if len(values) > 1 and len(lifted[name]) > 1}


def undermerged(matches: Sequence[VariableMatch]) -> Dict[str, List[str]]:
    """Source variables spread over several output names (recall error)."""
    grouped = _grouped_locals(matches, key=lambda m: m.source or "", value=lambda m: m.variable)
    return {source: sorted(names) for source, names in grouped.items() if len(names) > 1}


def conflicts(matches: Sequence[VariableMatch]) -> Dict[str, List[str]]:
    """One SSA variable attributed to several sources - should not happen, recorded to surface it."""
    grouped = _grouped_locals(matches, key=lambda m: f"{m.variable} ({m.lifted})", value=lambda m: m.source or "")
    return {identity: sorted(values) for identity, values in grouped.items() if len(values) > 1}


def build_report(task) -> Dict[str, Any]:
    """The evaluation result for one decompiled function (post-out-of-SSA ``task.graph``)."""
    matches = collect_matches(task.graph)
    return {
        "variables": [match.to_json() for match in matches],
        "overmerged": overmerged(matches),
        "undermerged": undermerged(matches),
        "conflicts": conflicts(matches),
    }
