#!/usr/bin/env python3
"""Report how dewolf's post-out-of-SSA variables match the C source variables.

Runs the dewolf pipeline up to and including out-of-SSA translation, then for each renamed
variable reports the lifted (pre-rename) SSA variable and the source it was matched to:
  * a C source variable name recovered from DWARF (``variable.origin.source_name``), or
  * for read-only globals (string literals / const data), the constant value itself.

One out-of-SSA name (e.g. ``var_1``) merges a whole renaming class of SSA variables, and each
occurrence keeps the provenance of the specific SSA variable it replaced. The unit of record is
therefore the (output name, lifted SSA variable) pair, so a name mapping to several source
variables (an *over-merge*) stays visible instead of being collapsed to its first occurrence.

It also emits two code snapshots so the reported variables can be read in context and provenance
propagation can be inspected: the CFG after preprocessing (each line annotated with the DWARF
source names, once lifting and preprocessing have propagated them) and the CFG after out-of-SSA
(each line annotated with the SSA origin of its variables).

The binary must be compiled with -g (that is where the source names come from). The variable
matching, tallies, and collisions are printed to the terminal; the full results (including the
code snapshots and CFG edges, which are not printed) are written to a JSON file.

JSON output: ``{"binary": <path>, "functions": {<name>: <entry>}}`` with exactly one entry per
function, every entry sharing the same keys so the file is uniform to parse:
  * ``status``:  ``"success"`` (analyzed) | ``"failed"`` (pipeline failed at a stage) |
    ``"decompilation-error"`` (decompiler.run raised) | ``"parsing-error"`` (building the report raised)
  * ``message``: ``null`` when status is ``"success"``, otherwise why the function was skipped
  * ``report``:  the analysis (matches, tallies, over-/under-merges, conflicts, code snapshots,
    edges) when status is ``"success"``, otherwise ``null``

Usage (dewolf venv, binaryninja importable, cwd = dewolf repo):
  python3 report_variable_matching.py BINARY [fn1,fn2,...] [output.json] [-q/--quiet]

Pass -q/--quiet to suppress all terminal output (still writes the JSON) - useful for larger
evaluations. To view any field (including the code snapshots and edges) back out of the JSON
afterwards, use the standalone inspect_report.py (no dewolf/binaryninja needed):
  python3 inspect_report.py REPORT.json [-f fn1,fn2,...] [--fields variables,code,edges,tally,collisions]

Layering (outer depends on inner; dewolf types confined to the layers that need them):
  domain -> classification/collection -> analysis -> infrastructure -> presentation -> CLI
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, DefaultDict, Dict, Iterator, List, Set, Tuple

from decompiler.frontend.binaryninja.frontend import BinaryninjaFrontend
from decompiler.pipeline.default import CFG_STAGES
from decompiler.pipeline.pipeline import PREPROCESSING_STAGES, DecompilerPipeline
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation
from decompiler.structures.graphs.branches import SwitchCase
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo import Constant, GlobalVariable, Instruction, Variable
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

# --------------------------------------------------------------------------------------------- #
# Domain model (pure data; no dewolf/IO dependencies)
# --------------------------------------------------------------------------------------------- #


class MatchKind(Enum):
    """How a variable was matched to its source."""

    DWARF_LOCAL = "dwarf-local"  # matched to a DWARF source local via provenance
    CONST_STRING = "const-string"  # read-only global; the constant value is the ground truth
    UNMATCHED = "unmatched"  # no source could be attributed


@dataclass(frozen=True)
class VariableMatch:
    """A single (output name, lifted SSA variable) -> source attribution."""

    variable: str  # output (post-out-of-SSA) variable name
    lifted: str | None  # "name#ssa_label" of the SSA variable this occurrence replaced
    source: str | None  # matched source variable / constant value (None if unmatched)
    kind: MatchKind


@dataclass(frozen=True)
class CodeLine:
    """One instruction plus a per-variable annotation.

    ``annotations`` maps a variable name to the distinct tags describing it on this line. The tag
    meaning depends on the snapshot: DWARF source names for the lifted code, SSA origins
    ("name#label") for the post-out-of-SSA code. A name can carry several tags (e.g. a self-update
    var_1 = var_1 + 1 standing for two SSA versions).
    """

    text: str
    annotations: Dict[str, List[str]]


@dataclass(frozen=True)
class CodeBlock:
    """A basic block: its address and its annotated instruction lines."""

    address: int
    lines: List[CodeLine]


@dataclass(frozen=True)
class CfgEdge:
    """A control-flow edge between two basic blocks (identified by their addresses)."""

    source: int  # source block address
    sink: int  # sink block address
    condition: str  # BasicBlockEdgeCondition value: unconditional | true | false | indirect | switch
    cases: List[str] | None = None  # switch case constants, only for switch edges


@dataclass
class KindTally:
    """Matched/total counts for one MatchKind."""

    matched: int = 0
    total: int = 0


@dataclass
class FunctionReport:
    """The full matching result for one function, plus derived analyses."""

    name: str
    matches: List[VariableMatch]
    code_preprocessed: List[CodeBlock]  # CFG after preprocessing; lines annotated with DWARF source names
    code: List[CodeBlock]  # post-out-of-SSA CFG; lines annotated with SSA origins
    edges: List[CfgEdge]

    @property
    def matched(self) -> int:
        """Number of records that were attributed to a source (over all kinds)."""
        return sum(1 for match in self.matches if match.source is not None)

    @property
    def total(self) -> int:
        """Number of (output name, lifted SSA variable) records in this function."""
        return len(self.matches)

    def tally_by_kind(self) -> DefaultDict[MatchKind, KindTally]:
        """Matched/total per kind, so the renaming score (dwarf-local) is not diluted by
        trivially-matched string constants (const-string)."""
        tallies: DefaultDict[MatchKind, KindTally] = defaultdict(KindTally)
        for match in self.matches:
            tallies[match.kind].total += 1
            if match.source is not None:
                tallies[match.kind].matched += 1
        return tallies

    def overmerged(self) -> Dict[str, List[str]]:
        """Output names that map to several sources via *different* SSA variables (over-merge).

        The renamer grouped SSA variables that DWARF says are different source variables - a
        precision error. The differing sources must come from distinct lifted SSA variables; the
        same SSA variable resolving to several sources is a conflict (see conflicts()), not an
        over-merge, so it is excluded here.
        """
        sources = self._grouped(key=lambda match: match.variable, value=lambda match: match.source or "")
        lifted = self._grouped(key=lambda match: match.variable, value=lambda match: match.lifted or "")
        return {variable: sorted(names) for variable, names in sources.items() if len(names) > 1 and len(lifted[variable]) > 1}

    def conflicts(self) -> Dict[str, List[str]]:
        """One SSA variable ("output name (lifted)") attributed to more than one source.

        The same lifted SSA variable resolved to several source names - an ambiguity we cannot
        resolve, distinct from an over-merge (which is *different* SSA variables merged into one
        name). Should not normally happen; recorded so a bulk run surfaces it instead of hiding it.
        """
        grouped = self._grouped(key=lambda match: f"{match.variable} ({match.lifted})", value=lambda match: match.source or "")
        return {identity: sorted(names) for identity, names in grouped.items() if len(names) > 1}

    def undermerged(self) -> Dict[str, List[str]]:
        """Source variables spread across more than one output name (under-merge / over-split).

        The dual of overmerged: the renamer failed to unify SSA variables that DWARF says are the
        same source variable, so one source name appears under several out-of-SSA names - a recall
        error.
        """
        grouped = self._grouped(key=lambda match: match.source or "", value=lambda match: match.variable)
        return {source: sorted(names) for source, names in grouped.items() if len(names) > 1}

    def _grouped(self, key: Callable[[VariableMatch], str], value: Callable[[VariableMatch], str]) -> DefaultDict[str, Set[str]]:
        """Group DWARF-local matched matches by key(match), collecting the distinct value(match)s.

        Restricted to DWARF locals: a source that is a repeated string constant living under two
        globals is not a split variable, so it must not count as a collision.
        """
        grouped: DefaultDict[str, Set[str]] = defaultdict(set)
        for match in self.matches:
            if match.kind is MatchKind.DWARF_LOCAL and match.source is not None:
                grouped[key(match)].add(value(match))
        return grouped


# --------------------------------------------------------------------------------------------- #
# Variable matching (classify each dewolf Variable's source, then collect matches across the CFG)
# --------------------------------------------------------------------------------------------- #


def collect_matches(graph: ControlFlowGraph) -> List[VariableMatch]:
    """Collect the distinct VariableMatch records across the CFG, sorted by (output name, lifted).

    Deduping by the whole record (not by name/SSA identity alone) keeps only genuine duplicates:
      * repeated occurrences of the same SSA variable produce identical records and collapse to one;
      * anything that differs stays separate - a different SSA variable merged into the same output
        name, and (crucially) the same identity carrying a different source.
    Keeping every distinct source matters: if we saved only one source per (name, SSA variable), the
    over-/under-merge analyses - which look at the set of sources per name and names per source -
    could miss a collision.
    """
    matches: Set[VariableMatch] = set()  # frozen VariableMatch is hashable;
    for instruction in graph.instructions:
        for variable in _variables_of(instruction):
            matches.add(_match(variable))
    return sorted(matches, key=lambda match: (match.variable, match.lifted or ""))


def _variables_of(instruction: Instruction) -> Iterator[Variable]:
    """Yield every Variable occurrence (definitions then requirements) of an instruction."""
    for variable in instruction.definitions + instruction.requirements:
        if isinstance(variable, Variable):
            yield variable


def _match(variable: Variable) -> VariableMatch:
    """Build the VariableMatch record for a single variable occurrence."""
    source, kind = classify_source(variable)
    return VariableMatch(variable=str(variable), lifted=_lifted_id(variable), source=source, kind=kind)


def _lifted_id(variable: Variable) -> str | None:
    """The "name#label" identifier of the SSA variable this occurrence replaced, if any."""
    lifted = variable.ssa_name
    return f"{lifted.name}#{lifted.ssa_label}" if lifted is not None else None


def classify_source(variable: Variable) -> Tuple[str | None, MatchKind]:
    """Return the (source, kind) this out-of-SSA variable was matched to. Pure, no IO."""
    # After out-of-SSA the renamed variable carries its lifted provenance directly
    # (variable_renaming copies origin onto the replacement), so the C source name is
    # readable straight off the renamed variable.
    if variable.origin is not None and variable.origin.source_name is not None:
        return variable.origin.source_name, MatchKind.DWARF_LOCAL
    if isinstance(variable, GlobalVariable) and variable.is_constant:
        return _const_string(variable), MatchKind.CONST_STRING
    return None, MatchKind.UNMATCHED


def _const_string(global_var: GlobalVariable) -> str:
    """Render a read-only global's constant value as a readable string.

    String literals are stored as a Constant whose value is a list of single characters, so
    join them back into one string; otherwise stringify as is.
    """
    initial = global_var.initial_value
    value = initial.value if isinstance(initial, Constant) else initial
    if isinstance(value, List):
        return "".join(str(character) for character in value)
    return str(value)


# --------------------------------------------------------------------------------------------- #
# Code & edge extraction (recover the CFG's text and structure into the domain model)
# --------------------------------------------------------------------------------------------- #


def extract_code(graph: ControlFlowGraph, describe: Callable[[Variable], List[str]]) -> List[CodeBlock]:
    """Render a CFG as basic blocks of annotated instruction lines.

    ``describe(variable)`` returns the annotation tags for a single variable occurrence, so the
    same rendering serves different snapshots: DWARF source names right after lifting, SSA origins
    after out-of-SSA.
    """
    return [
        CodeBlock(
            address=block.address,
            lines=[CodeLine(text=str(instruction), annotations=_annotate(instruction, describe)) for instruction in block.instructions],
        )
        for block in sorted(graph.nodes, key=lambda block: block.address)
    ]


def _annotate(instruction: Instruction, describe: Callable[[Variable], List[str]]) -> Dict[str, List[str]]:
    """Collect describe(...) tags for every variable occurrence, keyed by variable name."""
    mapping: DefaultDict[str, Set[str]] = defaultdict(set)
    for variable in _variables_of(instruction):
        mapping[str(variable)].update(describe(variable))
    return {name: sorted(tags) for name, tags in mapping.items() if tags}


def ssa_origin(variable: Variable) -> List[str]:
    """The SSA name ("name#label") this variable stood for, if known (post-out-of-SSA annotation)."""
    ssa = variable.ssa_name
    return [f"{ssa.name}#{ssa.ssa_label}"] if ssa is not None else []


def source_name(variable: Variable) -> List[str]:
    """The matched DWARF source name of this variable, if any (post-preprocessing annotation)."""
    origin = variable.origin
    return [origin.source_name] if origin is not None and origin.source_name is not None else []


def extract_edges(graph: ControlFlowGraph) -> List[CfgEdge]:
    """Render the CFG edges (post-out-of-SSA), so the basic-block graph structure is recoverable."""
    return [
        CfgEdge(
            source=edge.source.address,
            sink=edge.sink.address,
            condition=edge.condition_type.value,
            cases=[str(case) for case in edge.cases] if isinstance(edge, SwitchCase) else None,
        )
        for edge in sorted(graph.edges, key=lambda edge: (edge.source.address, edge.sink.address))
    ]


# --------------------------------------------------------------------------------------------- #
# Report assembly (combine variable matches, code snapshots, and edges into a FunctionReport)
# --------------------------------------------------------------------------------------------- #


def build_function_report(name: str, result: DecompilationResult) -> FunctionReport:
    """Assemble the matches, code snapshots, and edges into a FunctionReport from a decompiled task's CFG."""
    graph = result.task.graph  # post-out-of-SSA CFG
    return FunctionReport(
        name=name,
        matches=collect_matches(graph),
        code_preprocessed=result.code_preprocessed,
        code=extract_code(graph, describe=ssa_origin),
        edges=extract_edges(graph),
    )


# --------------------------------------------------------------------------------------------- #
# Infrastructure (dewolf pipeline)
# --------------------------------------------------------------------------------------------- #


@dataclass
class DecompilationResult:
    """A decompiled function: the finished task plus the post-preprocessing code snapshot.

    The snapshot is taken after the preprocessing stages (which harmonize and propagate the DWARF
    source names - Coherence, register-pair handling, mem-phi conversion, missing definitions) but
    before the CFG/out-of-SSA stages mutate the graph further. Inspecting the source names here
    checks that lifting plus preprocessing propagate them correctly, before renaming muddies things.
    """

    task: DecompilerTask
    code_preprocessed: List[CodeBlock]


class OutOfSsaDecompiler:
    """Runs the dewolf pipeline up to and including out-of-SSA translation for a function.

    The pipeline is split at the preprocessing boundary so the CFG can be snapshot in between:
    preprocessing runs, the source-name-annotated code is captured, then the CFG stages and
    out-of-SSA run. Two DecompilerPipeline.run calls are equivalent to one combined run - run()
    early-returns on task.failed, and no CFG/out-of-SSA stage depends on a preprocessing stage
    (the only declared dependency, bitfield-comparison-unrolling -> expression-propagation, is
    within the post-preprocessing phase), so each pipeline validates on its own.
    """

    _frontend: BinaryninjaFrontend
    _options: Options
    _preprocessing: DecompilerPipeline
    _post_preprocessing: DecompilerPipeline

    def __init__(self, frontend: BinaryninjaFrontend, options: Options) -> None:
        """Store the frontend/options and build the preprocessing and post-preprocessing pipelines."""
        self._frontend = frontend
        self._options = options
        self._preprocessing, self._post_preprocessing = self._build_pipelines(options)

    def run(self, name: str) -> DecompilationResult:
        """Lift, run preprocessing, snapshot the source-name-annotated code, then run the rest."""
        task = DecompilerTask(name, name, self._options)
        self._frontend.lift(task)
        self._preprocessing.run(task)
        code_preprocessed = extract_code(task.graph, describe=source_name)
        self._post_preprocessing.run(task)
        return DecompilationResult(task=task, code_preprocessed=code_preprocessed)

    @staticmethod
    def _build_pipelines(options: Options) -> Tuple[DecompilerPipeline, DecompilerPipeline]:
        """Build the (preprocessing, post-preprocessing) pipeline pair.

        decompile.py does NOT run the full default.CFG_STAGES list: it selects CFG stages BY NAME
        from the ``pipeline.cfg_stages`` option (via DecompilerPipeline.from_strings), which omits
        graph-expression-folding / dead-component-pruner / edge-pruner and uses a different
        order/multiplicity. We mirror that exact selection and order so the CFG fed into out-of-SSA
        is identical, then stop after OutOfSsaTranslation (skipping the restructuring and AST
        stages, which run after out-of-SSA and do not affect it).
        """
        name_to_stage = {stage.name: stage for stage in CFG_STAGES}
        post_stages = [name_to_stage[name] for name in options.getlist("pipeline.cfg_stages") if name in name_to_stage]
        post_stages.append(OutOfSsaTranslation)
        return DecompilerPipeline(PREPROCESSING_STAGES.copy()), DecompilerPipeline(post_stages)


# --------------------------------------------------------------------------------------------- #
# Presentation (text + JSON; depend only on the domain model)
# --------------------------------------------------------------------------------------------- #


class TextReportRenderer:
    """Prints a FunctionReport as human-readable text."""

    _KIND_ORDER = (MatchKind.DWARF_LOCAL, MatchKind.CONST_STRING, MatchKind.UNMATCHED)

    def render(self, report: FunctionReport) -> None:
        """Print the report's variable matching, tallies, and collisions.

        The code snapshots and CFG edges are intentionally not printed - they are large and go to
        the JSON only; use inspect_report.py to view them (or any other field) from the JSON.
        """
        print(f"\n## {report.name}")
        self._render_matches(report.matches)
        self._render_tally(report.tally_by_kind())
        self._render_collisions("over-merged variables (one name -> multiple source variables)", report.overmerged())
        self._render_collisions("under-merged variables (one source variable -> multiple names)", report.undermerged())
        self._render_collisions("conflicts (one SSA variable -> multiple source variables)", report.conflicts())

    @staticmethod
    def render_written(output_path: str) -> None:
        """Print the confirmation that the JSON output was written."""
        print(f"\nwrote {output_path}")

    @staticmethod
    def render_skipped(name: str, message: str) -> None:
        """Print the header and skip note for a function that was not analyzed."""
        print(f"\n## {name}")
        print(f"  (skipped: {message})")

    @staticmethod
    def _render_matches(matches: List[VariableMatch]) -> None:
        """Print one line per match: output name, lifted SSA variable, matched source, and kind."""
        print("  ### variable matching")
        for match in matches:
            lifted = match.lifted or "-"
            source = match.source or "(none)"
            print(f"  {match.variable:14} - lifted {lifted:14} - source variable: {source}  [{match.kind.value}]")

    def _render_tally(self, tally: Dict[MatchKind, KindTally]) -> None:
        """Print the matched/total counts per kind, in the canonical kind order."""
        for kind in self._KIND_ORDER:
            if kind in tally:
                print(f"  {kind.value:13} {tally[kind].matched}/{tally[kind].total}")

    @staticmethod
    def _render_collisions(title: str, collisions: Dict[str, List[str]]) -> None:
        """Print a collision table (over-/under-merges), or nothing when there are none."""
        if not collisions:
            return
        print(f"  ### {title}")
        for group, values in collisions.items():
            print(f"    {group} -> {', '.join(values)}")


class NullReportRenderer:
    """Renderer that prints nothing; selected with --quiet for large evaluations."""

    def render(self, report: FunctionReport) -> None:
        pass

    def render_skipped(self, name: str, message: str) -> None:
        pass

    def render_written(self, output_path: str) -> None:
        pass


class JsonReportSerializer:
    """Serializes a FunctionReport to a JSON-ready dict."""

    def function_to_dict(self, report: FunctionReport) -> Dict[str, Any]:
        """Convert a FunctionReport into a JSON-serializable dict of all its fields and analyses."""
        return {
            "matched": report.matched,
            "total": report.total,
            "by_kind": self._tally_to_dict(report.tally_by_kind()),
            "overmerged": report.overmerged(),
            "undermerged": report.undermerged(),
            "conflicts": report.conflicts(),
            "variables": [self._match_to_dict(match) for match in report.matches],
            "code_preprocessed": [self._block_to_dict(block) for block in report.code_preprocessed],
            "code": [self._block_to_dict(block) for block in report.code],
            "edges": [self._edge_to_dict(edge) for edge in report.edges],
        }

    @staticmethod
    def _tally_to_dict(tally: Dict[MatchKind, KindTally]) -> Dict[str, Any]:
        """Serialize the per-kind matched/total tally, keyed by kind value."""
        return {kind.value: {"matched": item.matched, "total": item.total} for kind, item in tally.items()}

    @staticmethod
    def _match_to_dict(match: VariableMatch) -> Dict[str, Any]:
        """Serialize a single VariableMatch record."""
        return {"variable": match.variable, "lifted": match.lifted, "source": match.source, "kind": match.kind.value}

    @staticmethod
    def _block_to_dict(block: CodeBlock) -> Dict[str, Any]:
        """Serialize a code block: its address and its annotated instruction lines."""
        return {
            "block": block.address,
            "instructions": [{"text": line.text, "annotations": line.annotations} for line in block.lines],
        }

    @staticmethod
    def _edge_to_dict(edge: CfgEdge) -> Dict[str, Any]:
        """Serialize a CFG edge, including switch cases only when present."""
        data: Dict[str, Any] = {"source": edge.source, "sink": edge.sink, "condition": edge.condition}
        if edge.cases is not None:
            data["cases"] = edge.cases
        return data


# --------------------------------------------------------------------------------------------- #
# CLI orchestration
# --------------------------------------------------------------------------------------------- #


def default_output_path(binary: str) -> str:
    """Derive the output file from the binary name so distinct binaries do not overwrite each other.

    Uses the full basename (not the stem) so variants such as ``test.O2`` / ``test.stripped`` keep
    separate reports.
    """
    return f"variable_matching_{Path(binary).name}.json"


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    """Parse the command-line arguments (binary, optional function list, optional output path)."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", help="path to the -g compiled binary")
    parser.add_argument("functions", nargs="?", default=None, help="comma-separated function names (default: all)")
    parser.add_argument("output", nargs="?", default=None, help="output JSON path (default: variable_matching_<binary-name>.json)")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress all terminal output (still writes the JSON)")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    """Run the report for each requested function and write the combined JSON output.

    Decompiles each function up to out-of-SSA, printing a skip note for functions whose pipeline
    failed or raised, and rendering plus serializing a FunctionReport for the rest.
    """
    args = parse_args(argv)
    # Silence pipeline logging (e.g. DeadLoopElimination "could not convert ... into z3 logic"),
    logging.getLogger().setLevel(logging.ERROR)
    function_list = {name.strip() for name in args.functions.split(",")} if args.functions else None
    output_path = args.output or default_output_path(args.binary)

    options = Options.load_default_options()
    frontend = BinaryninjaFrontend.from_path(args.binary, options)
    decompiler = OutOfSsaDecompiler(frontend, options)
    renderer = NullReportRenderer() if args.quiet else TextReportRenderer()
    serializer = JsonReportSerializer()

    functions: Dict[str, Dict[str, Any]] = {}
    for name in frontend.get_all_function_names():
        if function_list is not None and name not in function_list:
            continue
        try:
            result = decompiler.run(name)
        except Exception as exc:
            message = f"decompiling {name} raised {type(exc).__name__}: {exc}"
            renderer.render_skipped(name, message)
            functions[name] = {"status": "decompilation-error", "message": message, "report": None}
            continue

        if result.task.failed:
            message = f"decompiling {name} failed at stage {result.task.failure_origin}"
            renderer.render_skipped(name, message)
            functions[name] = {"status": "failed", "message": message, "report": None}
            continue

        try:
            report: FunctionReport = build_function_report(name, result)
            serialized_report = serializer.function_to_dict(report)
        except Exception as exc:
            message = f"building the report for {name} failed after a successful decompilation: {type(exc).__name__}: {exc}"
            renderer.render_skipped(name, message)
            functions[name] = {"status": "parsing-error", "message": message, "report": None}
            continue

        renderer.render(report)  # I/O: pipe/print errors propagate, not miscategorized as a function error
        functions[name] = {"status": "success", "message": None, "report": serialized_report}

    Path(output_path).write_text(json.dumps({"binary": args.binary, "functions": functions}, indent=2))
    renderer.render_written(output_path)


if __name__ == "__main__":
    main()
