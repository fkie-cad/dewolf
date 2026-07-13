#!/usr/bin/env python3
"""Report how dewolf's post-out-of-SSA variables match the C source variables.

Runs the dewolf pipeline up to and including out-of-SSA translation, then for
each renamed variable reports the lifted (pre-rename) variable and the source it
was matched to:
  * a C source variable name recovered from DWARF (variable.origin.source_name), or
  * for read-only globals (string literals / const data), the constant value itself.

It also emits the decompiled code at that pipeline point (the CFG basic blocks after
out-of-SSA) so the reported variables can be read in context.

The binary must be compiled with -g (that is where the source names come from).
Results are printed and also written to a JSON file.

Usage (dewolf venv, binaryninja importable, cwd = dewolf repo):
  python3 report_variable_matching.py BINARY [fn1,fn2,...] [output.json]
"""

import json
import sys

from decompiler.frontend.binaryninja.frontend import BinaryninjaFrontend
from decompiler.pipeline.default import CFG_STAGES
from decompiler.pipeline.pipeline import PREPROCESSING_STAGES, DecompilerPipeline
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation
from decompiler.structures.pseudo import GlobalVariable, Variable
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def build_pipeline(options):
    """Build exactly the pipeline decompile.py runs, truncated right after out-of-SSA.

    decompile.py does NOT run the full default.CFG_STAGES list: it selects CFG stages
    BY NAME from the ``pipeline.cfg_stages`` option (via DecompilerPipeline.from_strings),
    which omits graph-expression-folding / dead-component-pruner / edge-pruner and uses a
    different order/multiplicity. We mirror that exact selection and order so the CFG fed
    into out-of-SSA is identical, then stop after OutOfSsaTranslation (skipping the
    restructuring and AST stages, which run after out-of-SSA and do not affect it).
    """
    name_to_stage = {stage.name: stage for stage in CFG_STAGES}
    stages = PREPROCESSING_STAGES.copy()
    stages += [name_to_stage[name] for name in options.getlist("pipeline.cfg_stages") if name in name_to_stage]
    stages.append(OutOfSsaTranslation)
    return DecompilerPipeline(stages)


def _const_string(global_var):
    """Render a read-only global's constant value as a readable string.

    String literals are stored as a Constant whose value is a list of single
    characters, so join them back into one string; otherwise stringify as is.
    """
    value = getattr(global_var.initial_value, "value", global_var.initial_value)
    if isinstance(value, list):
        return "".join(str(character) for character in value)
    return str(value)


def function_code(task):
    """Render the CFG at this pipeline point (post-out-of-SSA) as basic blocks of instructions.

    This is the code representation the variable records refer to: the variable names
    printed here (var_1, data_..., etc.) are exactly the ones classified below.
    """
    blocks = []
    for block in sorted(task.graph.nodes, key=lambda b: b.address):
        blocks.append({"block": block.address, "instructions": [str(instr) for instr in block.instructions]})
    return blocks


def report_function(frontend, name, options, pipeline):
    """Run the pipeline to out-of-SSA and return (matching records, code representation)."""
    task = DecompilerTask(name, name, options)
    frontend.lift(task)
    pipeline.run(task)  # same run semantics as decompile.py (truncated after out-of-SSA)
    if task.failed:
        print(f"  (pipeline failed at stage '{task.failure_origin}'; out-of-SSA may not have run)")

    records = []
    seen = set()
    for instr in task.graph.instructions:
        for var in list(instr.definitions) + list(instr.requirements):
            if not isinstance(var, Variable) or str(var) in seen:
                continue
            seen.add(str(var))
            # After out-of-SSA the renamed variable carries its lifted provenance
            # directly (variable_renaming copies origin onto the replacement), so
            # the C source name is readable straight off the renamed variable.
            if var.origin is not None and var.origin.source_name is not None:
                source, kind = var.origin.source_name, "dwarf-local"
            elif isinstance(var, GlobalVariable) and var.is_constant:
                # read-only globals (string literals / const data) have no DWARF
                # local, but the constant value itself is the ground truth.
                source, kind = _const_string(var), "const-string"
            else:
                source, kind = None, "unmatched"
            lifted = var.ssa_name  # the specific pre-rename SSA variable it replaced
            records.append(
                {
                    "variable": str(var),
                    "lifted": f"{lifted.name}#{lifted.ssa_label}" if lifted is not None else None,
                    "source": source,
                    "kind": kind,
                }
            )
    return records, function_code(task)


def kind_breakdown(records):
    """Count matched/total per kind (dwarf-local, const-string, unmatched)."""
    breakdown = {}
    for r in records:
        entry = breakdown.setdefault(r["kind"], {"matched": 0, "total": 0})
        entry["total"] += 1
        if r["source"] is not None:
            entry["matched"] += 1
    return breakdown


def print_report(name, records, code):
    print(f"\n## {name}")
    print("  ### code after out-of-SSA")
    for blk in code:
        print(f"    block {hex(blk['block'])}:")
        for line in blk["instructions"]:
            print(f"      {line}")
    print("  ### variable matching")
    for r in records:
        lifted = r["lifted"] or "-"
        print(f"  {r['variable']:14} <- lifted {lifted:14} -> source variable: {r['source'] or '(none)'}  [{r['kind']}]")
    breakdown = kind_breakdown(records)
    # report each kind separately so the variable-renaming score (dwarf-local) is
    # not diluted by trivially-matched string constants (const-string).
    for kind in ("dwarf-local", "const-string", "unmatched"):
        if kind in breakdown:
            print(f"  {kind:13} {breakdown[kind]['matched']}/{breakdown[kind]['total']}")


def main():
    binary = sys.argv[1]
    only = set(sys.argv[2].split(",")) if len(sys.argv) > 2 and sys.argv[2] else None
    out_path = sys.argv[3] if len(sys.argv) > 3 else "variable_matching.json"
    options = Options.load_default_options()
    frontend = BinaryninjaFrontend.from_path(binary, options)
    pipeline = build_pipeline(options)

    report = {}
    for name in frontend.get_all_function_names():
        if only is not None and name not in only:
            continue
        try:
            records, code = report_function(frontend, name, options, pipeline)
        except Exception as exc:
            print(f"\n## {name}\n  (skipped: {type(exc).__name__}: {exc})")
            continue
        print_report(name, records, code)
        report[name] = {
            "matched": sum(1 for r in records if r["source"] is not None),
            "total": len(records),
            "by_kind": kind_breakdown(records),
            "variables": records,
            "code": code,
        }

    with open(out_path, "w") as fh:
        json.dump({"binary": binary, "functions": report}, fh, indent=2)
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
