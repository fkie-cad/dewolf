#!/usr/bin/env python3
"""Inspect a variable-matching JSON report produced by report_variable_matching.py.

Reads the JSON (no dewolf / Binary Ninja needed) and prints the fields you ask for, for one or
more functions. Handy after a quiet evaluation run (``report_variable_matching.py --quiet``): that
writes the full JSON without printing anything, and this pulls back exactly the parts you want -
including fields the main run also prints (variables, tallies, collisions) and ones it no longer
does (the code snapshots and CFG edges).

Usage (no dewolf venv needed - only the standard library):
  python inspect_report.py REPORT.json [-f fn1,fn2,...] [--fields variables,code,edges,tally,collisions]

With no --fields, prints a one-line summary per function. Fields (comma-separated, or ``all``):
  summary      status and matched/total count (the default)
  variables    the (output name <- lifted SSA -> source) matching table
  code         both code snapshots (after preprocessing, after out-of-SSA)
  edges        the CFG edges
  tally        matched/total per match kind
  collisions   over-merged, under-merged, and conflicting variables
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

FIELDS = ("summary", "variables", "code", "edges", "tally", "collisions")


def _print_variables(variables: List[Dict[str, Any]]) -> None:
    """Print one line per match: output name, lifted SSA variable, matched source, and kind."""
    print("  ### variable matching")
    for match in variables:
        lifted = match["lifted"] or "-"
        source = match["source"] or "(none)"
        print(f"  {match['variable']:14} <- lifted {lifted:14} -> source variable: {source}  [{match['kind']}]")


def _print_code(title: str, code: List[Dict[str, Any]]) -> None:
    """Print one code snapshot: blocks with their instruction lines and per-variable tags."""
    print(f"  ### {title}")
    for block in code:
        print(f"    block {hex(block['block'])}:")
        for line in block["instructions"]:
            tags = ", ".join(f"{name}={'/'.join(values)}" for name, values in line["annotations"].items())
            suffix = f"    [{tags}]" if tags else ""
            print(f"      {line['text']}{suffix}")


def _print_edges(edges: List[Dict[str, Any]]) -> None:
    """Print the CFG edges with their conditions (and switch cases, if any)."""
    if not edges:
        return
    print("  ### edges")
    for edge in edges:
        cases = edge.get("cases")
        label = f"{edge['condition']}: {', '.join(cases)}" if cases else edge["condition"]
        print(f"    {hex(edge['source'])} -> {hex(edge['sink'])}  [{label}]")


def _print_tally(by_kind: Dict[str, Dict[str, int]]) -> None:
    """Print the matched/total counts per match kind."""
    for kind, tally in by_kind.items():
        print(f"  {kind:13} {tally['matched']}/{tally['total']}")


def _print_collisions(title: str, collisions: Dict[str, List[str]]) -> None:
    """Print a collision table (over-/under-merges), or nothing when there are none."""
    if not collisions:
        return
    print(f"  ### {title}")
    for group, values in collisions.items():
        print(f"    {group} -> {', '.join(values)}")


def inspect_function(name: str, entry: Dict[str, Any], fields: List[str]) -> None:
    """Print the requested fields for a single function entry from the report JSON."""
    print(f"\n## {name}")
    report = entry["report"]
    if "summary" in fields:
        counts = f"{report['matched']}/{report['total']} matched" if report is not None else "no report"
        print(f"  status: {entry['status']}    {counts}")
        if entry["message"]:
            print(f"  message: {entry['message']}")
    detail_fields = [field for field in fields if field != "summary"]
    if not detail_fields:
        return
    if report is None:  # failed / error entries carry no report to show these fields from
        print(f"  (status '{entry['status']}': no report for {', '.join(detail_fields)})")
        return
    if "variables" in fields:
        _print_variables(report["variables"])
    if "code" in fields:
        _print_code("code after preprocessing (with DWARF source names)", report["code_preprocessed"])
        _print_code("code after out-of-SSA (with SSA origins)", report["code"])
    if "edges" in fields:
        _print_edges(report["edges"])
    if "tally" in fields:
        _print_tally(report["by_kind"])
    if "collisions" in fields:
        _print_collisions("over-merged variables (one name -> multiple source variables)", report["overmerged"])
        _print_collisions("under-merged variables (one source variable -> multiple names)", report["undermerged"])
        _print_collisions("conflicts (one SSA variable -> multiple source variables)", report["conflicts"])


def parse_fields(value: str) -> List[str]:
    """Parse the comma-separated --fields value into a validated list (``all`` selects every field)."""
    requested = [field.strip() for field in value.split(",") if field.strip()]
    if "all" in requested:
        return list(FIELDS)
    unknown = [field for field in requested if field not in FIELDS]
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown field(s): {', '.join(unknown)}; choose from {', '.join(FIELDS)}, all")
    return requested


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    """Parse the command-line arguments (report path, optional function filter, optional fields)."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", help="path to a variable_matching_*.json file")
    parser.add_argument("-f", "--functions", default=None, help="comma-separated function names (default: all)")
    parser.add_argument("--fields", type=parse_fields, default=["summary"], help="comma-separated fields to show (default: summary)")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    """Load the report JSON and print the requested fields for each selected function."""
    args = parse_args(argv)
    data = json.loads(Path(args.report).read_text())
    functions: Dict[str, Dict[str, Any]] = data["functions"]
    wanted = {name.strip() for name in args.functions.split(",")} if args.functions else None

    print(f"# {data['binary']}")
    for name, entry in functions.items():
        if wanted is not None and name not in wanted:
            continue
        inspect_function(name, entry, args.fields)


if __name__ == "__main__":
    main()