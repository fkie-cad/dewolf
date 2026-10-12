#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

from decompiler.util.function_corpus import build_function_groups


def build_exclusion_list(binary_folder: str, error_log_path: str) -> dict:
    """Fingerprint every function in every binary under binary_folder, group by fingerprint,
    and return {"groups": {fingerprint: [binary::function, ...]}, "excluded": [...]}."""
    groups, functions_by_binary, failed = build_function_groups(binary_folder, error_log_path)
    total = sum(len(names) for names in functions_by_binary.values())

    excluded: list[str] = []
    for members in groups.values():
        members.sort()
        excluded.extend(members[1:])  # keep the first (deterministic) representative

    print(
        f"--- Fingerprinted {total} functions ({failed} failed), {len(groups)} distinct groups, {len(excluded)} excluded as duplicates. ---"
    )
    return {"groups": groups, "excluded": sorted(excluded)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binaryFolder", "-b", required=True, help="Folder of binaries making up the evaluation corpus.")
    parser.add_argument("--output", "-o", required=True, help="Output path for the exclusion-list JSON.")
    args = parser.parse_args()

    error_log_path = str(Path(args.output).with_suffix(".errors.log"))
    result = build_exclusion_list(args.binaryFolder, error_log_path)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    main()
