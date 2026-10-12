#!/usr/bin/env python3
import argparse
import os
import sys
from collections import defaultdict

import binaryninja
from decompiler.util.function_corpus import is_enumerable_function
from decompiler.util.function_fingerprint_mlil import function_fingerprint


def print_group_debug_info(groups: dict[str, list[str]]) -> None:
    duplicate_groups = [members for members in groups.values() if len(members) > 1]
    duplicate_groups.sort(key=len, reverse=True)

    print()
    print(f"--- {len(duplicate_groups)} duplicate groups (size > 1) ---")
    for members in duplicate_groups:
        total = len(members)
        binaries_by_name: dict[str, list[str]] = defaultdict(list)
        for member in members:
            binary, name = member.split("::", 1)
            binaries_by_name[name].append(binary)

        names = ", ".join(sorted(binaries_by_name))
        print(f"\nGroup occurred {total} times, in the functions {names}:")
        for name, binaries in sorted(binaries_by_name.items(), key=lambda kv: len(kv[1]), reverse=True):
            count = len(binaries)
            binary_list = ", ".join(sorted(binaries))
            print(f"    {name}: {count} time{'s' if count != 1 else ''} ({count / total:.1%}) -- in {binary_list}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("bins_dir")
    return parser.parse_args()


def main() -> None:
    bins_dir = parse_args().bins_dir

    total = 0
    failed = 0
    skipped_binaries = 0
    groups: dict[str, list[str]] = defaultdict(list)

    for binary_file in sorted(os.listdir(bins_dir)):
        binary_path = os.path.join(bins_dir, binary_file)
        if not os.path.isfile(binary_path):
            continue
        try:
            bv = binaryninja.load(binary_path)
        except Exception:
            bv = None
        if bv is None:
            skipped_binaries += 1
            continue

        for function in bv.functions:
            if not is_enumerable_function(function):
                continue
            total += 1
            try:
                fp = function_fingerprint(function)
            except Exception:
                failed += 1
                continue
            groups[fp].append(f"{binary_file}::{function.name}")

    kept = len(groups) + failed  # functions that failed to fingerprint are kept as-is, never deduplicated
    removed = total - kept

    print(f"Binaries scanned:            {len(os.listdir(bins_dir)) - skipped_binaries} ({skipped_binaries} skipped, not loadable)")
    print(f"Total functions:             {total}")
    print(f"Functions after dedup:       {kept}")
    print(f"Duplicates removed:          {removed} ({removed / total:.1%})")
    if failed:
        print(f"(of which {failed} functions failed to fingerprint and were kept as-is)", file=sys.stderr)

    print_group_debug_info(groups)


if __name__ == "__main__":
    main()
