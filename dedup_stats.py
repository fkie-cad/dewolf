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


def discover_projects(binary_folder: str) -> list[str]:
    """Each subdirectory of binary_folder is one project (e.g. util-linux, coreutils)"""
    return sorted(d for d in os.listdir(binary_folder) if os.path.isdir(os.path.join(binary_folder, d)))


def scan_binaries_dir(bins_dir: str, member_prefix: str = "") -> tuple[int, int, int, dict[str, list[str]]]:
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
            groups[fp].append(f"{member_prefix}{binary_file}::{function.name}")

    return total, failed, skipped_binaries, groups


def print_dedup_summary(label: str, num_binaries: int, skipped_binaries: int, total: int, kept: int, failed: int) -> None:
    removed = total - kept
    print(f"\n=== {label} ===")
    print(f"Binaries scanned:            {num_binaries - skipped_binaries} ({skipped_binaries} skipped, not loadable)")
    print(f"Total functions:             {total}")
    print(f"Functions after dedup:       {kept}")
    if total:
        print(f"Duplicates removed:          {removed} ({removed / total:.1%})")
    else:
        print(f"Duplicates removed:          {removed}")
    if failed:
        print(f"(of which {failed} functions failed to fingerprint and were kept as-is)", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("bins_dir")
    parser.add_argument(
        "--project-mode",
        action="store_true",
        help="Treat bins_dir as a folder of project subfolders (e.g. input/ or eval/) instead of a flat folder of "
        "binaries. Dedup is computed per project first; a fingerprint already claimed by an earlier project counts "
        "as fully removed (not re-kept) in every later project, matching conditionalTrainingRunner.py's cross-project dedup.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bins_dir = args.bins_dir

    if not args.project_mode:
        total, failed, skipped_binaries, groups = scan_binaries_dir(bins_dir)
        kept = len(groups) + failed  # functions that failed to fingerprint are kept as-is, never deduplicated
        print_dedup_summary(bins_dir, len(os.listdir(bins_dir)), skipped_binaries, total, kept, failed)
        print_group_debug_info(groups)
        return

    projects = discover_projects(bins_dir)
    if not projects:
        raise ValueError(f"No project subfolders found in {bins_dir}.")

    global_seen_fingerprints: set[str] = set()
    all_groups: dict[str, list[str]] = defaultdict(list)
    grand_num_binaries = 0
    grand_skipped_binaries = 0
    grand_total = 0
    grand_kept = 0
    grand_failed = 0

    for project in projects:
        project_dir = os.path.join(bins_dir, project)
        total, failed, skipped_binaries, groups = scan_binaries_dir(project_dir, member_prefix=f"{project}/")

        kept = failed
        for fp, members in groups.items():
            all_groups[fp].extend(members)
            if fp in global_seen_fingerprints:
                continue
            global_seen_fingerprints.add(fp)
            kept += 1

        print_dedup_summary(project, len(os.listdir(project_dir)), skipped_binaries, total, kept, failed)

        grand_num_binaries += len(os.listdir(project_dir))
        grand_skipped_binaries += skipped_binaries
        grand_total += total
        grand_kept += kept
        grand_failed += failed

    print_dedup_summary(
        f"overall ({len(projects)} projects)", grand_num_binaries, grand_skipped_binaries, grand_total, grand_kept, grand_failed
    )
    print_group_debug_info(all_groups)


if __name__ == "__main__":
    main()
