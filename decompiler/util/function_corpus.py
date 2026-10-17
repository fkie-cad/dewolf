"""Shared operations over a corpus of functions spanning many binaries: deciding which
BinaryNinja functions count as real decompilation targets (as opposed to compiler/CRT
scaffolding or imported/external symbols), and grouping functions across a whole binary folder
by their MLIL-SSA structural fingerprint i.e. deciding which functions are the same
compiled object code (e.g. the same statically-linked library routine) recurring across
binaries.
"""

import os
import traceback

import binaryninja
from binaryninja.enums import SymbolType
from binaryninja.function import Function
from decompiler.util.function_fingerprint_mlil import function_fingerprint

# Compiler/CRT scaffolding that is never a real decompilation target.
BLACKLIST = {
    "_init",
    "_fini",
    "_start",
    "__cxa_finalize",
    "__x86.get_pc_thunk.bx",
    "deregister_tm_clones",
    "register_tm_clones",
    "__do_global_dtors_aux",
    "frame_dummy",
    "__x86.get_pc_thunk.dx",
    "__libc_start_main",
    "__libc_csu_init",
    "__libc_csu_fini",
    "__x86.get_pc_thunk.bp",
}


def is_enumerable_function(function: Function) -> bool:
    """True unless function is blacklisted scaffolding or an imported/external symbol."""
    if function.name in BLACKLIST:
        return False
    if function.symbol.type == SymbolType.ImportedFunctionSymbol:
        return False
    return True


def build_function_groups(binary_folder: str, error_log_path: str) -> tuple[dict[str, list[str]], dict[str, list[str]], int]:
    """Scan every binary in binary_folder and fingerprint every enumerable function via MLIL.

    Returns (groups, functions_by_binary, failed):
      groups: {fingerprint: [binary::function, ...]} -- only for functions that fingerprinted
        successfully; this is what a duplicate decision is based on.
      functions_by_binary: {binary_file: [function_name, ...]} -- every enumerable function,
        regardless of whether fingerprinting succeeded. Callers that need the complete function
        list (not just the ones that ended up in some group) must use this, not flatten `groups`
        -- a function that failed to fingerprint is absent from `groups` entirely, and must still
        be treated as unique (never deduplicated), not silently dropped.
      failed: how many functions raised while fingerprinting.
    """
    groups: dict[str, list[str]] = {}
    functions_by_binary: dict[str, list[str]] = {}
    failed = 0

    for binary_file in sorted(os.listdir(binary_folder)):
        binary_path = os.path.join(binary_folder, binary_file)
        if not os.path.isfile(binary_path):
            continue
        try:
            bv = binaryninja.load(binary_path)
        except Exception:
            bv = None
        if bv is None:
            with open(error_log_path, "a") as error_log:
                error_log.write(f"Error while loading {binary_path}: not a loadable binary\n")
            continue

        try:
            names = functions_by_binary.setdefault(binary_file, [])
            for function in bv.functions:
                if not is_enumerable_function(function):
                    continue
                names.append(function.name)
                key = f"{binary_file}::{function.name}"
                try:
                    fp = function_fingerprint(function)
                except Exception:
                    failed += 1
                    with open(error_log_path, "a") as error_log:
                        error_log.write(f"Error while fingerprinting {key}: {traceback.format_exc()}\n")
                    continue
                groups.setdefault(fp, []).append(key)
        finally:
            bv.file.close()

    return groups, functions_by_binary, failed
