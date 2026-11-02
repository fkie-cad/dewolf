#!/usr/bin/env python3
import json
import sys
from collections import defaultdict

def debug_recall(json_path):
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to load {json_path}: {e}")
        return

    print(f"--- Debugging Recall for {data.get('binary', json_path)} ---")

    undermerged_counts = {}

    for func_name, func_data in data.get("functions", {}).items():
        report = func_data.get("report") or {}
        variables = report.get("variables", [])
        
        # Check for completely empty variable lists
        if not variables:
            print(f"[!] {func_name}: 'variables' list is empty or missing. Recall is 0.")
            continue
            
        source_to_lifted = defaultdict(list)
        unmapped_sources = 0
        total_vars = len(variables)
        
        print(f"[-] {func_name} (Total variable entries: {total_vars}):")
        
        for v in variables:
            src = v.get("source", "UNKNOWN_SRC")
            lifted = v.get("variable")
            
            if src:
                if lifted:
                    source_to_lifted[src].append(lifted)
                else:
                    unmapped_sources += 1
            
        # Flag 1: Source variables with no lifted mapping
        if unmapped_sources > 0:
            print(f"    -> MISSING: {unmapped_sources} source variable(s) did not map to any lifted variable.")
            
        # Flag 2: Undermerging (dilutes the recall fraction)
        undermerged_sets_count = 0
        for src, lifted_list in source_to_lifted.items():
            unique_lifted = set(lifted_list)
            if len(unique_lifted) > 1:
                undermerged_sets_count += 1
                print(f"    -> UNDERMERGED: Source '{src}' maps to multiple lifted vars: {list(unique_lifted)}")

        if undermerged_sets_count > 0:
            undermerged_counts[func_name] = undermerged_sets_count

    # Print newline and sorted list of functions by undermerged sets (descending)
    print()
    print("--- Functions with Most Undermerged Sets (Descending) ---")
    sorted_undermerged = sorted(undermerged_counts.items(), key=lambda x: x[1], reverse=True)
    
    if sorted_undermerged:
        for func_name, count in sorted_undermerged:
            print(f"  {func_name}: {count} undermerged set(s)")
    else:
        print("  No undermerged sets found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debug_recall.py <path_to_json>")
    else:
        debug_recall(sys.argv[1])
