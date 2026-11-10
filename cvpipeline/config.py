"""The run manifest ``<out>/run_config.json``.

It records every parameter that influences the cached results (blocks, features, params, per-split
evaluations, conditional renaming strategy, function filter, pair weighting) - not worker counts, timeouts or the baseline list (baselines can be added on a later
run; their results are independent of the splits). A rerun into an existing output folder must
use the same values, otherwise results from the old configuration would silently be mixed with
new ones, so the run aborts.

The manifest guards the run's own parameters only. It carries no version of the code: after a
change to the pipeline or the decompiler, use a fresh output folder, as an existing one would
reuse what the old code cached.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from cvpipeline.storage import read_json, write_json_atomic

MANIFEST = "run_config.json"

# The pipeline's CFGs must not depend on debug symbols: Binary Ninja never imports the binaries' own
# DWARF into its analysis (fingerprinting for dedup, feature extraction and evaluation alike). DWARF
# is only read by decompiler/frontend/binaryninja/dwarf.py to label the lifted variables' origins.
#
# Every stage loads a binary on its own and must see the same code, so all of them load it with
# exactly these options (corpus.fingerprint_binary, decompilation.open_frontend):
# - maxFunctionAnalysisTime (ms): Binary Ninja's default of 20 s cuts the analysis of very large
#   functions off (luaV_execute needs about that long). A function cut off keeps the signature the
#   analysis had reached at that moment, which depends on the machine's load, and the IL of its
#   callers changes with it. With a generous limit such a function is analysed to the end.
# - maxFunctionSize (bytes): dewolf's default (binaryninja.max_function_size), so fingerprinting and
#   decompilation agree on which functions are too large to analyse.
BN_LOAD_OPTIONS = {
    "analysis.debugInfo.internal": False,
    "analysis.limits.maxFunctionAnalysisTime": 600_000,
    "analysis.limits.maxFunctionSize": 1_200_000,
}

# Variable-class strategy of ConditionalVariableRenamer used when evaluating the conditional mode
# (0-3: s-t-cut / LP based, 4: greedy merging; see its create_variable_classes).
CONDITIONAL_STRATEGIES = (0, 1, 2, 3, 4)
DEFAULT_CONDITIONAL_STRATEGY = 4

# Which functions contribute training rows (features.passes_filter), among those with labeled pairs:
#   none          every function
#   source-names  at least two distinct DWARF source variables among the labeled pairs
#   both-classes  at least one same-source and one different-source pair
FUNCTION_FILTERS = ("none", "source-names", "both-classes")
DEFAULT_FUNCTION_FILTER = "source-names"

# How the labeled rows are weighted when fitting (features.iter_training_rows):
#   edge  every distinct variable pair of a function weighs 1 in total (1/n for each of its n
#         occurrences), as the dependency graph has one edge per pair
#   row   every occurrence weighs 1
PAIR_WEIGHTINGS = ("edge", "row")
DEFAULT_PAIR_WEIGHTING = "edge"


class ConfigMismatch(RuntimeError):
    pass


@dataclass(frozen=True)
class RunConfig:
    projects_dir: str  # resolved absolute path
    k: int
    t: int
    seed: int
    C: float
    strategy: int = DEFAULT_CONDITIONAL_STRATEGY
    function_filter: str = DEFAULT_FUNCTION_FILTER
    pair_weighting: str = DEFAULT_PAIR_WEIGHTING

    def to_json(self) -> dict:
        return asdict(self)


def check_or_write(output_dir: Path, config: RunConfig) -> None:
    path = output_dir / MANIFEST
    if not path.exists():
        write_json_atomic(path, config.to_json())
        return
    previous = read_json(path)
    current = config.to_json()
    differences = {key: (previous.get(key), value) for key, value in current.items() if previous.get(key) != value}
    if differences:
        details = ", ".join(f"{key}: was {old!r}, now {new!r}" for key, (old, new) in differences.items())
        raise ConfigMismatch(
            f"{path} was written with different parameters ({details}). Use a new output folder or the original parameters."
        )
