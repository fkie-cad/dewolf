"""The run manifest ``<out>/run_config.json``.

It records every parameter that influences the cached results (blocks, params, per-split
evaluations, conditional renaming strategy) - not worker counts, timeouts or the baseline list (baselines can be added on a later
run; their results are independent of the splits). A rerun into an existing output folder must
use the same values, otherwise results from the old configuration would silently be mixed with
new ones, so the run aborts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from cvpipeline.storage import read_json, write_json_atomic

MANIFEST = "run_config.json"

# The pipeline's CFGs must not depend on debug symbols: Binary Ninja never imports the binaries' own
# DWARF into its analysis (fingerprinting for dedup, feature extraction and evaluation alike). DWARF
# is only read by decompiler/frontend/binaryninja/dwarf.py to label the lifted variables' origins.
BN_LOAD_OPTIONS = {"analysis.debugInfo.internal": False}

# How the ground-truth labels are produced; recorded in the manifest so results built with older
# labels (or with Binary Ninja's debug-info import) are never mixed with new ones. Bump the version
# when the DWARF matching changes.
GROUND_TRUTH = "dwarf-v2-nodebuginfo"

# Variable-class strategy of ConditionalVariableRenamer used when evaluating the conditional mode
# (0-3: s-t-cut / LP based, 4: greedy merging; see its create_variable_classes).
CONDITIONAL_STRATEGIES = (0, 1, 2, 3, 4)
DEFAULT_CONDITIONAL_STRATEGY = 4


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
    ground_truth: str = GROUND_TRUTH

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
