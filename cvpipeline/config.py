"""The run manifest ``<out>/run_config.json``.

It records every parameter that influences the cached results (blocks, params, per-split
evaluations) - not worker counts, timeouts or the baseline list (baselines can be added on a later
run; their results are independent of the splits). A rerun into an existing output folder must
use the same values, otherwise results from the old configuration would silently be mixed with
new ones, so the run aborts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from cvpipeline.storage import read_json, write_json_atomic

MANIFEST = "run_config.json"


class ConfigMismatch(RuntimeError):
    pass


@dataclass(frozen=True)
class RunConfig:
    projects_dir: str  # resolved absolute path
    k: int
    t: int
    seed: int
    C: float

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
