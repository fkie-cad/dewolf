import hashlib
from typing import Iterable

from decompiler.pipeline.ssa.conditional_attribute_helper import TrainingRecord


def training_fingerprint(records: Iterable[TrainingRecord]) -> str:
    canonical = sorted((tuple(record.vector), record.training_goal) for record in records)
    return hashlib.sha256(repr(canonical).encode()).hexdigest()
