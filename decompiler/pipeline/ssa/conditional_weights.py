"""Module for the weights of the conditional out-of-SSA renaming, the linear model that scores variable pairs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union

from decompiler.pipeline.ssa.conditional_attribute_helper import Feature, FeatureVector

DEFAULT_WEIGHTS_FILE = Path(__file__).with_name("conditional_weights.json")


@dataclass(frozen=True)
class ConditionalWeights:
    """The model of the conditional out-of-SSA renaming, see from_file."""

    coefficients: Dict[Feature, float]
    intercept: float
    strategy: int  # how ConditionalVariableRenamer.create_variable_classes splits the dependency graph
    min_kept_score: Optional[float] = None

    def score(self, vector: FeatureVector) -> float:
        """The linear model applied to the feature vector: intercept + sum(coefficient * feature)."""
        return sum(self.coefficients[feature] * vector.get(feature, 0) for feature in Feature) + self.intercept

    @classmethod
    def from_file(cls, path: Union[str, Path, None] = None) -> ConditionalWeights:
        """
        Load the weights of the conditional out-of-SSA renaming from a JSON file.

        - None or "" -> the default file

        Format (a JSON object):
            - coefficients: the coefficient of each conditional_attribute_helper.Feature, keyed by its name
              (missing or unknown names raise a ValueError).
            - intercept: number.
            - strategy: how ConditionalVariableRenamer.create_variable_classes splits the dependency graph (0-4).
            - min_kept_score: lower bound for the scores of kept dependency-graph edges, or null (no lower bound).
        Other keys (e.g. description, trained) are documentation only and ignored.
        A file that cannot be read or does not have this format raises a ValueError.
        """
        path = Path(path) if path else DEFAULT_WEIGHTS_FILE
        try:
            with open(path) as file:
                return cls._from_data(json.load(file))
        except (OSError, KeyError, TypeError, ValueError) as error:  # json.JSONDecodeError is a ValueError
            raise ValueError(f"Conditional out-of-SSA weights file {path}: {type(error).__name__}: {error}") from error

    @classmethod
    def _from_data(cls, data: dict) -> ConditionalWeights:
        """Create the weights from the content of a weights file, see from_file."""
        names = set(data["coefficients"])
        expected_names = {feature.value for feature in Feature}
        if names != expected_names:
            raise ValueError(f"missing features {sorted(expected_names - names)}, unknown features {sorted(names - expected_names)}")
        min_kept_score = data.get("min_kept_score")
        return cls(
            coefficients={Feature(name): float(coefficient) for name, coefficient in data["coefficients"].items()},
            intercept=float(data["intercept"]),
            strategy=int(data["strategy"]),
            min_kept_score=None if min_kept_score is None else float(min_kept_score),
        )
