"""Module for the weights of the conditional out-of-SSA renaming, the linear model that scores variable pairs."""

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
    def from_file(cls, path: Union[str, Path, None] = None) -> "ConditionalWeights":
        """
        Load the weights of the conditional out-of-SSA renaming from a JSON file.

        - None or "" -> the default file

        Format (a JSON object):
            - features: the names of conditional_attribute_helper.Feature, each exactly once (in any order),
              otherwise a ValueError is raised.
            - coefficients: one number per feature, in the order of features.
            - intercept: number.
            - strategy: how ConditionalVariableRenamer.create_variable_classes splits the dependency graph (0-4).
            - min_kept_score: lower bound for the scores of kept dependency-graph edges, or null (no lower bound).
        Other keys (e.g. description, trained) are documentation only and ignored.
        """
        path = Path(path) if path else DEFAULT_WEIGHTS_FILE
        with open(path) as file:
            data = json.load(file)
        names = list(data.get("features", ()))
        expected_names = [feature.value for feature in Feature]
        if sorted(names) != sorted(expected_names):
            raise ValueError(f"Conditional out-of-SSA weights file {path}: features {names} do not match {expected_names}")
        if len(data["coefficients"]) != len(names):
            raise ValueError(
                f"Conditional out-of-SSA weights file {path}: expected {len(names)} coefficients, got {len(data['coefficients'])}"
            )
        coefficients = {Feature(name): float(coefficient) for name, coefficient in zip(names, data["coefficients"])}
        min_kept_score = data.get("min_kept_score")
        return cls(
            coefficients=coefficients,
            intercept=float(data["intercept"]),
            strategy=int(data["strategy"]),
            min_kept_score=None if min_kept_score is None else float(min_kept_score),
        )
