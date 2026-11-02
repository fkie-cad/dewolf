"""The logistic-regression model: fitting, AUC, the ``params.json`` format and averaging.

``params.json`` has the same shape as the legacy ``koeffizienten.json``:
``{"intercept": float, "coef": {feature: float, ...}}`` (plus optional metadata keys).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np

from cvpipeline.features import FEATURES
from cvpipeline.storage import read_json, write_json_atomic


@dataclass
class Params:
    coef: Dict[str, float]
    intercept: float
    metadata: Dict[str, object] = field(default_factory=dict)

    def coefficients(self) -> List[float]:
        """Coefficients in FEATURES order, as ConditionalOutOfSSA expects them."""
        return [self.coef[name] for name in FEATURES]

    def to_json(self) -> dict:
        return {"intercept": self.intercept, "coef": dict(self.coef), **self.metadata}

    @classmethod
    def from_json(cls, data: dict) -> "Params":
        missing = [name for name in FEATURES if name not in data.get("coef", {})]
        if missing or "intercept" not in data:
            raise ValueError(f"not a params file: missing {missing or ['intercept']}")
        metadata = {key: value for key, value in data.items() if key not in ("intercept", "coef")}
        return cls(coef={name: float(data["coef"][name]) for name in FEATURES}, intercept=float(data["intercept"]), metadata=metadata)

    def save(self, path: str | Path) -> None:
        write_json_atomic(path, self.to_json())

    @classmethod
    def load(cls, path: str | Path) -> "Params":
        return cls.from_json(read_json(path))


def rows_to_arrays(rows: Iterable[Sequence[float]]) -> Tuple[np.ndarray, np.ndarray]:
    """Rows are [f_1, ..., f_n, goal] -> (X, y)."""
    data = np.asarray(list(rows), dtype=float)
    if data.size == 0:
        return np.empty((0, len(FEATURES))), np.empty(0)
    return data[:, : len(FEATURES)], data[:, len(FEATURES)]


def fit(X: np.ndarray, y: np.ndarray, C: float) -> Params:
    from sklearn.linear_model import LogisticRegression

    if len(np.unique(y)) < 2:
        raise ValueError(f"training data has only one class ({len(y)} rows); cannot fit")
    model = LogisticRegression(C=C, max_iter=1000)
    model.fit(X, y)
    return Params(coef=dict(zip(FEATURES, map(float, model.coef_[0]))), intercept=float(model.intercept_[0]))


def predict_proba(params: Params, X: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-(X @ np.asarray(params.coefficients()) + params.intercept)))


def auc(params: Params, X: np.ndarray, y: np.ndarray) -> float | None:
    """ROC-AUC on (X, y); None if y has a single class (AUC undefined)."""
    from sklearn.metrics import roc_auc_score

    if len(np.unique(y)) < 2:
        return None
    return float(roc_auc_score(y, predict_proba(params, X)))


def average(params_list: Sequence[Params]) -> Params:
    """Arithmetic mean of every coefficient and the intercept."""
    if not params_list:
        raise ValueError("no params to average")
    coef = {name: float(np.mean([p.coef[name] for p in params_list])) for name in FEATURES}
    intercept = float(np.mean([p.intercept for p in params_list]))
    return Params(coef=coef, intercept=intercept)


def mean_and_std(values: Sequence[float]) -> Tuple[float, float]:
    clean = [v for v in values if v is not None and not math.isnan(v)]
    if not clean:
        return float("nan"), float("nan")
    return float(np.mean(clean)), float(np.std(clean))
