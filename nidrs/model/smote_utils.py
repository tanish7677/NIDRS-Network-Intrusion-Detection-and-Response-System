"""
NIDRS - SMOTE oversampling helper
=================================
SMOTE = Synthetic Minority Over-sampling Technique.

multiclass_model.py calls apply_smote() to balance the TRAINING data only
(the test split is never touched, so evaluation stays honest).

Backend order
-------------
1. imbalanced-learn's SMOTENC (preferred - `pip install imbalanced-learn`).
2. A built-in implementation of the same algorithm (numpy + scikit-learn
   only), used automatically when imbalanced-learn is not installed, so the
   model is ALWAYS trained with SMOTE-style balancing.

Both backends treat the three label-encoded categorical columns
(protocol_type, service, flag = columns 1, 2, 3) the SMOTE-NC way: a
synthetic row copies the most frequent category among the neighbours
instead of inventing a meaningless "in-between" category code.
"""

import numpy as np
import pandas as pd
from sklearn.neighbors import NearestNeighbors

CATEGORICAL_COLUMNS = [1, 2, 3]


def _builtin_smote(X, y, k_neighbors, random_state, categorical_columns):
    rng = np.random.default_rng(random_state)

    X = pd.DataFrame(X).reset_index(drop=True)
    y = pd.Series(y).reset_index(drop=True)

    columns = list(X.columns)
    cat_idx = [columns.index(c) for c in categorical_columns if c in columns]
    num_idx = [i for i in range(len(columns)) if i not in cat_idx]

    values = X.to_numpy(dtype=float)
    labels = y.to_numpy()

    counts = pd.Series(labels).value_counts()
    target = int(counts.max())

    new_rows = [values]
    new_labels = [labels]

    for cls, count in counts.items():

        n_needed = target - int(count)

        if n_needed <= 0:
            continue

        cls_values = values[labels == cls]

        # not enough samples to find neighbours -> plain duplication
        if len(cls_values) < 2:
            picks = rng.integers(0, len(cls_values), size=n_needed)
            new_rows.append(cls_values[picks])
            new_labels.append(np.full(n_needed, cls))
            continue

        k = min(k_neighbors, len(cls_values) - 1)

        # neighbours are searched on the numeric part only
        nn = NearestNeighbors(n_neighbors=k + 1).fit(cls_values[:, num_idx])
        neighbour_idx = nn.kneighbors(
            cls_values[:, num_idx], return_distance=False
        )[:, 1:]                                     # drop the point itself

        base = rng.integers(0, len(cls_values), size=n_needed)
        chosen = neighbour_idx[
            base, rng.integers(0, k, size=n_needed)
        ]
        gap = rng.random((n_needed, 1))

        synthetic = cls_values[base].copy()

        # numeric columns: interpolate between a sample and its neighbour
        synthetic[:, num_idx] = (
            cls_values[base][:, num_idx]
            + gap * (cls_values[chosen][:, num_idx]
                     - cls_values[base][:, num_idx])
        )

        # categorical columns: most frequent value among the k neighbours
        for c in cat_idx:
            neigh_vals = cls_values[neighbour_idx[base], c]
            for r in range(n_needed):
                vals, cnts = np.unique(neigh_vals[r], return_counts=True)
                synthetic[r, c] = vals[np.argmax(cnts)]

        new_rows.append(synthetic)
        new_labels.append(np.full(n_needed, cls))

    X_out = pd.DataFrame(np.vstack(new_rows), columns=columns)

    # keep integer-valued columns integer-valued
    for c in columns:
        if pd.api.types.is_integer_dtype(X[c]):
            X_out[c] = X_out[c].round().astype(X[c].dtype)

    y_out = pd.Series(np.concatenate(new_labels), name=y.name)

    return X_out, y_out


def apply_smote(X, y, k_neighbors=3, random_state=42,
                categorical_columns=CATEGORICAL_COLUMNS):
    """
    Returns (X_resampled, y_resampled, backend_name).
    """

    try:
        from imblearn.over_sampling import SMOTENC

        columns = list(pd.DataFrame(X).columns)
        positions = [columns.index(c) for c in categorical_columns]

        sampler = SMOTENC(
            categorical_features=positions,
            k_neighbors=k_neighbors,
            random_state=random_state
        )

        X_res, y_res = sampler.fit_resample(X, y)

        return X_res, y_res, "imbalanced-learn SMOTENC"

    except ImportError:

        X_res, y_res = _builtin_smote(
            X, y, k_neighbors, random_state, categorical_columns
        )

        return X_res, y_res, "built-in SMOTE (SMOTE-NC style)"
