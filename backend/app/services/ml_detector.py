from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services.feature_extractor import ML_FEATURE_COLUMNS, features_to_vector


DEFAULT_MODEL_PATH = settings.xgboost_model_path


def is_ml_available() -> bool:
    try:
        import xgboost  # noqa: F401
    except ImportError:
        return False
    return True


def predict_chain_with_model(
    features: dict[str, Any],
    model_path: str | Path = DEFAULT_MODEL_PATH,
) -> dict[str, Any]:
    model_path = Path(model_path)
    vector = [features_to_vector(features)]

    if not model_path.exists():
        return {
            "enabled": False,
            "label": None,
            "confidence": None,
            "reason": f"model file not found: {model_path}",
        }

    try:
        from xgboost import XGBClassifier
    except ImportError:
        return {
            "enabled": False,
            "label": None,
            "confidence": None,
            "reason": "xgboost is not installed",
        }

    try:
        model = XGBClassifier()
        model.load_model(str(model_path))
        expected_feature_count = model.get_booster().num_features()
        actual_feature_count = len(vector[0])

        if expected_feature_count != actual_feature_count:
            return {
                "enabled": False,
                "label": None,
                "confidence": None,
                "reason": (
                    "model feature count does not match backend chain features: "
                    f"model expects {expected_feature_count}, backend provides {actual_feature_count}"
                ),
                "feature_columns": ML_FEATURE_COLUMNS,
            }

        prediction = int(model.predict(vector)[0])

        confidence = None
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(vector)[0]
            confidence = float(max(probabilities))
    except Exception as exc:
        try:
            prediction, confidence = _predict_with_booster(vector, model_path)
        except Exception as fallback_exc:
            return {
                "enabled": False,
                "label": None,
                "confidence": None,
                "reason": (
                    "model prediction failed: "
                    f"{fallback_exc}; classifier fallback was triggered by: {exc}"
                ),
                "feature_columns": ML_FEATURE_COLUMNS,
            }

    return {
        "enabled": True,
        "label": "suspicious" if prediction == 1 else "benign",
        "confidence": confidence,
        "feature_columns": ML_FEATURE_COLUMNS,
    }


def _predict_with_booster(vector: list[list[float]], model_path: Path) -> tuple[int, float | None]:
    import xgboost as xgb

    booster = xgb.Booster()
    booster.load_model(str(model_path))
    expected_feature_count = booster.num_features()
    actual_feature_count = len(vector[0])

    if expected_feature_count != actual_feature_count:
        raise ValueError(
            "model feature count does not match backend chain features: "
            f"model expects {expected_feature_count}, backend provides {actual_feature_count}"
        )

    probabilities = booster.predict(xgb.DMatrix(vector, feature_names=ML_FEATURE_COLUMNS))
    raw_prediction = probabilities[0]

    if hasattr(raw_prediction, "__len__"):
        values = [float(value) for value in raw_prediction]
        prediction = int(max(range(len(values)), key=values.__getitem__))
        confidence = max(values)
        return prediction, confidence

    probability = float(raw_prediction)
    prediction = 1 if probability >= 0.5 else 0
    confidence = max(probability, 1 - probability)
    return prediction, confidence


def predict_chains_with_model(
    rule_results: list[dict[str, Any]],
    model_path: str | Path = DEFAULT_MODEL_PATH,
) -> list[dict[str, Any]]:
    return [
        {
            **result,
            "ml_result": predict_chain_with_model(result.get("features", {}), model_path),
        }
        for result in rule_results
    ]


def train_xgboost_from_csv(
    csv_path: str | Path,
    label_column: str = "label",
    model_path: str | Path = DEFAULT_MODEL_PATH,
) -> dict[str, Any]:
    try:
        import pandas as pd
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, classification_report
        from xgboost import XGBClassifier
    except ImportError as exc:
        return {
            "trained": False,
            "reason": f"missing ML dependency: {exc.name}",
        }

    csv_path = Path(csv_path)
    model_path = Path(model_path)

    if not csv_path.exists():
        return {
            "trained": False,
            "reason": f"csv file not found: {csv_path}",
        }

    dataset = pd.read_csv(csv_path)
    missing_columns = [
        column
        for column in [*ML_FEATURE_COLUMNS, label_column]
        if column not in dataset.columns
    ]

    if missing_columns:
        return {
            "trained": False,
            "reason": "csv file is missing required columns",
            "missing_columns": missing_columns,
        }

    x = dataset[ML_FEATURE_COLUMNS]
    y = dataset[label_column].map(_normalize_label)

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.nunique() > 1 else None,
    )

    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
    )
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    accuracy = float(accuracy_score(y_test, predictions))

    model_path.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(model_path))

    return {
        "trained": True,
        "model_path": str(model_path),
        "rows": int(len(dataset)),
        "feature_columns": ML_FEATURE_COLUMNS,
        "label_column": label_column,
        "accuracy": accuracy,
        "classification_report": classification_report(y_test, predictions, output_dict=True),
    }


def _normalize_label(value: Any) -> int:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"suspicious", "malicious", "malware", "ransomware", "1", "true"}:
            return 1
        return 0

    return int(value)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the XGBoost ransomware detector.")
    parser.add_argument("csv_path", help="Path to the training CSV dataset.")
    parser.add_argument(
        "--label-column",
        default="label",
        help="Name of the target label column. Default: label",
    )
    parser.add_argument(
        "--model-path",
        default=str(DEFAULT_MODEL_PATH),
        help=f"Output model path. Default: {DEFAULT_MODEL_PATH}",
    )
    args = parser.parse_args()

    result = train_xgboost_from_csv(
        csv_path=args.csv_path,
        label_column=args.label_column,
        model_path=args.model_path,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))

    if not result.get("trained"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
