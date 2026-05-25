from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import pandas as pd

from preprocess import FEATURE_COLUMNS_PATH, LABEL_ENCODER_PATH
from train_xgboost import MODEL_PATH


def load_feature_columns(path: str | Path = FEATURE_COLUMNS_PATH) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def align_features(dataset: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    encoded = pd.get_dummies(dataset.fillna(0), dummy_na=False)
    return encoded.reindex(columns=feature_columns, fill_value=0)


def predict_csv(
    input_csv: str | Path,
    model_path: str | Path = MODEL_PATH,
) -> list[dict[str, object]]:
    try:
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise RuntimeError(
            "xgboost is not installed. Run `pip install -r backend/requirements.txt` first."
        ) from exc

    input_csv = Path(input_csv)
    model_path = Path(model_path)

    if not input_csv.exists():
        raise FileNotFoundError(f"input csv not found: {input_csv}")
    if not model_path.exists():
        raise FileNotFoundError(f"model file not found: {model_path}")

    dataset = pd.read_csv(input_csv)
    feature_columns = load_feature_columns()
    x = align_features(dataset, feature_columns)

    model = XGBClassifier()
    model.load_model(str(model_path))
    predictions = model.predict(x)
    probabilities = model.predict_proba(x) if hasattr(model, "predict_proba") else None

    labels = predictions
    if LABEL_ENCODER_PATH.exists():
        with open(LABEL_ENCODER_PATH, "rb") as f:
            label_encoder = pickle.load(f)
        labels = label_encoder.inverse_transform(predictions)

    results = []
    for index, label in enumerate(labels):
        confidence = None
        if probabilities is not None:
            confidence = float(max(probabilities[index]))
        results.append({
            "row": index,
            "label": str(label),
            "confidence": confidence,
        })

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run XGBoost inference on a CSV file.")
    parser.add_argument("input_csv")
    parser.add_argument("--model-path", default=str(MODEL_PATH))
    args = parser.parse_args()

    result = predict_csv(args.input_csv, model_path=args.model_path)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
