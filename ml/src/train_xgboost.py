from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from preprocess import (
    FEATURE_COLUMNS_PATH,
    MODELS_DIR,
    RAW_DATA_PATH,
    TEST_PATH,
    TRAIN_PATH,
    preprocess_dataset,
)


MODEL_PATH = MODELS_DIR / "xgboost_model.json"


def train_xgboost(
    train_path: str | Path = TRAIN_PATH,
    test_path: str | Path = TEST_PATH,
    model_path: str | Path = MODEL_PATH,
    force_preprocess: bool = False,
    raw_log_path: str | Path | None = RAW_DATA_PATH,
    label_column: str | None = None,
) -> dict[str, str | int | float | list[str]]:
    train_path = Path(train_path)
    test_path = Path(test_path)
    model_path = Path(model_path)

    if force_preprocess or not train_path.exists() or not test_path.exists():
        preprocess_dataset(csv_path=raw_log_path, label_column=label_column)

    try:
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise RuntimeError(
            "xgboost is not installed. Run `pip install -r backend/requirements.txt` first."
        ) from exc

    train = pd.read_csv(train_path)
    test = pd.read_csv(test_path)

    if "label" not in train.columns or "label" not in test.columns:
        raise ValueError("processed train/test files must contain a label column")

    x_train = train.drop(columns=["label"])
    y_train = train["label"]
    x_test = test.drop(columns=["label"])
    y_test = test["label"]

    model = XGBClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="logloss",
        random_state=42,
    )
    model.fit(x_train, y_train)

    accuracy = float(model.score(x_test, y_test))
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(model_path))

    with open(FEATURE_COLUMNS_PATH, "r", encoding="utf-8") as f:
        feature_columns = json.load(f)

    return {
        "model_path": str(model_path),
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
        "feature_count": len(feature_columns),
        "accuracy": accuracy,
        "feature_columns": feature_columns,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train dynamic XGBoost ransomware model.")
    parser.add_argument(
        "--log-path",
        default=str(RAW_DATA_PATH),
        help="Winlogbeat JSON/JSONL file used to build chain features.",
    )
    parser.add_argument(
        "--csv-path",
        default=None,
        help="Backward-compatible alias for --log-path.",
    )
    parser.add_argument("--label-column", default=None)
    parser.add_argument("--model-path", default=str(MODEL_PATH))
    parser.add_argument("--preprocess", action="store_true")
    args = parser.parse_args()
    raw_log_path = args.csv_path or args.log_path

    result = train_xgboost(
        model_path=args.model_path,
        force_preprocess=args.preprocess,
        raw_log_path=raw_log_path,
        label_column=args.label_column,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
