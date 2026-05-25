from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay, classification_report

from preprocess import LABEL_ENCODER_PATH, TEST_PATH
from train_xgboost import MODEL_PATH


ML_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = ML_ROOT / "reports"
CLASSIFICATION_REPORT_PATH = REPORTS_DIR / "classification_report.txt"
CONFUSION_MATRIX_PATH = REPORTS_DIR / "confusion_matrix.png"
FEATURE_IMPORTANCE_PATH = REPORTS_DIR / "feature_importance.png"


def evaluate_model(
    model_path: str | Path = MODEL_PATH,
    test_path: str | Path = TEST_PATH,
) -> dict[str, str]:
    try:
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise RuntimeError(
            "xgboost is not installed. Run `pip install -r backend/requirements.txt` first."
        ) from exc

    model_path = Path(model_path)
    test_path = Path(test_path)

    if not model_path.exists():
        raise FileNotFoundError(f"model file not found: {model_path}")
    if not test_path.exists():
        raise FileNotFoundError(f"test file not found: {test_path}")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    test = pd.read_csv(test_path)
    x_test = test.drop(columns=["label"])
    y_test = test["label"]

    model = XGBClassifier()
    model.load_model(str(model_path))
    predictions = model.predict(x_test)

    target_names = None
    if LABEL_ENCODER_PATH.exists():
        with open(LABEL_ENCODER_PATH, "rb") as f:
            label_encoder = pickle.load(f)
        target_names = [str(label) for label in label_encoder.classes_]

    report_text = classification_report(
        y_test,
        predictions,
        target_names=target_names,
        zero_division=0,
    )
    CLASSIFICATION_REPORT_PATH.write_text(report_text, encoding="utf-8")

    ConfusionMatrixDisplay.from_predictions(
        y_test,
        predictions,
        display_labels=target_names,
        xticks_rotation=45,
    )
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PATH)
    plt.close()

    importance = pd.Series(model.feature_importances_, index=x_test.columns)
    importance.sort_values(ascending=False).head(20).plot(kind="barh")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(FEATURE_IMPORTANCE_PATH)
    plt.close()

    return {
        "classification_report": str(CLASSIFICATION_REPORT_PATH),
        "confusion_matrix": str(CONFUSION_MATRIX_PATH),
        "feature_importance": str(FEATURE_IMPORTANCE_PATH),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate trained XGBoost model.")
    parser.add_argument("--model-path", default=str(MODEL_PATH))
    parser.add_argument("--test-path", default=str(TEST_PATH))
    args = parser.parse_args()

    result = evaluate_model(model_path=args.model_path, test_path=args.test_path)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
