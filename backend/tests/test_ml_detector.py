from pathlib import Path
import sys
from types import SimpleNamespace

from app.services.ml_detector import predict_chain_with_model, train_xgboost_from_csv


def test_predict_chain_returns_disabled_when_model_file_is_missing(tmp_path):
    missing_model = tmp_path / "missing_model.json"

    result = predict_chain_with_model({}, model_path=missing_model)

    assert result["enabled"] is False
    assert result["label"] is None
    assert "model file not found" in result["reason"]


def test_train_xgboost_from_csv_reports_missing_file(tmp_path):
    result = train_xgboost_from_csv(Path(tmp_path) / "missing.csv")

    assert result["trained"] is False
    assert (
        "csv file not found" in result["reason"]
        or "missing ML dependency" in result["reason"]
    )


def test_predict_chain_returns_disabled_when_classifier_and_booster_fail(tmp_path, monkeypatch):
    class BrokenClassifier:
        def load_model(self, model_path):
            raise RuntimeError("classifier load failed")

    def broken_booster(vector, model_path):
        raise RuntimeError("booster load failed")

    model_path = tmp_path / "broken_model.json"
    model_path.write_text("not a valid model", encoding="utf-8")

    monkeypatch.setitem(sys.modules, "xgboost", SimpleNamespace(XGBClassifier=BrokenClassifier))
    monkeypatch.setattr("app.services.ml_detector._predict_with_booster", broken_booster)

    result = predict_chain_with_model({}, model_path=model_path)

    assert result["enabled"] is False
    assert result["label"] is None
    assert "model prediction failed" in result["reason"]
