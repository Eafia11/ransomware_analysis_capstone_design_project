from pathlib import Path

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
