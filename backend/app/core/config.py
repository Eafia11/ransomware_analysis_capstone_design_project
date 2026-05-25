from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_MODEL_DIR = PROJECT_ROOT / "ml" / "models"


class Settings(BaseModel):
    app_name: str = "Ransomware Analysis Backend"
    app_version: str = "0.1.0"
    environment: str = "development"
    log_level: str = "INFO"
    data_dir: Path = DEFAULT_DATA_DIR
    upload_dir: Path = DEFAULT_DATA_DIR / "uploads"
    parsed_dir: Path = DEFAULT_DATA_DIR / "parsed"
    normalized_dir: Path = DEFAULT_DATA_DIR / "normalized"
    analyzed_dir: Path = DEFAULT_DATA_DIR / "analyzed"
    reports_dir: Path = DEFAULT_DATA_DIR / "reports"
    model_dir: Path = DEFAULT_MODEL_DIR
    xgboost_model_path: Path = DEFAULT_MODEL_DIR / "xgboost_model.json"
    database_url: str = f"sqlite:///{(DEFAULT_DATA_DIR / 'app.db').as_posix()}"
    max_upload_size_bytes: int = 50 * 1024 * 1024
    allowed_upload_extensions: set[str] = {".json", ".jsonl", ".log", ".txt"}


def _path_from_env(name: str, default: Path) -> Path:
    value = os.getenv(name)
    path = Path(value) if value else default
    return path if path.is_absolute() else PROJECT_ROOT / path


@lru_cache
def get_settings() -> Settings:
    data_dir = _path_from_env("DATA_DIR", DEFAULT_DATA_DIR)
    model_dir = _path_from_env("MODEL_DIR", DEFAULT_MODEL_DIR)

    return Settings(
        app_name=os.getenv("APP_NAME", Settings().app_name),
        app_version=os.getenv("APP_VERSION", Settings().app_version),
        environment=os.getenv("APP_ENV", Settings().environment),
        log_level=os.getenv("LOG_LEVEL", Settings().log_level),
        data_dir=data_dir,
        upload_dir=_path_from_env("UPLOAD_DIR", data_dir / "uploads"),
        parsed_dir=_path_from_env("PARSED_DIR", data_dir / "parsed"),
        normalized_dir=_path_from_env("NORMALIZED_DIR", data_dir / "normalized"),
        analyzed_dir=_path_from_env("ANALYZED_DIR", data_dir / "analyzed"),
        reports_dir=_path_from_env("REPORTS_DIR", data_dir / "reports"),
        model_dir=model_dir,
        xgboost_model_path=_path_from_env(
            "XGBOOST_MODEL_PATH",
            model_dir / "xgboost_model.json",
        ),
        database_url=os.getenv(
            "DATABASE_URL",
            f"sqlite:///{(data_dir / 'app.db').as_posix()}",
        ),
        max_upload_size_bytes=int(
            os.getenv("MAX_UPLOAD_SIZE_BYTES", str(Settings().max_upload_size_bytes))
        ),
    )


settings = get_settings()
