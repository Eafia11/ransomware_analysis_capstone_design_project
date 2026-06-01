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
    ingest_dir: Path = DEFAULT_DATA_DIR / "ingested"
    sandbox_upload_dir: Path = DEFAULT_DATA_DIR / "sandbox_uploads"
    sandbox_state_dir: Path = DEFAULT_DATA_DIR / "sandbox_sessions"
    parsed_dir: Path = DEFAULT_DATA_DIR / "parsed"
    normalized_dir: Path = DEFAULT_DATA_DIR / "normalized"
    analyzed_dir: Path = DEFAULT_DATA_DIR / "analyzed"
    reports_dir: Path = DEFAULT_DATA_DIR / "reports"
    model_dir: Path = DEFAULT_MODEL_DIR
    xgboost_model_path: Path = DEFAULT_MODEL_DIR / "xgboost_model.json"
    llm_model: str = "gpt-5.2"
    openai_api_key: str | None = None
    database_url: str = f"sqlite:///{(DEFAULT_DATA_DIR / 'app.db').as_posix()}"
    api_key: str | None = None
    max_upload_size_bytes: int = 50 * 1024 * 1024
    allowed_upload_extensions: set[str] = {".json", ".jsonl", ".log", ".txt"}
    aws_region: str = "ap-southeast-2"
    sandbox_windows_ami_id: str | None = None
    sandbox_windows_key_name: str | None = None
    sandbox_windows_subnet_id: str | None = None
    sandbox_windows_security_group_ids: list[str] = []
    sandbox_windows_instance_type: str = "t3.small"
    sandbox_windows_ssh_username: str = "Administrator"
    sandbox_windows_ssh_password: str | None = None
    sandbox_windows_ssh_key_path: Path | None = None
    sandbox_windows_remote_sample_dir: str = r"C:\NetGuardian\Samples"
    sandbox_runtime_seconds: int = 300
    sandbox_max_active_sessions: int = 1
    sandbox_ssh_wait_seconds: int = 900
    sandbox_log_wait_seconds: int = 60
    sandbox_log_poll_interval_seconds: int = 5
    sandbox_terminate_wait: bool = True


def _path_from_env(name: str, default: Path) -> Path:
    value = os.getenv(name)
    path = Path(value) if value else default
    return path if path.is_absolute() else PROJECT_ROOT / path


def _optional_path_from_env(name: str) -> Path | None:
    value = os.getenv(name)
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def _list_from_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def _bool_from_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
        ingest_dir=_path_from_env("INGEST_DIR", data_dir / "ingested"),
        sandbox_upload_dir=_path_from_env(
            "SANDBOX_UPLOAD_DIR",
            data_dir / "sandbox_uploads",
        ),
        sandbox_state_dir=_path_from_env(
            "SANDBOX_STATE_DIR",
            data_dir / "sandbox_sessions",
        ),
        parsed_dir=_path_from_env("PARSED_DIR", data_dir / "parsed"),
        normalized_dir=_path_from_env("NORMALIZED_DIR", data_dir / "normalized"),
        analyzed_dir=_path_from_env("ANALYZED_DIR", data_dir / "analyzed"),
        reports_dir=_path_from_env("REPORTS_DIR", data_dir / "reports"),
        model_dir=model_dir,
        xgboost_model_path=_path_from_env(
            "XGBOOST_MODEL_PATH",
            model_dir / "xgboost_model.json",
        ),
        llm_model=os.getenv("LLM_MODEL", Settings().llm_model),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        database_url=os.getenv(
            "DATABASE_URL",
            f"sqlite:///{(data_dir / 'app.db').as_posix()}",
        ),
        api_key=os.getenv("NETGUARDIAN_API_KEY") or os.getenv("NG_API_KEY"),
        max_upload_size_bytes=int(
            os.getenv("MAX_UPLOAD_SIZE_BYTES", str(Settings().max_upload_size_bytes))
        ),
        aws_region=os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", Settings().aws_region)),
        sandbox_windows_ami_id=os.getenv("NG_WINDOWS_AMI_ID"),
        sandbox_windows_key_name=os.getenv("NG_WINDOWS_KEY_NAME"),
        sandbox_windows_subnet_id=os.getenv("NG_WINDOWS_SUBNET_ID"),
        sandbox_windows_security_group_ids=_list_from_env("NG_WINDOWS_SECURITY_GROUP_IDS"),
        sandbox_windows_instance_type=os.getenv(
            "NG_WINDOWS_INSTANCE_TYPE",
            Settings().sandbox_windows_instance_type,
        ),
        sandbox_windows_ssh_username=os.getenv(
            "NG_WINDOWS_SSH_USERNAME",
            Settings().sandbox_windows_ssh_username,
        ),
        sandbox_windows_ssh_password=os.getenv("NG_WINDOWS_SSH_PASSWORD"),
        sandbox_windows_ssh_key_path=_optional_path_from_env("NG_WINDOWS_SSH_KEY_PATH"),
        sandbox_windows_remote_sample_dir=os.getenv(
            "NG_WINDOWS_REMOTE_SAMPLE_DIR",
            Settings().sandbox_windows_remote_sample_dir,
        ),
        sandbox_runtime_seconds=int(
            os.getenv("SANDBOX_RUNTIME_SECONDS", str(Settings().sandbox_runtime_seconds))
        ),
        sandbox_max_active_sessions=int(
            os.getenv(
                "SANDBOX_MAX_ACTIVE_SESSIONS",
                str(Settings().sandbox_max_active_sessions),
            )
        ),
        sandbox_ssh_wait_seconds=int(
            os.getenv("SANDBOX_SSH_WAIT_SECONDS", str(Settings().sandbox_ssh_wait_seconds))
        ),
        sandbox_log_wait_seconds=int(
            os.getenv("SANDBOX_LOG_WAIT_SECONDS", str(Settings().sandbox_log_wait_seconds))
        ),
        sandbox_log_poll_interval_seconds=int(
            os.getenv(
                "SANDBOX_LOG_POLL_INTERVAL_SECONDS",
                str(Settings().sandbox_log_poll_interval_seconds),
            )
        ),
        sandbox_terminate_wait=_bool_from_env(
            "SANDBOX_TERMINATE_WAIT",
            Settings().sandbox_terminate_wait,
        ),
    )


settings = get_settings()
