from __future__ import annotations

import re
from pathlib import Path


SAFE_FILENAME_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def ensure_directory(path: str | Path) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def sanitize_filename(filename: str) -> str:
    name = Path(filename).name.strip()
    sanitized = SAFE_FILENAME_PATTERN.sub("_", name)
    return sanitized or "uploaded_file"


def build_unique_file_path(directory: str | Path, prefix: str, filename: str) -> Path:
    safe_filename = sanitize_filename(filename)
    return ensure_directory(directory) / f"{prefix}_{safe_filename}"


def save_bytes(file_path: str | Path, content: bytes) -> Path:
    path = Path(file_path)
    ensure_directory(path.parent)

    with open(path, "wb") as f:
        f.write(content)

    return path


def ensure_data_directories(*directories: str | Path) -> None:
    for directory in directories:
        ensure_directory(directory)
