from __future__ import annotations

import hashlib
from pathlib import Path


def calculate_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def calculate_file_sha256(file_path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)

    return digest.hexdigest()
