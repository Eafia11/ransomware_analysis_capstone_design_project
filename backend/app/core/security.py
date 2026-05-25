from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException, UploadFile, status

from app.core.config import settings
from app.utils.file_utils import sanitize_filename
from app.utils.hash_utils import calculate_sha256


def validate_upload_file(file: UploadFile, content: bytes) -> None:
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File name is required.",
        )

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty files cannot be uploaded.",
        )

    if len(content) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Uploaded file is too large.",
        )

    extension = Path(file.filename).suffix.lower()
    if extension not in settings.allowed_upload_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type: {extension or 'no extension'}",
        )
