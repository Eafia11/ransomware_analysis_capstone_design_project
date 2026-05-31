from __future__ import annotations

import hmac
import ipaddress
from pathlib import Path

from fastapi import Header, HTTPException, Request, UploadFile, status

from app.core.config import settings


API_KEY_HEADER = "X-NetGuardian-Api-Key"


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


def require_api_key(
    x_netguardian_api_key: str | None = Header(default=None, alias=API_KEY_HEADER),
) -> None:
    configured_key = settings.api_key
    if not configured_key:
        return

    if not x_netguardian_api_key or not hmac.compare_digest(
        x_netguardian_api_key,
        configured_key,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid NetGuardian API key is required.",
        )


def require_internal_or_api_key(
    request: Request,
    x_netguardian_api_key: str | None = Header(default=None, alias=API_KEY_HEADER),
) -> None:
    if is_loopback_request(request):
        return
    require_api_key(x_netguardian_api_key)


def is_loopback_request(request: Request) -> bool:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    client_host = forwarded_for.split(",", 1)[0].strip()
    if not client_host and request.client:
        client_host = request.client.host

    if client_host in {"localhost", "testclient"}:
        return True

    try:
        return ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        return False
