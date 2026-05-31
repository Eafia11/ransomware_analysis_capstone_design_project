from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request

from app.core.security import API_KEY_HEADER, require_api_key, require_internal_or_api_key
from app.models.schemas import IngestResponse
from app.services.ingest_service import ingest_winlogbeat_event

router = APIRouter()


@router.post("/ingest/winlogbeat", response_model=IngestResponse)
def ingest_winlogbeat(
    event: dict[str, Any] = Body(...),
    stream_id: str | None = Query(default=None),
    analysis_id: str | None = Query(default=None),
    _: None = Depends(require_api_key),
):
    return _ingest_event(event, stream_id=stream_id, analysis_id=analysis_id)


@router.post("/logs", response_model=IngestResponse)
def ingest_logstash_winlogbeat(
    request: Request,
    event: dict[str, Any] = Body(...),
    stream_id: str | None = Query(default=None),
    analysis_id: str | None = Query(default=None),
    x_netguardian_api_key: str | None = Header(default=None, alias=API_KEY_HEADER),
):
    require_internal_or_api_key(request, x_netguardian_api_key)
    return _ingest_event(event, stream_id=stream_id, analysis_id=analysis_id)


def _ingest_event(
    event: dict[str, Any],
    stream_id: str | None = None,
    analysis_id: str | None = None,
):
    if not event:
        raise HTTPException(status_code=400, detail="Event body cannot be empty.")

    return ingest_winlogbeat_event(
        event,
        stream_id=stream_id,
        analysis_id=analysis_id,
    )
