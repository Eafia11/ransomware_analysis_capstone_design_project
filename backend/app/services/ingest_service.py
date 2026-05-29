from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services.storage import create_analysis, get_analysis, update_analysis
from app.utils.file_utils import ensure_directory, sanitize_filename
from app.utils.hash_utils import calculate_file_sha256


def ingest_winlogbeat_event(
    event: dict[str, Any],
    stream_id: str | None = None,
    analysis_id: str | None = None,
) -> dict[str, Any]:
    source_host = _extract_source_host(event)
    resolved_stream_id = _normalize_stream_id(stream_id or source_host)
    resolved_analysis_id = analysis_id or _analysis_id_for_stream(resolved_stream_id)
    file_path = _stream_file_path(resolved_stream_id)

    _append_json_line(file_path, event)
    sha256 = calculate_file_sha256(file_path)
    event_count = _count_lines(file_path)
    filename = file_path.name

    existing = get_analysis(resolved_analysis_id)
    if existing is None:
        analysis = create_analysis({
            "analysis_id": resolved_analysis_id,
            "filename": filename,
            "saved_path": str(file_path),
            "sha256": sha256,
            "status": "uploaded",
        })
    else:
        status = existing["status"] if existing["status"] == "analyzing" else "uploaded"
        analysis = update_analysis(
            resolved_analysis_id,
            filename=filename,
            saved_path=str(file_path),
            sha256=sha256,
            status=status,
            result=None if status == "uploaded" else existing.get("result"),
            error=None,
        )

    return {
        "analysis_id": resolved_analysis_id,
        "stream_id": resolved_stream_id,
        "source_host": source_host,
        "filename": filename,
        "saved_path": str(file_path),
        "sha256": sha256,
        "status": analysis["status"] if analysis else "uploaded",
        "event_count": event_count,
    }


def _append_json_line(file_path: Path, event: dict[str, Any]) -> None:
    ensure_directory(file_path.parent)
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")))
        f.write("\n")


def _stream_file_path(stream_id: str) -> Path:
    return ensure_directory(settings.ingest_dir) / f"{stream_id}.jsonl"


def _normalize_stream_id(value: str | None) -> str:
    stream_id = sanitize_filename(value or "unknown-host").strip("._-")
    return stream_id[:80] or "unknown-host"


def _analysis_id_for_stream(stream_id: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"winlogbeat-stream:{stream_id}"))


def _extract_source_host(event: dict[str, Any]) -> str:
    candidates = [
        _safe_get(event, "host", "name"),
        _safe_get(event, "host", "hostname"),
        _safe_get(event, "winlog", "computer_name"),
        _safe_get(event, "agent", "name"),
        event.get("computer_name"),
        event.get("host_name"),
    ]

    for value in candidates:
        if value:
            return str(value)

    return "unknown-host"


def _safe_get(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def _count_lines(file_path: Path) -> int:
    with open(file_path, "r", encoding="utf-8") as f:
        return sum(1 for _ in f)
