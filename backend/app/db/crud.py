from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import AnalysisRecord


def analysis_to_dict(record: AnalysisRecord) -> dict[str, Any]:
    return {
        "analysis_id": record.analysis_id,
        "filename": record.filename,
        "saved_path": record.saved_path,
        "sha256": record.sha256,
        "status": record.status,
        "result": record.result,
        "error": record.error,
    }


def create_analysis(db: Session, analysis: dict[str, Any]) -> dict[str, Any]:
    record = AnalysisRecord(
        analysis_id=analysis["analysis_id"],
        filename=analysis["filename"],
        saved_path=analysis["saved_path"],
        sha256=analysis["sha256"],
        status=analysis["status"],
        result=analysis.get("result"),
        error=analysis.get("error"),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return analysis_to_dict(record)


def get_analysis(db: Session, analysis_id: str) -> dict[str, Any] | None:
    record = db.get(AnalysisRecord, analysis_id)
    if record is None:
        return None
    return analysis_to_dict(record)


def update_analysis(db: Session, analysis_id: str, **updates: Any) -> dict[str, Any] | None:
    record = db.get(AnalysisRecord, analysis_id)
    if record is None:
        return None

    allowed_fields = {"filename", "saved_path", "sha256", "status", "result", "error"}
    for key, value in updates.items():
        if key in allowed_fields:
            setattr(record, key, value)

    db.commit()
    db.refresh(record)
    return analysis_to_dict(record)


def count_analyses(db: Session) -> int:
    return int(db.scalar(select(func.count()).select_from(AnalysisRecord)) or 0)
