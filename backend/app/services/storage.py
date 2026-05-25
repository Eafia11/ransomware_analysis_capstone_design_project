from __future__ import annotations

from typing import Any

from app.db import crud
from app.db.session import SessionLocal, init_db


def _run_with_db(operation, *args: Any, **kwargs: Any):
    init_db()
    db = SessionLocal()
    try:
        return operation(db, *args, **kwargs)
    finally:
        db.close()


def create_analysis(analysis: dict[str, Any]) -> dict[str, Any]:
    return _run_with_db(crud.create_analysis, analysis)


def get_analysis(analysis_id: str) -> dict[str, Any] | None:
    return _run_with_db(crud.get_analysis, analysis_id)


def update_analysis(analysis_id: str, **updates: Any) -> dict[str, Any] | None:
    return _run_with_db(crud.update_analysis, analysis_id, **updates)


def set_analysis_status(analysis_id: str, status: str) -> dict[str, Any] | None:
    return update_analysis(analysis_id, status=status)


def set_analysis_result(analysis_id: str, result: dict[str, Any]) -> dict[str, Any] | None:
    return update_analysis(analysis_id, status="completed", result=result, error=None)


def count_analyses() -> int:
    return _run_with_db(crud.count_analyses)
