from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from app.models.result_model import AnalysisResult


class AnalysisStatus(str, Enum):
    uploaded = "uploaded"
    analyzing = "analyzing"
    completed = "completed"
    failed = "failed"


class HealthResponse(BaseModel):
    status: str
    service: str
    stored_analyses: int


class UploadResponse(BaseModel):
    analysis_id: str
    filename: str
    saved_path: str
    sha256: str
    status: AnalysisStatus


class AnalysisRecord(BaseModel):
    analysis_id: str
    filename: str
    saved_path: str
    sha256: str
    status: AnalysisStatus
    result: AnalysisResult | None = None
    error: str | None = None


class AnalyzeResponse(BaseModel):
    analysis_id: str
    status: AnalysisStatus
    message: str
    result: AnalysisResult | None = None
