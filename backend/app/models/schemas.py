from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from app.models.result_model import AnalysisResult


class AnalysisStatus(str, Enum):
    uploaded = "uploaded"
    analyzing = "analyzing"
    completed = "completed"
    failed = "failed"


class SandboxStatus(str, Enum):
    queued = "queued"
    launching = "launching"
    waiting_for_ssh = "waiting_for_ssh"
    transferring = "transferring"
    running = "running"
    terminating = "terminating"
    analyzing_logs = "analyzing_logs"
    terminated = "terminated"
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


class IngestResponse(BaseModel):
    analysis_id: str
    stream_id: str
    source_host: str
    filename: str
    saved_path: str
    sha256: str
    status: AnalysisStatus
    event_count: int


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


class LlmReportResponse(BaseModel):
    analysis_id: str
    status: str
    provider: str
    model: str
    response_id: str | None = None
    report: str
    saved_path: str
    metadata_path: str


class SandboxSessionResponse(BaseModel):
    session_id: str
    status: SandboxStatus
    filename: str
    saved_path: str
    sha256: str
    runtime_seconds: int
    created_at: str
    updated_at: str
    instance_id: str | None = None
    public_ip: str | None = None
    private_ip: str | None = None
    remote_path: str | None = None
    execution_started_at: str | None = None
    scheduled_termination_at: str | None = None
    terminated_at: str | None = None
    error: str | None = None
    message: str | None = None
    analysis_id: str | None = None
    analysis_status: str | None = None
    analysis_result: AnalysisResult | None = None
    analysis_error: str | None = None
    ingested_stream_id: str | None = None
    ingested_log_path: str | None = None
    ingested_source_log_path: str | None = None
    ingested_source_offset: int | None = None
    ingested_event_count: int | None = None
