from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.models.log_model import AbstractedAttackChain, AttackChain, ChainAction


class EventTypeSummary(BaseModel):
    total: int = 0
    by_channel: dict[str, int] = Field(default_factory=dict)
    by_provider: dict[str, int] = Field(default_factory=dict)
    by_event_id: dict[str, int] = Field(default_factory=dict)


class AnalysisSummary(BaseModel):
    parsed_events: int = 0
    sysmon_events: int = 0
    sysmon_core_events: int = 0
    attack_chains: int = 0
    suspicious_chains: int = 0
    risk_level: str | None = None
    ioc_counts: dict[str, int] = Field(default_factory=dict)
    events_by_type: EventTypeSummary | dict[str, Any] = Field(default_factory=dict)


class ChainFeatures(BaseModel):
    event_count: int = 0
    process_create_count: int = 0
    file_create_count: int = 0
    registry_modify_count: int = 0
    network_connect_count: int = 0
    uses_suspicious_process: int = 0
    uses_suspicious_command: int = 0
    has_multiple_behaviors: int = 0


class MitreTechnique(BaseModel):
    technique_id: str
    technique: str
    tactic: str
    evidence: list[str] = Field(default_factory=list)
    confidence: str | None = None


class MlDetectionResult(BaseModel):
    enabled: bool = False
    label: str | None = None
    confidence: float | None = None
    reason: str | None = None
    feature_columns: list[str] = Field(default_factory=list)


class RuleDetectionResult(BaseModel):
    process_guid: str | None = None
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    user: str | None = None
    start_time: str | None = None
    event_count: int | None = None
    features: ChainFeatures | dict[str, Any] = Field(default_factory=dict)
    indicators: dict[str, Any] = Field(default_factory=dict)
    score: int = 0
    label: str
    reasons: list[str] = Field(default_factory=list)
    actions: list[ChainAction] = Field(default_factory=list)
    mitre_attack: list[MitreTechnique] = Field(default_factory=list)
    ml_result: MlDetectionResult | dict[str, Any] | None = None


class AnalysisResult(BaseModel):
    summary: AnalysisSummary
    risk_level: str | None = None
    key_findings: list[str] = Field(default_factory=list)
    iocs: dict[str, list[str]] = Field(default_factory=dict)
    llm_report: dict[str, Any] = Field(default_factory=dict)
    ai_report: str | None = None
    ai_report_metadata: dict[str, Any] = Field(default_factory=dict)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    abstracted_attack_chains: list[AbstractedAttackChain] = Field(default_factory=list)
    rule_results: list[RuleDetectionResult] = Field(default_factory=list)
    suspicious_results: list[RuleDetectionResult] = Field(default_factory=list)
    artifact_paths: dict[str, str] = Field(default_factory=dict)
