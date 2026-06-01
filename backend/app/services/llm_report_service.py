from __future__ import annotations

import json
from typing import Any, Callable

from app.core.config import settings
from app.services.winlogbeat_parser import save_json
from app.utils.file_utils import ensure_directory


LLM_REPORT_INSTRUCTIONS = (
    "You are a ransomware incident report writer for a security capstone project. "
    "Write a concise Korean analysis report using only the supplied JSON evidence. "
    "Include summary, risk assessment, key evidence, MITRE ATT&CK interpretation, "
    "IOCs, possible false positives, and recommended response actions. "
    "Do not invent evidence that is not present in the JSON."
)


class LlmReportError(RuntimeError):
    """Raised when the external LLM report generation cannot be completed."""


def require_llm_input(result: dict[str, Any]) -> dict[str, Any]:
    llm_input = result.get("llm_report")
    if not isinstance(llm_input, dict) or not llm_input:
        raise LlmReportError("Analysis result does not contain llm_report input.")
    return llm_input


def create_ai_analysis_report(
    analysis_id: str,
    result: dict[str, Any],
    client_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    llm_input = require_llm_input(result)
    client = build_openai_client(client_factory)
    model = settings.llm_model
    response = client.responses.create(
        model=model,
        instructions=LLM_REPORT_INSTRUCTIONS,
        input=json.dumps(llm_input, ensure_ascii=False, indent=2),
    )

    report = getattr(response, "output_text", "") or ""
    if not report.strip():
        raise LlmReportError("LLM response did not include report text.")

    response_id = getattr(response, "id", None)
    paths = save_ai_report_artifacts(
        analysis_id=analysis_id,
        report=report,
        metadata={
            "analysis_id": analysis_id,
            "provider": "openai",
            "model": model,
            "response_id": response_id,
        },
    )

    return {
        "analysis_id": analysis_id,
        "status": "completed",
        "provider": "openai",
        "model": model,
        "response_id": response_id,
        "report": report,
        "saved_path": paths["report"],
        "metadata_path": paths["metadata"],
    }


def build_openai_client(client_factory: Callable[..., Any] | None = None) -> Any:
    if not settings.openai_api_key:
        raise LlmReportError("OPENAI_API_KEY is not configured.")

    if client_factory is not None:
        return client_factory(api_key=settings.openai_api_key)

    try:
        from openai import OpenAI
    except ImportError as exc:
        raise LlmReportError("openai package is required for AI report generation.") from exc

    return OpenAI(api_key=settings.openai_api_key)


def save_ai_report_artifacts(
    analysis_id: str,
    report: str,
    metadata: dict[str, Any],
) -> dict[str, str]:
    reports_dir = ensure_directory(settings.reports_dir)
    report_path = reports_dir / f"{analysis_id}_ai_report.md"
    metadata_path = reports_dir / f"{analysis_id}_ai_report_metadata.json"

    report_path.write_text(report, encoding="utf-8")
    save_json(metadata, metadata_path)

    return {
        "report": str(report_path),
        "metadata": str(metadata_path),
    }
