from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.models.schemas import LlmReportResponse
from app.services.llm_report_service import LlmReportError, create_ai_analysis_report
from app.services.storage import get_analysis, update_analysis

router = APIRouter()


@router.post("/llm-report/{analysis_id}", response_model=LlmReportResponse)
def generate_llm_report(analysis_id: str):
    record = get_analysis(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis ID was not found.")

    if record["status"] != "completed" or not record.get("result"):
        raise HTTPException(
            status_code=409,
            detail="Analysis must be completed before generating an AI report.",
        )

    result = record["result"]
    try:
        report_response = create_ai_analysis_report(analysis_id, result)
    except LlmReportError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    updated_result = {
        **result,
        "ai_report": report_response["report"],
        "ai_report_metadata": {
            "provider": report_response["provider"],
            "model": report_response["model"],
            "response_id": report_response["response_id"],
            "saved_path": report_response["saved_path"],
            "metadata_path": report_response["metadata_path"],
        },
        "artifact_paths": {
            **result.get("artifact_paths", {}),
            "ai_report": report_response["saved_path"],
            "ai_report_metadata": report_response["metadata_path"],
        },
    }
    update_analysis(analysis_id, result=updated_result)

    return report_response
