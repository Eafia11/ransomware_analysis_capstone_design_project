from fastapi import APIRouter, HTTPException

from app.models.schemas import AnalyzeResponse
from app.services.report_service import analyze_winlogbeat_file
from app.services.storage import (
    get_analysis,
    set_analysis_result,
    set_analysis_status,
    update_analysis,
)

router = APIRouter()


@router.post("/analyze/{analysis_id}", response_model=AnalyzeResponse)
def analyze_file(analysis_id: str):
    item = get_analysis(analysis_id)

    if item is None:
        raise HTTPException(status_code=404, detail="Analysis ID was not found.")

    if item["status"] not in ["uploaded", "failed"]:
        return {
            "analysis_id": analysis_id,
            "status": item["status"],
            "message": "Analysis is already running or completed.",
            "result": item.get("result"),
        }

    set_analysis_status(analysis_id, "analyzing")

    try:
        result = analyze_winlogbeat_file(item["saved_path"], analysis_id=analysis_id)
    except Exception as exc:
        update_analysis(analysis_id, status="failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc

    updated = set_analysis_result(analysis_id, result)

    return {
        "analysis_id": analysis_id,
        "status": updated["status"] if updated else "completed",
        "message": "Analysis completed.",
        "result": result,
    }
