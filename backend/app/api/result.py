from fastapi import APIRouter, HTTPException

from app.models.schemas import AnalysisRecord
from app.services.storage import get_analysis

router = APIRouter()


@router.get("/result/{analysis_id}", response_model=AnalysisRecord)
def get_result(analysis_id: str):
    result = get_analysis(analysis_id)

    if result is None:
        raise HTTPException(status_code=404, detail="Analysis ID was not found.")

    return result
