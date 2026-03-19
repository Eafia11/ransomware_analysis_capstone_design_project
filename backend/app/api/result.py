from fastapi import APIRouter, HTTPException
from app.services.storage import analysis_store

router = APIRouter()

@router.get("/result/{analysis_id}")
def get_result(analysis_id: str):
    result = analysis_store.get(analysis_id)

    if result is None:
        raise HTTPException(status_code=404, detail="해당 analysis_id를 찾을 수 없습니다.")

    return result