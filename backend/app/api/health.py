from fastapi import APIRouter

from app.core.config import settings
from app.models.schemas import HealthResponse
from app.services.storage import count_analyses

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health_check():
    return {
        "status": "ok",
        "service": settings.app_name,
        "stored_analyses": count_analyses(),
    }
