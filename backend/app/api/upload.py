import uuid

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.config import settings
from app.core.security import validate_upload_file
from app.models.schemas import UploadResponse
from app.services.storage import create_analysis
from app.utils.file_utils import build_unique_file_path, ensure_directory, save_bytes
from app.utils.hash_utils import calculate_sha256

router = APIRouter()

ensure_directory(settings.upload_dir)


@router.post("/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="File name is required.")

    content = await file.read()
    validate_upload_file(file, content)

    analysis_id = str(uuid.uuid4())
    file_path = build_unique_file_path(settings.upload_dir, analysis_id, file.filename)
    save_bytes(file_path, content)

    analysis = create_analysis({
        "analysis_id": analysis_id,
        "filename": file.filename,
        "saved_path": str(file_path),
        "sha256": calculate_sha256(content),
        "status": "uploaded",
    })

    return analysis
