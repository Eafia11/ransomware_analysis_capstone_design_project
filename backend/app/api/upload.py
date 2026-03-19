from fastapi import APIRouter, UploadFile, File, HTTPException
import uuid
import os
import hashlib

from app.services.storage import analysis_store

router = APIRouter()

UPLOAD_DIR = "samples"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="파일 이름이 없습니다.")

    analysis_id = str(uuid.uuid4())
    saved_name = f"{analysis_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, saved_name)

    content = await file.read()

    if not content:
        raise HTTPException(status_code=400, detail="빈 파일은 업로드할 수 없습니다.")

    with open(file_path, "wb") as f:
        f.write(content)

    sha256 = hashlib.sha256(content).hexdigest()

    analysis_store[analysis_id] = {
        "analysis_id": analysis_id,
        "filename": file.filename,
        "saved_path": file_path,
        "sha256": sha256,
        "status": "uploaded"
    }

    return analysis_store[analysis_id]