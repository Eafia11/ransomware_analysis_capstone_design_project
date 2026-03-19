from fastapi import APIRouter, HTTPException
from app.services.storage import analysis_store

router = APIRouter()

@router.post("/analyze/{analysis_id}")
def analyze_file(analysis_id: str):
    item = analysis_store.get(analysis_id)

    if item is None:
        raise HTTPException(status_code=404, detail="해당 analysis_id를 찾을 수 없습니다.")

    if item["status"] not in ["uploaded", "failed"]:
        return {
            "analysis_id": analysis_id,
            "status": item["status"],
            "message": "이미 분석이 진행되었거나 완료되었습니다."
        }

    item["status"] = "analyzing"

    dummy_result = {
        "is_malware": True,
        "confidence": 0.91,
        "attack_chain": [
            "Initial Access",
            "Execution",
            "Defense Evasion",
            "Impact"
        ],
        "summary": "의심스러운 파일 실행 및 영향 행위가 탐지되었습니다.",
        "detected_events": [
            "Process Create",
            "File Write",
            "Registry Modification"
        ]
    }

    item["status"] = "completed"
    item["result"] = dummy_result

    return {
        "analysis_id": analysis_id,
        "status": item["status"],
        "message": "분석이 완료되었습니다.",
        "result": item["result"]
    }