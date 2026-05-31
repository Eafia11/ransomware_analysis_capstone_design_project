from __future__ import annotations

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)

from app.core.security import require_api_key
from app.models.schemas import SandboxSessionResponse
from app.services.sandbox_service import (
    SandboxBusyError,
    create_sandbox_session,
    load_sandbox_session,
    run_sandbox_session,
)

router = APIRouter(
    prefix="/sandbox",
    tags=["sandbox"],
    dependencies=[Depends(require_api_key)],
)


@router.post(
    "/run",
    response_model=SandboxSessionResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_sandbox(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    runtime_seconds: int | None = Form(default=None),
):
    content = await file.read()
    try:
        session = create_sandbox_session(
            filename=file.filename or "",
            content=content,
            runtime_seconds=runtime_seconds,
        )
    except SandboxBusyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    background_tasks.add_task(run_sandbox_session, session["session_id"])
    return session


@router.get("/status/{session_id}", response_model=SandboxSessionResponse)
def get_sandbox_status(session_id: str):
    session = load_sandbox_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Sandbox session was not found.")
    return session
