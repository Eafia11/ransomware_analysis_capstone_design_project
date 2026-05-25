from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.health import router as health_router
from app.api.upload import router as upload_router
from app.api.result import router as result_router
from app.api.analyze import router as analyze_router
from app.core.config import settings
from app.core.logger import configure_logging
from app.db.session import init_db
from app.utils.file_utils import ensure_data_directories

configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_data_directories(
        settings.upload_dir,
        settings.parsed_dir,
        settings.normalized_dir,
        settings.analyzed_dir,
        settings.reports_dir,
    )
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

app.include_router(health_router)
app.include_router(upload_router)
app.include_router(result_router)
app.include_router(analyze_router)

@app.get("/")
def root():
    return {"message": "Backend running", "service": settings.app_name}
