from fastapi import FastAPI
from app.api.upload import router as upload_router
from app.api.result import router as result_router
from app.api.analyze import router as analyze_router

app = FastAPI(title="Ransomware Analysis Backend")

app.include_router(upload_router)
app.include_router(result_router)
app.include_router(analyze_router)

@app.get("/")
def root():
    return {"message": "Backend running"}