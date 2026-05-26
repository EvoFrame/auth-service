from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()


@app.get("/")
async def root():
    return JSONResponse({"message": "Auth Service is running"})


@app.get("/health")
async def health():
    return JSONResponse({"status": "healthy"})
