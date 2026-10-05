"""
Breakpoint API entrypoint.

    uvicorn app.main:app --reload     (from backend/)

Serves the dashboard's data API under /api and a health check at /. CORS is open
to the Vite dev server; in production the dashboard is served from the same origin.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router

app = FastAPI(title="Breakpoint", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def health() -> dict[str, str]:
    return {"service": "breakpoint", "status": "ok"}
