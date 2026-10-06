"""
Breakpoint API entrypoint.

    uvicorn app.main:app --reload --port 8008     (from backend/; 8008 avoids ORAI on 8000)

Serves the dashboard's data API under /api and a health check at /. CORS is open
to the Vite dev server; in production the dashboard is served from the same origin.
"""
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router

app = FastAPI(title="Breakpoint", version="0.1.0")

# Dev defaults to the Vite origin; set BREAKPOINT_CORS (comma-separated) in prod,
# e.g. the Render static-site URL.
_origins = os.environ.get(
    "BREAKPOINT_CORS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def health() -> dict[str, str]:
    return {"service": "breakpoint", "status": "ok"}
