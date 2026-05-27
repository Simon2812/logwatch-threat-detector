"""HTTP API for uploading authentication logs and receiving findings."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

from logwatch.analyzer import analyze_log_file
from logwatch.detection import DetectionConfig


app = FastAPI(
    title="LogWatch Threat Detector",
    version="0.1.0",
    description="Upload SSH/auth logs and receive brute-force and suspicious-login findings.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> dict:
    # Restrict uploads to plain log-like content so binary files are rejected
    # before they reach the parser.
    if file.content_type not in {
        "text/plain",
        "application/octet-stream",
        "application/x-log",
        None,
    }:
        raise HTTPException(status_code=400, detail="Upload a plain text auth log file")

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        temp_file.write(await file.read())

    try:
        # Reuse the same analyzer as the CLI so API and command-line reports
        # stay consistent.
        return analyze_log_file(temp_path, config=DetectionConfig())
    finally:
        temp_path.unlink(missing_ok=True)
