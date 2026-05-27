"""API tests for authentication log uploads."""

from __future__ import annotations

from fastapi.testclient import TestClient

from logwatch.api.main import app


def test_health_endpoint():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_upload_endpoint():
    client = TestClient(app)
    log_content = b"May 21 02:13:42 web-01 sshd[2019]: Failed password for root from 203.0.113.50 port 41106 ssh2\n"

    response = client.post(
        "/analyze",
        files={"file": ("auth.log", log_content, "text/plain")},
    )

    assert response.status_code == 200
    assert response.json()["summary"]["parsed_events"] == 1
