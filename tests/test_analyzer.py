"""Analyzer integration tests for log threat reporting."""

from __future__ import annotations

from pathlib import Path

from logwatch.analyzer import analyze_log_file
from logwatch.reporting import write_html_report, write_json_report


def test_analyze_log_file_returns_summary_and_findings(tmp_path):
    report = analyze_log_file(Path("tests/fixtures/mini_attack.log"))

    assert report["summary"]["parsed_events"] == 9
    assert report["summary"]["findings_count"] > 0
    assert report["findings"]

    json_path = write_json_report(report, tmp_path / "report.json")
    html_path = write_html_report(report, tmp_path / "report.html")

    assert json_path.exists()
    assert html_path.exists()
    assert "LogWatch Threat Report" in html_path.read_text(encoding="utf-8")
