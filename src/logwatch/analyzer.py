"""High-level orchestration for parsing logs and writing threat reports."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from logwatch.detection import DetectionConfig, analyze_events
from logwatch.models import AnalysisSummary, EventType, Finding, Severity, utc_now
from logwatch.parsers import parse_auth_log


SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def analyze_log_file(path: Path, config: DetectionConfig | None = None) -> dict:
    events, total_lines = parse_auth_log(Path(path))
    findings = analyze_events(events, config=config)
    summary = _build_summary(events=events, total_lines=total_lines, findings=findings)
    # Return plain dictionaries at the boundary so CLI, report writers and the
    # API all serialize the same analysis result.
    return {
        "summary": _summary_to_dict(summary),
        "findings": [_finding_to_dict(finding) for finding in findings],
        "events": [
            {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type.value,
                "username": event.username,
                "source_ip": event.source_ip,
                "service": event.service,
                "raw": event.raw,
            }
            for event in events
        ],
    }


def _build_summary(
    *,
    events,
    total_lines: int,
    findings: list[Finding],
) -> AnalysisSummary:
    event_counts = Counter(event.event_type for event in events)
    highest = _highest_severity(findings)
    # Missing event types default to zero through Counter, which keeps the
    # summary stable for clean logs and sparse samples.
    return AnalysisSummary(
        analyzed_at=utc_now(),
        total_lines=total_lines,
        parsed_events=len(events),
        failed_logins=event_counts[EventType.FAILED_LOGIN],
        successful_logins=event_counts[EventType.SUCCESSFUL_LOGIN],
        invalid_users=event_counts[EventType.INVALID_USER],
        findings_count=len(findings),
        highest_severity=highest,
    )


def _highest_severity(findings: list[Finding]) -> Severity | None:
    if not findings:
        return None
    return max(findings, key=lambda finding: SEVERITY_ORDER.index(finding.severity)).severity


def _summary_to_dict(summary: AnalysisSummary) -> dict:
    return {
        "analyzed_at": summary.analyzed_at.isoformat(),
        "total_lines": summary.total_lines,
        "parsed_events": summary.parsed_events,
        "failed_logins": summary.failed_logins,
        "successful_logins": summary.successful_logins,
        "invalid_users": summary.invalid_users,
        "findings_count": summary.findings_count,
        "highest_severity": summary.highest_severity.value if summary.highest_severity else None,
    }


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "description": finding.description,
        "source_ip": finding.source_ip,
        "username": finding.username,
        "event_count": finding.event_count,
        "evidence": finding.evidence,
    }
