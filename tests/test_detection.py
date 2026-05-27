"""Detection rule tests for suspicious authentication behavior."""

from __future__ import annotations

from pathlib import Path

from logwatch.detection import DetectionConfig, analyze_events
from logwatch.parsers.ssh import parse_auth_log


def test_detects_brute_force_and_success_after_failures():
    events, _ = parse_auth_log(Path("tests/fixtures/mini_attack.log"), year=2026)

    findings = analyze_events(
        events,
        DetectionConfig(
            brute_force_threshold=3,
            brute_force_window_minutes=10,
            invalid_user_threshold=3,
            successful_after_failures_threshold=3,
        ),
    )
    rule_ids = {finding.rule_id for finding in findings}

    assert "AUTH-001" in rule_ids
    assert "AUTH-002" in rule_ids
    assert "AUTH-003" in rule_ids
    assert "AUTH-004" in rule_ids
