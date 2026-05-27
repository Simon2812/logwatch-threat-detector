"""Detection rules for brute force, spraying and suspicious login patterns."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta

from logwatch.models import AuthEvent, EventType, Finding, Severity


SUSPICIOUS_USERNAMES = {"admin", "administrator", "root", "test", "guest", "oracle", "postgres"}


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds that tune authentication anomaly detection sensitivity."""

    brute_force_threshold: int = 5
    brute_force_window_minutes: int = 10
    invalid_user_threshold: int = 3
    successful_after_failures_threshold: int = 3


def analyze_events(events: list[AuthEvent], config: DetectionConfig | None = None) -> list[Finding]:
    """Apply all configured authentication detection rules to parsed events."""
    config = config or DetectionConfig()
    findings: list[Finding] = []
    # Rules are independent and append evidence-rich findings; the final sort
    # puts the most urgent items first in JSON, HTML and API responses.
    findings.extend(_detect_brute_force_by_ip(events, config))
    findings.extend(_detect_invalid_user_spray(events, config))
    findings.extend(_detect_success_after_failures(events, config))
    findings.extend(_detect_suspicious_usernames(events))
    return sorted(findings, key=lambda finding: _severity_rank(finding.severity), reverse=True)


def _detect_brute_force_by_ip(events: list[AuthEvent], config: DetectionConfig) -> list[Finding]:
    findings: list[Finding] = []
    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.event_type in {EventType.FAILED_LOGIN, EventType.INVALID_USER} and event.source_ip:
            failures_by_ip[event.source_ip].append(event)

    window = timedelta(minutes=config.brute_force_window_minutes)
    for source_ip, failures in failures_by_ip.items():
        failures = sorted(failures, key=lambda item: item.timestamp)
        for index, first in enumerate(failures):
            # Sliding windows catch bursts that start at any failure, not only
            # at fixed clock boundaries such as 00, 10, 20 minutes.
            group = [
                event for event in failures[index:] if event.timestamp - first.timestamp <= window
            ]
            if len(group) >= config.brute_force_threshold:
                usernames = sorted({event.username for event in group if event.username})
                findings.append(
                    Finding(
                        rule_id="AUTH-001",
                        title="Possible SSH brute-force attack",
                        severity=Severity.HIGH,
                        description=(
                            f"{len(group)} failed authentication attempts from {source_ip} "
                            f"within {config.brute_force_window_minutes} minutes."
                        ),
                        source_ip=source_ip,
                        evidence=[event.raw for event in group[:8]],
                        event_count=len(group),
                        username=", ".join(usernames) if usernames else None,
                    )
                )
                # One brute-force finding per source IP keeps the report
                # concise while still showing representative raw evidence.
                break
    return findings


def _detect_invalid_user_spray(events: list[AuthEvent], config: DetectionConfig) -> list[Finding]:
    findings: list[Finding] = []
    invalid_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == EventType.INVALID_USER and event.source_ip:
            invalid_by_ip[event.source_ip].append(event)

    for source_ip, invalid_events in invalid_by_ip.items():
        unique_users = sorted({event.username for event in invalid_events if event.username})
        if len(unique_users) >= config.invalid_user_threshold:
            # Unique usernames matter more than raw count for spraying because
            # the signal is breadth across accounts from one source.
            findings.append(
                Finding(
                    rule_id="AUTH-002",
                    title="Username enumeration or password spraying",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{source_ip} attempted logins for {len(unique_users)} invalid usernames."
                    ),
                    source_ip=source_ip,
                    username=", ".join(unique_users),
                    evidence=[event.raw for event in invalid_events[:8]],
                    event_count=len(invalid_events),
                )
            )
    return findings


def _detect_success_after_failures(
    events: list[AuthEvent], config: DetectionConfig
) -> list[Finding]:
    findings: list[Finding] = []
    events_by_ip_user: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.source_ip and event.username:
            events_by_ip_user[(event.source_ip, event.username)].append(event)

    for (source_ip, username), grouped_events in events_by_ip_user.items():
        grouped_events = sorted(grouped_events, key=lambda item: item.timestamp)
        failures_before_success = 0
        evidence: list[str] = []
        for event in grouped_events:
            if event.event_type in {EventType.FAILED_LOGIN, EventType.INVALID_USER}:
                failures_before_success += 1
                evidence.append(event.raw)
            elif event.event_type == EventType.SUCCESSFUL_LOGIN:
                if failures_before_success >= config.successful_after_failures_threshold:
                    # Preserve the successful login with the preceding failure
                    # evidence so the finding is directly actionable.
                    evidence.append(event.raw)
                    findings.append(
                        Finding(
                            rule_id="AUTH-003",
                            title="Successful login after repeated failures",
                            severity=Severity.CRITICAL,
                            description=(
                                f"User {username} had {failures_before_success} failed attempts "
                                f"from {source_ip} before a successful login."
                            ),
                            source_ip=source_ip,
                            username=username,
                            evidence=evidence[-8:],
                            event_count=failures_before_success + 1,
                        )
                    )
                failures_before_success = 0
                evidence = []
    return findings


def _detect_suspicious_usernames(events: list[AuthEvent]) -> list[Finding]:
    suspicious = [
        event
        for event in events
        if event.username and event.username.lower() in SUSPICIOUS_USERNAMES
    ]
    by_username = Counter(event.username.lower() for event in suspicious if event.username)
    findings: list[Finding] = []
    for username, count in by_username.items():
        matching = [
            event for event in suspicious if event.username and event.username.lower() == username
        ]
        # This low-severity rule is intentionally broad; it is useful context
        # when paired with higher-severity brute-force or spray findings.
        findings.append(
            Finding(
                rule_id="AUTH-004",
                title="Suspicious high-value username targeted",
                severity=Severity.LOW,
                description=f"The username '{username}' appeared in {count} authentication events.",
                username=username,
                source_ip=", ".join(
                    sorted({event.source_ip for event in matching if event.source_ip})
                ),
                evidence=[event.raw for event in matching[:8]],
                event_count=count,
            )
        )
    return findings


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[severity]
