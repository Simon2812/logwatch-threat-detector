"""Domain models used by the log threat detector."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class EventType(str, Enum):
    """Supported authentication event categories."""

    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    INVALID_USER = "invalid_user"
    OTHER = "other"


class Severity(str, Enum):
    """Ordered severity labels used to prioritize findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AuthEvent:
    """Normalized authentication event extracted from a raw log line."""

    timestamp: datetime
    event_type: EventType
    username: str | None
    source_ip: str | None
    service: str
    raw: str


@dataclass(frozen=True)
class Finding:
    """Security finding with severity, evidence and affected object context."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    source_ip: str | None = None
    username: str | None = None
    evidence: list[str] = field(default_factory=list)
    event_count: int = 0


@dataclass(frozen=True)
class AnalysisSummary:
    """Aggregate analysis statistics returned with generated threat reports."""

    analyzed_at: datetime
    total_lines: int
    parsed_events: int
    failed_logins: int
    successful_logins: int
    invalid_users: int
    findings_count: int
    highest_severity: Severity | None


def utc_now() -> datetime:
    """Return the current UTC timestamp for report metadata."""
    return datetime.now(timezone.utc)
