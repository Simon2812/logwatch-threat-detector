"""OpenSSH authentication log parser."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from logwatch.models import AuthEvent, EventType


SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>[\w/-]+)(?:\[(?P<pid>\d+)])?:\s+(?P<message>.*)$"
)
# Keep the parser narrow on purpose: these expressions target the OpenSSH
# messages used by the detector instead of trying to parse every syslog line.
FAILED_PASSWORD = re.compile(
    r"Failed password for (?:(?:invalid user )?(?P<user1>[\w.\-]+)|(?P<user2>\S+)) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
INVALID_USER = re.compile(r"Invalid user (?P<user>[\w.\-]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?P<user>[\w.\-]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_auth_log(path: Path, year: int | None = None) -> tuple[list[AuthEvent], int]:
    path = Path(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    return parse_auth_lines(lines, year=year)


def parse_auth_lines(lines: list[str], year: int | None = None) -> tuple[list[AuthEvent], int]:
    current_year = year or datetime.utcnow().year
    events: list[AuthEvent] = []
    for line in lines:
        # Non-authentication lines are ignored, but the total line count is
        # returned for the report so parsing coverage is visible.
        event = parse_auth_line(line, year=current_year)
        if event:
            events.append(event)
    return events, len(lines)


def parse_auth_line(line: str, year: int | None = None) -> AuthEvent | None:
    match = SYSLOG_PREFIX.match(line.strip())
    if not match:
        return None

    year = year or datetime.utcnow().year
    timestamp = datetime.strptime(
        f"{year} {match.group('month')} {match.group('day')} {match.group('time')}",
        "%Y %b %d %H:%M:%S",
    )
    service = match.group("service")
    message = match.group("message")

    # Check accepted logins first so the success-after-failures rule can link
    # a later success to earlier failures for the same user and source IP.
    accepted = ACCEPTED_PASSWORD.search(message)
    if accepted:
        return AuthEvent(
            timestamp=timestamp,
            event_type=EventType.SUCCESSFUL_LOGIN,
            username=accepted.group("user"),
            source_ip=accepted.group("ip"),
            service=service,
            raw=line,
        )

    invalid = INVALID_USER.search(message)
    if invalid:
        return AuthEvent(
            timestamp=timestamp,
            event_type=EventType.INVALID_USER,
            username=invalid.group("user"),
            source_ip=invalid.group("ip"),
            service=service,
            raw=line,
        )

    failed = FAILED_PASSWORD.search(message)
    if failed:
        return AuthEvent(
            timestamp=timestamp,
            event_type=EventType.FAILED_LOGIN,
            username=failed.group("user1") or failed.group("user2"),
            source_ip=failed.group("ip"),
            service=service,
            raw=line,
        )

    return None
