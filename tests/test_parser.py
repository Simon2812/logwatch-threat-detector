"""Parser tests for representative OpenSSH log lines."""

from __future__ import annotations

from logwatch.models import EventType
from logwatch.parsers.ssh import parse_auth_line, parse_auth_log


def test_parse_failed_password_line():
    line = "May 21 02:13:42 web-01 sshd[2019]: Failed password for root from 203.0.113.50 port 41106 ssh2"

    event = parse_auth_line(line, year=2026)

    assert event is not None
    assert event.event_type == EventType.FAILED_LOGIN
    assert event.username == "root"
    assert event.source_ip == "203.0.113.50"
    assert event.service == "sshd"


def test_parse_auth_log_counts_lines_and_events():
    events, total_lines = parse_auth_log(
        __import__("pathlib").Path("tests/fixtures/mini_attack.log"), year=2026
    )

    assert total_lines == 9
    assert len(events) == 9
