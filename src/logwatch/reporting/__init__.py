"""Report writer exports for log threat findings."""

from logwatch.reporting.html import write_html_report
from logwatch.reporting.json_report import write_json_report

__all__ = ["write_html_report", "write_json_report"]
