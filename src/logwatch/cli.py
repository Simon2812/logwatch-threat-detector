"""Command-line interface for SSH log threat analysis."""

from __future__ import annotations

import argparse
from pathlib import Path

from logwatch.analyzer import analyze_log_file
from logwatch.detection import DetectionConfig
from logwatch.reporting import write_html_report, write_json_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze SSH/auth logs for suspicious login behavior."
    )
    # Threshold options make it possible to tune the detector for a quiet demo
    # log or for noisier production-style samples without code changes.
    parser.add_argument("log_file", type=Path, help="Path to an auth.log-style file")
    parser.add_argument("--json-out", type=Path, default=Path("artifacts/reports/report.json"))
    parser.add_argument("--html-out", type=Path, default=Path("artifacts/reports/report.html"))
    parser.add_argument("--brute-force-threshold", type=int, default=5)
    parser.add_argument("--brute-force-window-minutes", type=int, default=10)
    parser.add_argument("--invalid-user-threshold", type=int, default=3)
    parser.add_argument("--success-after-failures-threshold", type=int, default=3)
    parser.add_argument("--no-html", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = DetectionConfig(
        brute_force_threshold=args.brute_force_threshold,
        brute_force_window_minutes=args.brute_force_window_minutes,
        invalid_user_threshold=args.invalid_user_threshold,
        successful_after_failures_threshold=args.success_after_failures_threshold,
    )
    report = analyze_log_file(args.log_file, config=config)
    # Write machine-readable output first so automation can consume the result
    # even when HTML rendering is disabled.
    json_path = write_json_report(report, args.json_out)
    print(f"JSON report written to: {json_path}")
    if not args.no_html:
        html_path = write_html_report(report, args.html_out)
        print(f"HTML report written to: {html_path}")

    summary = report["summary"]
    print(
        "Summary: "
        f"{summary['findings_count']} findings, "
        f"highest severity={summary['highest_severity']}, "
        f"parsed events={summary['parsed_events']}"
    )


if __name__ == "__main__":
    main()
