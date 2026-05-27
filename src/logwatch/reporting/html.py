"""HTML report rendering for authentication threat findings."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template


HTML_TEMPLATE = Template(
    """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LogWatch Threat Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; color: #1f2937; background: #f8fafc; }
    h1, h2 { margin-bottom: 8px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin: 20px 0; }
    .metric { background: white; border: 1px solid #dbe3ef; border-radius: 8px; padding: 14px; }
    .metric span { display: block; color: #64748b; font-size: 13px; }
    .metric strong { display: block; font-size: 26px; margin-top: 4px; }
    .finding { background: white; border-left: 6px solid #64748b; border-radius: 8px; padding: 16px; margin: 16px 0; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.06); }
    .critical { border-left-color: #991b1b; }
    .high { border-left-color: #dc2626; }
    .medium { border-left-color: #d97706; }
    .low { border-left-color: #2563eb; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 12px; text-transform: uppercase; background: #e2e8f0; }
    pre { white-space: pre-wrap; background: #0f172a; color: #e2e8f0; border-radius: 6px; padding: 12px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>LogWatch Threat Report</h1>
  <p>Analyzed at {{ summary.analyzed_at }}</p>

  <section class="summary">
    <div class="metric"><span>Total lines</span><strong>{{ summary.total_lines }}</strong></div>
    <div class="metric"><span>Parsed events</span><strong>{{ summary.parsed_events }}</strong></div>
    <div class="metric"><span>Failed logins</span><strong>{{ summary.failed_logins }}</strong></div>
    <div class="metric"><span>Invalid users</span><strong>{{ summary.invalid_users }}</strong></div>
    <div class="metric"><span>Findings</span><strong>{{ summary.findings_count }}</strong></div>
    <div class="metric"><span>Highest severity</span><strong>{{ summary.highest_severity or "none" }}</strong></div>
  </section>

  <h2>Findings</h2>
  {% if findings %}
    {% for finding in findings %}
      <article class="finding {{ finding.severity }}">
        <span class="badge">{{ finding.severity }}</span>
        <h3>{{ finding.rule_id }} - {{ finding.title }}</h3>
        <p>{{ finding.description }}</p>
        <p><strong>Source IP:</strong> {{ finding.source_ip or "n/a" }}</p>
        <p><strong>Username:</strong> {{ finding.username or "n/a" }}</p>
        <p><strong>Events:</strong> {{ finding.event_count }}</p>
        {% if finding.evidence %}
          <h4>Evidence</h4>
          <pre>{% for line in finding.evidence %}{{ line }}
{% endfor %}</pre>
        {% endif %}
      </article>
    {% endfor %}
  {% else %}
    <p>No suspicious authentication behavior detected.</p>
  {% endif %}
</body>
</html>
"""
)


def write_html_report(report: dict, output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html = HTML_TEMPLATE.render(summary=report["summary"], findings=report["findings"])
    output_path.write_text(html, encoding="utf-8")
    return output_path
