# LogWatch Threat Detector

LogWatch parses Linux SSH authentication logs and flags suspicious login behavior: brute-force attempts, invalid-user spraying, high-value account targeting, and successful login after repeated failures.

## Typical Workflow

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m logwatch.cli sample_logs/attack_auth.log
pytest
```

Reports are written to:

```text
artifacts/reports/report.json
artifacts/reports/report.html
```

## Example Output

```text
Summary: 7 findings, highest severity=critical, parsed events=15
```

## Screenshots

These screenshots are from the real CLI run, generated JSON/HTML reports, the running FastAPI Swagger UI, and a real `/analyze` upload response.

To reproduce the same views:

```bash
PYTHONPATH=src python -m logwatch.cli sample_logs/attack_auth.log
PYTHONPATH=src uvicorn logwatch.api.main:app --reload
curl -F "file=@sample_logs/attack_auth.log;type=text/plain" http://localhost:8000/analyze
```

Open `artifacts/reports/report.html`, `artifacts/reports/report.json`, and `http://localhost:8000/docs`.

![CLI analysis](docs/screenshots/cli-analysis.png)

![JSON report](docs/screenshots/json-report.png)

![HTML report](docs/screenshots/html-report.png)

![FastAPI docs](docs/screenshots/fastapi-docs.png)

![Upload response](docs/screenshots/upload-response.png)

## Detection Rules

| ID | Signal | Severity |
|---|---|---|
| `AUTH-001` | Many failed logins from one source within a short window | High |
| `AUTH-002` | Invalid-user enumeration from one source | Medium |
| `AUTH-003` | Successful login after repeated failures | Critical |
| `AUTH-004` | Targeting usernames such as `root`, `admin`, or `test` | Low |

## API

```bash
uvicorn logwatch.api.main:app --reload
```

Open `http://localhost:8000/docs`.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/analyze` | Upload an auth log and receive findings |

## Project Files

```text
src/logwatch/parsers/     SSH auth-log parsing
src/logwatch/detection/   rule engine
src/logwatch/reporting/   JSON and HTML writers
sample_logs/              clean and attack examples
tests/                    parser, analyzer, detection, API tests
```

Keywords: python, cybersecurity, log analysis, threat detection, ssh, fastapi, pytest
