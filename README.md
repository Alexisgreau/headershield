# headershield

Audit HTTP security headers for a list of URLs. Calculates a score, stores results in SQLite, provides a REST API, a small Tailwind UI, CLI, and CSV/PDF exports.

## Features
- Async scanning with httpx (retries, redirects)
- Score 0–100 with penalties/bonuses; centralized rules
- Findings with recommendations (Nginx/Apache snippets, CSP template)
- SQLite persistence via SQLModel
- REST API + Jinja2 pages (Tailwind via CDN)
- Exports: CSV and PDF (ReportLab)
- CLI via `python -m app.cli`
- Tests (pytest, respx), linters (ruff/black/mypy), pre-commit
- Dockerized; docker compose up exposes `http://localhost:8000`

## Quickstart

### Local (pip)
```
python -m venv .venv && . .venv/Scripts/activate  # or source .venv/bin/activate
pip install -e .[dev]
make dev
```
Open http://localhost:8000

### Docker
```
docker compose up -d --build
```

### CLI
```
python -m app.cli scan --urls https://example.com,https://owasp.org --output out.json
```

## Tests & Quality
```
pytest -q
make lint
make fmt
```

## Environment
- `HS_DB_PATH` (default: `./data/headershield.db`)
- Python 3.11

## Documentation
- See `docs/SECURITY_MODEL.md` for scoring details.

## Notes
- Tailwind loaded via CDN in templates (no local build step).
- PDF uses ReportLab to avoid heavy system deps.

