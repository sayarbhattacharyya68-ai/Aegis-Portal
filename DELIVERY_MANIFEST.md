# Aegis-Portal — Updated Project Delivery

## What was changed

### Updated existing files
- `main.py` — Gemini UI integration; local-first Oracle with explicit opt-in for derived features; explicit consent before sending payment screenshots; pending-only transaction submission; upload validation and normalization; admin unlock/lock flow; idle-session and sensitive-state cleanup; destructive-action confirmations.
- `ai_analyser.py` — official `google-genai` client; configurable Gemini text/vision model IDs; bounded retry handling; local password feature extraction; consented multimodal analysis; sanitized Warden inputs; locally validated advisory outputs and safe fallbacks.
- `database_logic.py` — preserved SQLite schema compatibility and existing Fernet/PBKDF2 encryption format; owner-scoped credential updates/deletes; login throttling; validated credit operations; atomic/idempotent transaction approval; screenshot retention cleanup including aged orphan uploads.
- `notifier.py` — updated provider-specific messages and event notifications.
- `requirements.txt` — removed Groq and constrained runtime/documentation/test dependencies; `google-genai>=2.0,<3.0`.
- `README.md` — updated setup, security limitations, Gemini configuration, and GitHub/Streamlit owner handover.
- `generate_interview_doc.py` — current Gemini architecture, privacy boundaries, and security limitations reflected in generated interview reference.
- `deploy_and_convert.py` — now performs document conversion only; no Git commit, push, or deployment behavior.
- `.gitignore` — excludes secrets, local vault databases, SQLite sidecars, payment assets, user uploads, virtual environments, caches, and build artifacts.
- `.streamlit/config.toml` — XSRF protection enabled; unsafe overrides removed.
- `.devcontainer/devcontainer.json` — uses Python 3.11 and a standard Streamlit launch command without disabling security protections.

### New files
- `.env.example` — placeholder-only local configuration template.
- `tests/test_ai_analyser.py` — Gemini privacy, output validation, and fallback tests.
- `tests/test_database_logic.py` — encrypted vault, ownership, transaction idempotency, and retention tests.
- `DELIVERY_MANIFEST.md` — this handover inventory.

### Intentionally unchanged
- `Aegis_Portal_IEEE_Paper.txt`
- `Aegis_Portal_IEEE_Paper.docx`

These two academic assets are preserved as a historical description of the original prototype. They include historical Groq-era architecture claims and must not be treated as current runtime documentation. `README.md` explicitly identifies this distinction.

## Security-sensitive files excluded from this delivery

The original `.env`, `vault.db`, private UPI QR image, `.git` history, virtual environment, Python caches, compiled files, and any uploaded payment screenshots are not included. Configure fresh secrets locally and use a copy of the original database only when testing an upgrade.

## Validation performed in the available environment

- `python -m compileall -q .` — passed.
- `python -m pytest -q` — **19 passed, 1 skipped**.
- The skipped authentication test requires `bcrypt`, which is not installed in the validation container.
- The container also does not have Streamlit or `google-genai` installed, and no live Gemini API request was made. Install the declared dependencies in a fresh Python 3.11 virtual environment before running the application.
- Tests use synthetic data and mocks; no real vault, API key, payment account, or payment screenshot was used.
- No Git commit, push, repository sync, or Streamlit deployment was performed.

## Required owner actions

1. Create a fresh `.venv`, install `requirements.txt`, and configure `.env` from `.env.example`.
2. Back up the existing `vault.db` outside the project before testing an upgrade. Never use the real database as a test fixture.
3. Add the private QR image and payment recipient settings locally only if Credit-Bay is needed.
4. Review `git status` and staged file lists before any GitHub push. Do not publish secrets, database files, private payment assets, screenshots, or old `.git` history.
5. Configure Streamlit Community Cloud secrets separately. Use persistent storage and backups before considering real-user deployment.