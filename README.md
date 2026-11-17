# Aegis-Portal

**Secure Password Manager and Security Intelligence Dashboard**  
Python 3.11 · Streamlit · SQLite · Fernet · bcrypt · Google Gemini

Aegis-Portal is an existing Streamlit credential-vault project with registration/login, an encrypted personal vault, an optional AI-assisted password explanation, a consent-gated payment screenshot review, an administrative console, and a local security-event ledger.

The project retains its dark navy / violet / mint visual identity. Its security model has been tightened without changing the existing Fernet/PBKDF2 ciphertext format or the SQLite table layout.

> **Important:** This is a student/research project, not a certified production password manager. Review the Security Notes below before storing real credentials or deploying it publicly.

## Features

- **Identity:** bcrypt password hashing, registration, login, status checks, and session idle timeout.
- **Archive Vault:** SQLite storage of Fernet-encrypted credential values. Account edits and deletes are scoped to the signed-in owner.
- **Aegis Oracle:** password-strength scoring runs locally. The raw password, its hash, and account identifiers are not sent to Gemini. A user may separately opt in to sending coarse, non-reversible strength characteristics for a text explanation.
- **Vision Sentinel:** image files are type-checked, decoded, dimension/size-limited, normalized, and stripped of EXIF metadata. Uploading a payment screenshot to Gemini requires explicit consent. The AI output is advisory only.
- **Shard Warden:** sends only allowlisted event types, severity values, and coarse recency to Gemini; it does not send user email addresses, IP addresses, or event descriptions. Its recommendations cannot execute admin operations.
- **Credit-Bay:** every submitted payment enters the `PENDING` administrator review queue. Credits are granted only by the administrator, and transaction approval is atomic and idempotent.
- **Admin Terminal:** administrator access is disabled unless `ADMIN_KEY` is configured. Destructive actions require explicit UI confirmation.
- **Retention:** uploaded payment screenshots are removed after the configured retention period (default 30 days), and their paths are cleared from the ledger. Screenshots are removed after an administrator approves or rejects a transaction.

## Project structure

```text
Aegis-Portal/
├── main.py                  # Streamlit UI and workflow orchestration
├── ai_analyser.py           # Gemini client, local Oracle, Sentinel, Warden
├── database_logic.py        # SQLite, bcrypt, Fernet vault and payment ledger
├── notifier.py              # Notifications and security-event display helpers
├── generate_interview_doc.py# Existing interview-reference PDF generator
├── deploy_and_convert.py    # Safe DOCX conversion only; no Git/deploy action
├── Aegis_Portal_IEEE_Paper.txt
├── Aegis_Portal_IEEE_Paper.docx
├── requirements.txt
├── .env.example
├── .gitignore
└── .streamlit/config.toml
```

The private payment QR image is intentionally not included. Add your own private QR image to the local project directory and configure `PAYMENT_QR_IMAGE` in `.env`. Do not commit it.

## Requirements

- Windows 10/11, macOS, or Linux
- Python **3.11** (recommended and used by the VS Code dev-container)
- Internet access for installing packages and Gemini API requests
- A Gemini API key for the Vision Sentinel and Warden. Oracle explanations use Gemini only when the user opts in; local Oracle scoring works without a key.

The supported text and vision model defaults are configured centrally in `ai_analyser.py` and can be overridden with `GEMINI_TEXT_MODEL` and `GEMINI_VISION_MODEL`. The project uses Google’s official `google-genai` SDK and constrains it to the 2.x line (`>=2.0,<3.0`) to avoid unreviewed major-version changes.

## Run locally in VS Code (Windows PowerShell)

1. Extract the project to a normal writable folder, for example `C:\Projects\Aegis-Portal`.
2. Open **that project folder** in VS Code (`File → Open Folder`). Do not open the ZIP file itself.
3. Open VS Code's integrated terminal and check Python:

   ```powershell
   py -3.11 --version
   ```

4. Create and activate a fresh virtual environment:

   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

   If PowerShell blocks activation, run this once in the current terminal and retry:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\.venv\Scripts\Activate.ps1
   ```

5. Create your local configuration file:

   ```powershell
   Copy-Item .env.example .env
   notepad .env
   ```

   Set `GEMINI_API_KEY` and generate a strong `ADMIN_KEY` locally:

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Copy the generated value into `.env`. Configure the private payment recipient and QR settings only if you intend to use Credit-Bay. Never paste actual keys into source code or commit `.env`.

6. Run the checks:

   ```powershell
   python -m compileall .
   python -m pytest -q
   ```

7. Start the app:

   ```powershell
   streamlit run main.py
   ```

   Open the local URL printed by Streamlit, normally `http://localhost:8501`.

8. Stop the server with `Ctrl+C`, then deactivate the environment:

   ```powershell
   deactivate
   ```

### Command Prompt alternative

```bat
py -3.11 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
copy .env.example .env
streamlit run main.py
```

## Configuration reference

| Setting | Purpose | Default |
|---|---|---|
| `GEMINI_API_KEY` | Google Gemini API credential | Required for online Gemini analysis; deterministic fallback remains available |
| `GEMINI_TEXT_MODEL` | Oracle explanation / Warden text model | `gemini-3.8-flash` |
| `GEMINI_VISION_MODEL` | Vision Sentinel multimodal model | `gemini-3.8-flash` |
| `ADMIN_KEY` | Administrator console credential | No default; admin disabled when absent |
| `PAYMENT_RECIPIENT_NAME` | Locally configured recipient name for comparison | Unset |
| `PAYMENT_RECIPIENT_VPA` | Locally configured recipient VPA for comparison | Unset |
| `PAYMENT_QR_IMAGE` | Path to private payment QR image | `my_upi_qr.jpeg` |
| `AEGIS_DB_PATH` | Optional SQLite path | Project folder `vault.db` |
| `AUDIT_UPLOAD_DIR` | Local payment screenshot directory | `audit_screenshots` |
| `SCREENSHOT_RETENTION_DAYS` | Screenshot retention window | `30` |

On Streamlit Community Cloud, configure values in **App → Settings → Secrets** (TOML format). For local development, configure them in `.env`. Never include real values in README files or source control.

## Database compatibility and backups

The current vault uses:

- bcrypt for login-password hashes;
- Fernet for authenticated encryption of stored credential values;
- PBKDF2-HMAC-SHA256 with the existing 100,000 iteration count and the original per-record salt interpretation;
- SQLite with write-ahead logging.

The implementation deliberately preserves the existing encryption derivation and ciphertext format. The app uses the original project-folder `vault.db` path by default, so an existing database should remain discoverable when the project is extracted into the expected folder. Before updating an existing installation, stop the app and make a separate backup of `vault.db`. Test upgrades against a copy first. Never use a real vault database as a test fixture.

## Security notes and limitations

1. **Not strict zero-knowledge:** Streamlit runs server-side Python. When a vault is unlocked, decrypted records and the active vault key exist in the current server-side session state. Do not describe this implementation as a strict zero-knowledge/client-side vault.
2. **Local password score is heuristic:** Password strength estimates are not a guarantee against cracking and are not a substitute for a reputable password manager's breach checks or a unique, long passphrase.
3. **Gemini is an external processor:** Oracle opt-in sends only coarse local features. Vision consent sends the normalized screenshot and expected amount to Google's Gemini API. Review Google's current privacy and retention terms before using real financial screenshots.
4. **AI is not an authority:** Sentinel and Warden outputs never approve payments, grant credits, lock users, ban users, or purge records. Humans must make administrative decisions.
5. **Admin access is a shared secret:** The current project uses one configured administrator key. For a public production service, replace this with individual administrator accounts, MFA, role-based authorization, secure session management, and audited credential rotation.
6. **Deployment storage:** Do not assume a hosted Streamlit filesystem is durable. SQLite files and uploaded screenshots require a persistent disk and a tested backup/restore strategy. Do not store production vaults in ephemeral hosting storage.
7. **Threat model review remains necessary:** This project has not undergone an independent penetration test, cryptographic audit, dependency audit, or load/concurrency certification.

## GitHub and Streamlit deployment handover

The application code can be hosted in a private GitHub repository and deployed through Streamlit Community Cloud, but publication is a separate owner-authorized action. Before pushing, inspect `git status`, confirm `.env`, `vault.db`, screenshots, QR/payment assets, `.venv`, and `.git` history are not being added, and rotate any credential that was previously included in an archive or repository.

Typical owner-run Git steps after reviewing the files:

```powershell
git status --short
git add main.py ai_analyser.py database_logic.py notifier.py requirements.txt README.md .env.example .gitignore .streamlit .devcontainer tests deploy_and_convert.py
git diff --cached --stat
git commit -m "Migrate Aegis-Portal AI agents to Gemini and harden workflows"
git push origin main
```

Do not commit the live database, secrets, uploaded screenshots, personal QR assets, local virtual environments, or historical Git objects that may contain secrets. For Streamlit Community Cloud, select the repository/branch, set `main.py` as the entry point, and configure secrets in the app dashboard. Test using a throwaway database before connecting any real payment workflow.

## Historical academic paper

`Aegis_Portal_IEEE_Paper.txt` and its DOCX counterpart are retained as the paper describing the original research implementation. They intentionally preserve historical references to the original Groq-based prototype. They are not the runtime architecture documentation for this updated Gemini codebase.

## Auxiliary scripts

- `python deploy_and_convert.py` regenerates the Word version of the academic paper from its text source. It does **not** commit, push, or deploy anything.
- `python generate_interview_doc.py` generates the existing interview-reference PDF (requires `fpdf2`).

---

**Aegis-Portal — PRJCS681**  
Developer: Sayar Bhattacharyya  
Computer Science Engineering · IEM, Kolkata