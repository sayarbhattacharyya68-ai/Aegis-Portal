<div align="center">

```
╔════════════════════════════════════════════════════════════════════════════════════════════╗
║   █████╗ ███████╗ ██████╗ ██╗███████╗    ██████╗  ██████╗ ██████╗ ████████╗ █████╗ ██╗     ║
║  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██║     ║
║  ███████║█████╗  ██║  ███╗██║███████╗    ██████╔╝██║   ██║██████╔╝   ██║   ███████║██║     ║
║  ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██║     ║
║  ██║  ██║███████╗╚██████╔╝██║███████║    ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗║
║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝║
║                                                                                            ║
║                   AUTONOMOUS CYBER-PHYSICAL RESILIENCE ECOSYSTEM                           ║
║                              Project Code: PRJCS681                                        ║
╚════════════════════════════════════════════════════════════════════════════════════════════╝
```

**A research-grade, AI-augmented credential vault and security intelligence platform**  
*Powered by Groq LPU™ · Zero-Knowledge Cryptography · Multi-Agent AI Core*

---

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.x-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-LPU%E2%84%A2-F55036?style=flat-square)
![SQLite](https://img.shields.io/badge/SQLite-WAL%20Mode-003B57?style=flat-square&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-Research%20Project-94FBAB?style=flat-square)

</div>

---

## What Is Aegis-Portal?

Aegis-Portal is a production-ready, research-driven **credential management and AI-driven security ecosystem**. Developed as **Innovative Project PRJCS681**, the platform transcends conventional password vaulting by fusing zero-knowledge cryptography, a custom Ether-Credit (EC) resource economy, a UPI-linked payment system, and a three-agent AI intelligence core — all unified under a high-end Glassmorphism command interface.

The system is built to answer a key research question: *Can AI inference be embedded directly into a security-critical credential management workflow to deliver real-time adversarial intelligence at sub-second latency?*

The answer is the **Multi-Agent Intelligence Core** — three autonomous AI agents, each with a distinct forensic role, each powered exclusively by Groq API for LPU-accelerated inference. This moves the platform from simple encrypted storage into a **Zero-Knowledge Architecture** with real-time adversarial auditing and behavioral threat monitoring.

---

## System Architecture & Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         USER / BROWSER                                  │
│                    (Web · Desktop · Streamlit Cloud)                     │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    main.py — UI ORCHESTRATOR                            │
│         Streamlit Command Center · Glassmorphism Design System          │
│    Auth Gate │ Dashboard │ Archive Vault │ Oracle │ Credit-Bay │ Admin  │
└──────┬───────────────────────┬───────────────────────┬──────────────────┘
       │                       │                       │
       ▼                       ▼                       ▼
┌─────────────┐    ┌───────────────────┐    ┌──────────────────────────┐
│ Archive     │    │  AI Oracle        │    │  Credit-Bay              │
│ Vault       │    │  Module           │    │  Module                  │
│ (AES/Fernet)│    │  (1 EC per audit) │    │  (UPI · Vision Verify)   │
└──────┬──────┘    └────────┬──────────┘    └─────────┬────────────────┘
       │                    │                          │
       └────────────────────┼──────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│             ai_analyser.py — MULTI-AGENT INTELLIGENCE CORE              │
│                    Groq API · Sub-second LPU Inference                  │
├───────────────────┬─────────────────────┬───────────────────────────────┤
│  AGENT 1          │  AGENT 2            │  AGENT 3                      │
│  The Aegis Oracle │  The Vision Sentinel│  The Shard Warden             │
│  🔮               │  👁️                  │  🛡️                           │
│  Llama-3.3-70B    │  Llama-3.2-90B-Vis  │  Llama-3.3-70B               │
│  Entropy Auditor  │  Transaction Verify │  Behavioral Monitor           │
└───────────────────┴─────────────────────┴───────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│           notifier.py — FORENSIC LOGGING & SIGNAL LAYER                 │
│    Toast Alerts · Security Events · Immersive Language · Severity Levels│
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│            database_logic.py — PERSISTENCE ENGINE                       │
│              AES-128-CBC (Fernet) · bcrypt · SQLite WAL                 │
├─────────────────┬──────────────┬─────────────────┬──────────────────────┤
│  users          │  accounts    │  transactions   │  security_events     │
│  (Identities)   │  (Shards)    │  (Ledger)       │  (Audit Trail)       │
└─────────────────┴──────────────┴─────────────────┴──────────────────────┘
                               │
                               ▼
                         vault.db  +  audit_screenshots/
```

### Workflow Overview

1. **User authenticates** — bcrypt-hashed credentials are verified. Status is checked (active / warned / lockdown / banned). A kill-switch immediately terminates Oracle and Vault access for banned identities.
2. **Vault operations** — Credential shards are encrypted in volatile session memory via AES-128-CBC (PBKDF2HMAC-derived key). The master key is *never* stored server-side. Decryption requires manual re-entry of the Shard Key.
3. **Oracle consultation** — The user submits a credential payload. One Ether-Credit is consumed. Agent 1 performs adversarial entropy analysis and returns a tactical grade in under a second via Groq LPU.
4. **Payment & top-up** — User pays via UPI, uploads a screenshot. Agent 2 forensically verifies the image. A human admin performs final sign-off. Credits are dispensed upon approval.
5. **Admin monitoring** — The Admin Terminal queries Agent 3 for behavioral threat assessments on any identity, reviews the full forensic audit trail, manages Identity statuses, and dispenses credits manually.
6. **Every action is logged** — All events are persisted to `security_events` with severity levels (INFO / WARNING / CRITICAL), building a complete forensic audit trail visible in the Admin Terminal.

---

## Core Feature Pillars

### 1. Zero-Knowledge Cryptographic Architecture

**Volatile Key Management** — The master encryption key is generated in volatile session memory (`st.session_state`) and destroyed instantly upon logout. No key ever touches persistent disk storage.

**Client-Side Decryption** — The Archive Vault strictly requires manual entry of a Secret Shard Key. Without this key, encrypted data is mathematically unrecoverable — even a full database leak reveals nothing.

**Global Kill-Switch** — Persistent status checks run on every request. If an administrator bans an identity, an instant kill-switch blocks all Oracle and Vault access for that active session without requiring re-login.

**BAN Protocol (Total Data Destruction)** — The `banned` status triggers complete removal of all associated rows across `accounts`, `transactions`, `security_events`, and `users` tables atomically.

---

### 2. Multi-Agent Intelligence Core (Powered by Groq LPU™)

Three autonomous agents, each logic-bound to a specific forensic role, all powered exclusively by Groq API for sub-second inference.

#### 🔮 Agent 1 — The Aegis Oracle
- **Model:** `llama-3.3-70b-versatile`
- **Role:** Adversarial entropy auditor for credential payloads
- **Unique Purpose:** When a credential is submitted for vaulting, the Oracle performs real-time entropy analysis — never echoing the password, but assessing character entropy, brute-force resistance, dictionary attack surface, and pattern signatures.
- **Output Format (strict):**
  - Tactical grade: `[FORTIFIED]` / `[COMPROMISED]` / `[CRITICAL]`
  - Three rapid-fire tactical opinions (max 8 words each), prefixed with `▸`
  - One-line `⚡ RECOMMENDATION`
- **Economy:** Costs 1 Ether-Credit per consultation
- **Temperature:** `0.3` for deterministic, authoritative tactical language

#### 👁️ Agent 2 — The Vision Sentinel
- **Model:** `llama-3.2-90b-vision-preview` (Groq Vision)
- **Role:** Forensic transaction verifier and UPI screenshot analyst
- **Unique Purpose:** Receives raw image bytes (base64-encoded) of a UPI payment screenshot and cross-references it against the expected INR amount and recipient VPA. It checks for transaction success status, amount match, recipient identity, UPI reference number visibility, and potential image manipulation artifacts.
- **Output Format (strict JSON):**
  - `verdict`: `VERIFIED` / `SUSPICIOUS` / `UNREADABLE` / `PENDING_ADMIN_REVIEW`
  - `confidence`: 0.0–1.0
  - `amount_detected`, `upi_ref`, `recipient_match`, `findings[]`
- **HITL Design:** Even a `VERIFIED` verdict requires final admin sign-off — a deliberate Human-in-the-Loop safeguard.
- **Only agent that processes binary image data.**

#### 🛡️ Agent 3 — The Shard Warden
- **Model:** `llama-3.3-70b-versatile`
- **Role:** Behavioral monitor, access control authority, and threat analyst
- **Unique Purpose:** Admins invoke the Warden to analyze any identity's last 20 forensic security events. It generates a behavioral threat assessment and recommends an action.
- **Output Format (strict JSON):**
  - `threat_level`: `NOMINAL` / `ELEVATED` / `CRITICAL`
  - `risk_score`: 0.0–10.0
  - `assessment`: paragraph-length tactical evaluation
  - `recommended_action`: `MONITOR` / `WARN` / `BAN` / `LOCKDOWN`
  - `indicators[]`: list of behavioral red flags
- **Passive Heartbeat:** `warden_heartbeat_check()` computes a system-wide security posture from the active/banned user ratio — purely in Python, with zero API calls.
- **Temperature:** `0.2` for maximum decisiveness in access control decisions.

---

### 3. Economy & Credit-Bay 2.0

**Calibrated Exchange Rate** — Fixed at ₹10 = 1 Ether-Credit (EC). The UI dynamically calculates gem yield as the user enters an amount.

**AI + HITL Payment Flow** — Users upload a UPI payment screenshot ("Transaction Shard"). The Vision Sentinel performs initial AI forensic verification, then the transaction is queued for final administrator sign-off before credits are dispensed.

**Admin Dispenser** — Administrators can manually grant any number of Ether-Credits to any identity, useful for research testing, bug bounties, or system rewards.

**Transaction Ledger** — All transactions (amount, timestamp, Vision Sentinel verdict, screenshot path, admin verification details) are persisted to the `transactions` table for full auditability.

---

### 4. Forensic Admin Terminal

**Live Presence Heartbeat** — Every user action triggers `update_heartbeat()`. The Admin Terminal shows 🟢 Online (active within 2 minutes) or ⚪ Offline status for each identity.

**Forensic Event Log** — The `security_events` table captures 18 distinct event types (AUTH_SUCCESS, VAULT_BREACH_ATTEMPT, LOCKDOWN_TRIGGERED, etc.) with three severity levels. The Admin Terminal provides filterable, paginated access to this full audit trail.

**Warden Threat Assessment** — Admins can invoke Agent 3 on-demand for any identity, receiving a risk score, threat level, and recommended action based on live behavioral data.

**Identity Management** — Admins can promote identities through four status states: `active` → `warned` → `lockdown` → `banned` (total purge), or restore them to `active` at any point.

**Dashboard Statistics** — `get_dashboard_stats()` aggregates total identities, active identities, total credential shards, threat event count, and pending transaction count for the Command Center overview.

---

### 5. UI/UX — Glassmorphism Command Center

**Aesthetic Identity** — Fully redesigned using a high-end Glassmorphism theme: frosted glass containers (`backdrop-filter: blur(12px)`), Z-axis depth shadows, and Mint-Teal interactive glows across the entire interface.

**Signature Palette** — Deep Indigo `#080D24` · Electric Violet `#7064DF` · Mint-Teal `#94FBAB` · Coral-Red `#FF6B6B` · Amber `#FFB347`

**Dynamic Mesh Gradients** — CSS-driven radial gradient backgrounds that shift with depth and position, creating a fluid ambient atmosphere.

**Immersive Language** — All standard UI copy is replaced with immersive cybersecurity phrasing (e.g., "Forge Shard", "Sever Connection", "Identity Synchronized", "Cipher Mismatch Detected").

**Typography** — JetBrains Mono for all input fields (communicating cryptographic precision), Inter for all UI copy.

---

## System Architecture — File Reference

```
📁 AEGIS_PORTAL
├── main.py                 ─── Primary UI Orchestrator & Command Center
├── database_logic.py       ─── SQL Logic, AES Encryption & Persistence Engine
├── ai_analyser.py          ─── Groq Multi-Agent Intelligence Core (3 Agents)
├── notifier.py             ─── Forensic Logging & Signal Layer
├── requirements.txt        ─── Python Dependency Manifest
├── my_upi_qr.jpeg          ─── Verified UPI Payment QR Code
├── vault.db                ─── Local Encrypted Database (⛔ DO NOT COMMIT)
└── audit_screenshots/      ─── Payment Verification Repository (⛔ DO NOT COMMIT)
```

### File-by-File Purpose

#### `main.py` — Primary UI Orchestrator
Entry point and top-level controller. Initializes page config, injects the complete Glassmorphism CSS design system, manages `st.session_state` for authenticated user, credits, decrypted shard cache, and admin flag. Orchestrates six UI surfaces: Auth Gate (Login/Register) → Command Center Dashboard → Archive Vault → AI Oracle → Credit-Bay → Admin Terminal. All cross-module imports flow through this file.

**Internal layout (numbered sections):**
`1. Core Config` → `2. Design System (CSS)` → `3. Session Init` → `4. Auth Gate` → `5. Dashboard` → `6. Lockdown Check` → `7. Sidebar Navigation` → `8. Archive Vault Module` → `9. AI Oracle Module` → `10. Credit-Bay Module` → `11. Admin Terminal`

#### `ai_analyser.py` — Multi-Agent Intelligence Core
Houses all three AI agents and their display helpers. A single `_get_groq_client()` factory handles API key resolution (Streamlit Secrets → `.env` fallback). Each agent section is fully self-contained: system prompt constant → inference function → response parser → display utility. All three agents return structured, parseable output (tactical text for Agent 1, JSON for Agents 2 and 3).

#### `database_logic.py` — Persistence & Encryption Engine
All SQL operations, zero-knowledge Fernet encryption, and the forensic audit trail. Uses a WAL-mode SQLite context manager with automatic rollback. `setup_security()` initializes all four tables with schema migration support (safe `ALTER TABLE` for new columns). Five logical groups: Identity Auth → Heartbeat/Presence → Vault Cryptography → EC Economy → Transaction Ledger → Security Event Logging.

**Key cryptographic function:** `get_fernet_key(user_key, email)` derives a 32-byte Fernet key via PBKDF2HMAC (SHA-256, 100k iterations, email as salt). The key exists only in volatile function scope.

#### `notifier.py` — Forensic Logging & Signal Layer
User-facing notifications with immersive cybersecurity language. Contains `EVENT_TYPES` (18 event codes with icons and severity labels) and `IMMERSIVE_MESSAGES` (35+ themed message strings). Provides `notify()`, `toast()`, `security_alert()`, `trigger_lockdown()`, and forensic display helpers (`format_event_for_display`, `get_severity_color`, `format_timestamp`) for the Admin Terminal event table.

#### `requirements.txt` — Dependency Manifest
Declares all seven production dependencies (see detailed breakdown below).

#### `my_upi_qr.jpeg`
The verified UPI QR code for `sayarbhattacharyya9@oksbi` displayed in the Credit-Bay module. Users scan this to make real INR payments; the Vision Sentinel then forensically verifies the resulting screenshot.

#### `vault.db` *(gitignored)*
The live SQLite database containing all encrypted credential shards, user identities, transaction records, and security events. Must never be committed to version control.

#### `audit_screenshots/` *(gitignored)*
Local repository for payment verification screenshots submitted through the Credit-Bay. These are referenced by path in the `transactions` table and reviewed during admin verification.

---

## Database Schema

Aegis-Portal maintains four SQL tables in `vault.db`:

```sql
-- Identity store (bcrypt-hashed passwords, EC balance, presence, status)
CREATE TABLE users (
    email          TEXT PRIMARY KEY,
    hashed_pw      TEXT NOT NULL,
    ether_credits  INTEGER DEFAULT 5,
    last_login     TEXT,
    last_seen      TEXT,
    status         TEXT DEFAULT 'active'   -- active | warned | lockdown | banned
);

-- Encrypted credential shards (AES-128-CBC via Fernet, per-user salt)
CREATE TABLE accounts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_email  TEXT NOT NULL REFERENCES users(email),
    site         TEXT NOT NULL,
    username     TEXT NOT NULL,
    password     TEXT NOT NULL   -- Fernet-encrypted ciphertext
);

-- Credit-Bay payment ledger (Vision Sentinel verdict + admin sign-off)
CREATE TABLE transactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email   TEXT NOT NULL REFERENCES users(email),
    amount       INTEGER NOT NULL,
    timestamp    TEXT NOT NULL,
    status       TEXT DEFAULT 'PENDING',   -- PENDING | VERIFIED | SUSPICIOUS | APPROVED | REJECTED
    image_path   TEXT,
    verified_by  TEXT,
    verified_at  TEXT
);

-- Forensic audit trail (all security events, 18 types, 3 severity levels)
CREATE TABLE security_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    target_email  TEXT,
    details       TEXT,
    severity      TEXT DEFAULT 'INFO',   -- INFO | WARNING | CRITICAL
    source_ip     TEXT
);
```

---

## Dependency Reference (`requirements.txt`)

| Package | Version | Role in Aegis-Portal |
|---|---|---|
| `streamlit` | Latest | The complete application framework. Provides the web server, reactive UI components (widgets, forms, layout), session state management, secrets handling, and the browser-rendered frontend. All six UI surfaces are built with Streamlit's Python API. |
| `pandas` | Latest | Powers the Admin Terminal's forensic event table and identity management grid. Used to construct DataFrame objects from raw SQLite query results for tabular display in the UI. |
| `python-dotenv` | Latest | Loads environment variables from a local `.env` file during development. Provides the fallback mechanism for `GROQ_API_KEY` and `ADMIN_KEY` when `st.secrets` is unavailable (i.e., local dev vs. Streamlit Cloud). |
| `cryptography` | Latest | The core encryption library. Provides `Fernet` (AES-128-CBC with HMAC-SHA256 authentication) for symmetric encryption of credential shards, and `PBKDF2HMAC` (SHA-256, 100,000 iterations) for deriving per-user Fernet keys from the master Shard Key — the foundation of the Zero-Knowledge architecture. |
| `bcrypt` | Latest | Handles all authentication password hashing. User passwords are hashed with `bcrypt.hashpw()` (auto-generates salt, adaptive cost factor) and verified with `bcrypt.checkpw()`. Raw passwords are never stored or logged anywhere in the system. |
| `groq` | Latest | The official Groq Python SDK. Used by `ai_analyser.py` to communicate with the Groq LPU inference API for all three agents — `llama-3.3-70b-versatile` (Agents 1 and 3) and `llama-3.2-90b-vision-preview` (Agent 2). Provides `client.chat.completions.create()` with full parameter control. |
| `Pillow` | Latest | Python Imaging Library used in the Credit-Bay module to process uploaded payment screenshots before passing image bytes to the Vision Sentinel. Handles image format normalization and byte-buffer extraction compatible with base64 encoding for the Groq Vision API. |

---

## Deployment Instructions (Streamlit Community Cloud)

**Step 1** — Fork or clone this repository.

**Step 2** — Deploy via [Streamlit Community Cloud](https://share.streamlit.io).

**Step 3 (CRITICAL)** — Configure secrets in the Streamlit Dashboard under **App Settings → Secrets**:

```toml
GROQ_API_KEY = "gsk_your_actual_groq_api_key_here"
ADMIN_KEY    = "######"
```

> ⚠️ **Important:** Do not use GitHub Repository Secrets. The application reads from `st.secrets` first, then falls back to a local `.env` file for development. GitHub Actions secrets are not accessible to the Streamlit runtime.

**Step 4** — The app auto-initializes `vault.db` on first run via `setup_security()`. No manual database setup required.

---

## Admin Reference

```
Admin Key:  [REDACTED]
Project ID: PRJCS681
```

Admin access is granted by entering the `ADMIN_KEY` from `st.secrets` in the Admin Terminal. Admin capabilities include: full forensic audit log access, Warden threat assessment invocation, identity status management (warn / lockdown / ban / restore), manual Ether-Credit dispensation, and transaction approval/rejection.

---

## Security Architecture Notes

**Zero-Knowledge Guarantee** — The server holds only Fernet-encrypted ciphertext. The PBKDF2-derived key is computed in volatile function scope and is never written to disk, logged, or stored in session state after encryption is complete. Decryption requires the user to re-enter their Shard Key manually every session.

**No Plaintext Credential Surface** — The Aegis Oracle's system prompt explicitly prohibits repeating credentials back in its response. The Vision Sentinel receives only base64-encoded image bytes, not raw payment details. The Shard Warden receives only sanitized event metadata.

**Forensic Completeness** — `log_security_event()` is called for every meaningful system action. It uses a bare `try/except` with silent failure to ensure logging never crashes the application — security events are best-effort but never blocking.

**Ban Protocol Atomicity** — The `banned` status executes cascading deletes across all four tables within a single SQLite transaction. The identity is completely expunged before the ban event is logged under the SYSTEM target.

---

## Security Disclaimer

Aegis-Portal was developed as a research project into Autonomous Cyber-Physical Resilience. It is intended for **educational and research presentation purposes**. Any attempt to manipulate the payment verification system, inject false transaction proofs, or bypass the encryption layer results in the immediate revocation of the offending Shard Identity.

The platform is not intended for production use to store credentials of critical personal or financial accounts.

---

<div align="center">

**Developer:** Sayar Bhattacharyya  
*Computer Science Engineering @ IEM, Kolkata*

*"Security is not a feature. It is an architecture."*

</div>
