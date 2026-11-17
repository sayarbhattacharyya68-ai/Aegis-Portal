"""
Aegis-Portal Interview Document Generator
Generates a comprehensive PDF covering tools, workflow, LLMs, and project purpose.
"""

from fpdf import FPDF
import os

class AegisPDF(FPDF):
    """Custom PDF class with headers, footers, and styling helpers."""

    # ── colour palette (R, G, B) ──
    DARK_BG      = (8, 13, 36)
    INDIGO       = (40, 30, 90)
    VIOLET       = (112, 100, 223)
    MINT         = (148, 251, 171)
    WHITE        = (255, 255, 255)
    LIGHT_GRAY   = (220, 220, 230)
    MID_GRAY     = (160, 160, 175)
    TABLE_HEAD   = (30, 25, 70)
    TABLE_ROW_1  = (18, 20, 50)
    TABLE_ROW_2  = (24, 26, 58)
    CORAL        = (255, 107, 107)
    AMBER        = (255, 179, 71)
    LINK_BLUE    = (100, 160, 255)

    def __init__(self):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(15, 15, 15)

    # ── header / footer ──
    def header(self):
        if self.page_no() == 1:
            return  # title page has its own header
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*self.MID_GRAY)
        self.cell(0, 6, "Aegis-Portal  |  Interview Reference Document  |  PRJCS681", align="C")
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*self.MID_GRAY)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    # ── helper: section title ──
    def section_title(self, number, title):
        self.ln(4)
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*self.VIOLET)
        self.cell(0, 10, f"{number}  {title}", new_x="LMARGIN", new_y="NEXT")
        # underline
        self.set_draw_color(*self.VIOLET)
        self.set_line_width(0.6)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(5)

    # ── helper: sub-section title ──
    def sub_title(self, title):
        self.ln(3)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*self.MINT)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    # ── helper: body text ──
    def body(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 60)
        self.multi_cell(0, 5.5, text)
        self.ln(2)

    # ── helper: bold body text ──
    def body_bold(self, text):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(50, 50, 60)
        self.multi_cell(0, 5.5, text)
        self.ln(1)

    # ── helper: bullet point ──
    def bullet(self, text, indent=8):
        x = self.get_x()
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 60)
        self.cell(indent)
        self.set_font("Helvetica", "B", 10)
        self.cell(5, 5.5, "-")  # ASCII-safe bullet
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 5.5, f"  {text}")
        self.ln(1)

    # ── helper: numbered step ──
    def step(self, number, title, description):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*self.VIOLET)
        self.cell(8, 6, f"{number}.")
        self.set_text_color(40, 40, 55)
        self.cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(60, 60, 70)
        self.set_x(self.l_margin + 8)
        self.multi_cell(self.w - self.l_margin - self.r_margin - 8, 5.5, description)
        self.ln(3)

    # ── helper: draw a table ──
    def draw_table(self, headers, rows, col_widths=None):
        avail = self.w - self.l_margin - self.r_margin
        if col_widths is None:
            col_widths = [avail / len(headers)] * len(headers)

        # header row
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(*self.TABLE_HEAD)
        self.set_text_color(*self.WHITE)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 8, f" {h}", border=1, fill=True)
        self.ln()

        # data rows
        self.set_font("Helvetica", "", 8.5)
        for row_idx, row in enumerate(rows):
            fill_c = self.TABLE_ROW_1 if row_idx % 2 == 0 else self.TABLE_ROW_2
            # calculate row height
            max_lines = 1
            for i, cell_text in enumerate(row):
                # estimate lines needed
                text_w = col_widths[i] - 2
                str_w = self.get_string_width(cell_text)
                lines = max(1, int(str_w / text_w) + 1)
                max_lines = max(max_lines, lines)
            row_h = max(8, max_lines * 5)

            # check for page break
            if self.get_y() + row_h > self.h - 25:
                self.add_page()
                # re-draw header
                self.set_font("Helvetica", "B", 9)
                self.set_fill_color(*self.TABLE_HEAD)
                self.set_text_color(*self.WHITE)
                for i, h in enumerate(headers):
                    self.cell(col_widths[i], 8, f" {h}", border=1, fill=True)
                self.ln()
                self.set_font("Helvetica", "", 8.5)

            x_start = self.get_x()
            y_start = self.get_y()
            for i, cell_text in enumerate(row):
                self.set_xy(x_start + sum(col_widths[:i]), y_start)
                self.set_fill_color(245, 245, 252)
                self.set_text_color(40, 40, 55)
                # Draw cell background
                self.rect(x_start + sum(col_widths[:i]), y_start, col_widths[i], row_h, "D")
                self.set_xy(x_start + sum(col_widths[:i]) + 1, y_start + 1)
                self.multi_cell(col_widths[i] - 2, 5, cell_text)
            self.set_xy(x_start, y_start + row_h)
        self.ln(4)

    # ── helper: quote / callout box ──
    def callout(self, text):
        self.set_fill_color(235, 240, 255)
        self.set_draw_color(*self.VIOLET)
        x = self.get_x()
        y = self.get_y()
        w = self.w - self.l_margin - self.r_margin
        self.set_font("Helvetica", "I", 10)
        self.set_text_color(60, 50, 100)
        # calc height
        self.set_xy(x + 6, y + 3)
        self.multi_cell(w - 12, 5.5, text)
        h = self.get_y() - y + 3
        # draw box behind (draw after is fine for border)
        self.set_xy(x, y)
        self.rect(x, y, w, h, "D")
        # left accent bar
        self.set_fill_color(*self.VIOLET)
        self.rect(x, y, 2, h, "F")
        self.set_xy(x, y + h + 2)
        self.ln(3)


def build_pdf():
    pdf = AegisPDF()
    pdf.alias_nb_pages()

    # ════════════════════════════════════════════════════════
    #  TITLE PAGE
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.ln(40)
    pdf.set_font("Helvetica", "B", 30)
    pdf.set_text_color(*AegisPDF.VIOLET)
    pdf.cell(0, 14, "AEGIS-PORTAL", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(80, 80, 100)
    pdf.cell(0, 8, "Autonomous Cyber-Physical Resilience Ecosystem", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, "Project Code: PRJCS681", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)

    # decorative line
    pdf.set_draw_color(*AegisPDF.VIOLET)
    pdf.set_line_width(1)
    mid = pdf.w / 2
    pdf.line(mid - 40, pdf.get_y(), mid + 40, pdf.get_y())
    pdf.ln(10)

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(100, 100, 120)
    pdf.cell(0, 7, "Interview Reference Document", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "Tools, Workflow, LLM Roles & Project Purpose", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(20)

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(80, 80, 100)
    pdf.cell(0, 7, "Developer: Sayar Bhattacharyya", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "Computer Science Engineering | IEM, Kolkata", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(*AegisPDF.MID_GRAY)
    pdf.cell(0, 7, "Powered by Google Gemini  |  Encrypted Vault Storage  |  Multi-Agent AI Core", align="C", new_x="LMARGIN", new_y="NEXT")

    # ════════════════════════════════════════════════════════
    #  TABLE OF CONTENTS
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*AegisPDF.VIOLET)
    pdf.cell(0, 12, "Table of Contents", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    toc_items = [
        ("1", "Project Purpose & Core Objectives"),
        ("2", "Core Development Stack (Tools & Libraries)"),
        ("3", "Process / Workflow Overview"),
        ("4", "Gemini Models & Their Exact Roles"),
        ("5", "System Architecture Diagram"),
        ("6", "File-by-File Reference"),
        ("7", "Database Schema"),
        ("8", "Dependency Reference"),
        ("9", "Security Architecture Notes"),
        ("10", "TL;DR for the Interview"),
    ]
    for num, title in toc_items:
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(*AegisPDF.VIOLET)
        pdf.cell(12, 8, num + ".")
        pdf.set_text_color(50, 50, 60)
        pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")

    # ════════════════════════════════════════════════════════
    #  SECTION 1: PROJECT PURPOSE
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("1", "Project Purpose & Core Objectives")

    pdf.body(
        "Aegis-Portal is a research-grade, AI-augmented credential-vault and security-intelligence platform "
        "that demonstrates how autonomous large-language-model agents can be embedded directly into a "
        "encrypted password-management workflow to provide real-time, forensic security insights."
    )
    pdf.body(
        "Developed as Innovative Project PRJCS681, the platform transcends conventional password vaulting by "
        "fusing authenticated credential encryption, a custom Ether-Credit (EC) resource economy, a UPI-linked "
        "payment system, and a three-agent AI intelligence core -- all unified under a high-end Glassmorphism "
        "command interface."
    )
    pdf.body(
        "The system is built to answer a key research question: Can AI inference be embedded directly into a "
        "security-critical credential management workflow to deliver real-time adversarial intelligence at "
        "practical response latency and reliability?"
    )

    pdf.sub_title("Core Objectives")

    objectives = [
        ("Secure Credential Storage",
         "Encrypted 'shards' are stored in a local SQLite WAL database. Encryption uses per-user Fernet keys "
         "derived from a user-provided Shard Key; the active key is retained in Streamlit session memory while the vault is unlocked."),
        ("Real-Time AI Security Auditing",
         "Three AI-assisted workflows use Google Gemini where consent and configuration permit: "
         "Oracle (entropy & password-strength audit), Vision Sentinel (forensic verification of UPI payment "
         "screenshots), and Shard Warden (behavioural threat assessment of identities)."),
        ("Economy & Incentivisation",
         "Users earn/spend Ether-Credits (EC). Each AI query costs 1 EC; payments are made via Indian UPI, "
         "verified by the Vision Sentinel, and approved by a human admin."),
        ("Comprehensive Auditing & Admin Control",
         "Every action generates a structured security event logged in security_events. Administrators can "
         "view the full forensic trail, invoke the Warden for risk scoring, and manage user status "
         "(warn, lockdown, ban)."),
        ("Encrypted Vault Architecture",
         "The server never stores plaintext credentials or encryption keys. Decryption requires the user to "
         "re-enter the Shard Key each session, ensuring that even a full database breach yields no usable passwords."),
        ("Research Demonstration",
         "Shows how optional cloud inference can support security reasoning while local controls remain authoritative. "
         "a first-line defensive layer rather than a downstream analysis tool."),
    ]
    for title, desc in objectives:
        pdf.body_bold(title)
        pdf.body(desc)

    pdf.sub_title("One-Sentence Pitch")
    pdf.callout(
        "Aegis-Portal is a glass-morphed, AI-driven password vault that encrypts credentials with "
        "authenticated vault encryption while leveraging AI-assisted analysis to audit credential strength, "
        "verify payments, and continuously assess user behaviour for real-time security intelligence."
    )

    # ════════════════════════════════════════════════════════
    #  SECTION 2: CORE DEVELOPMENT STACK
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("2", "Core Development Stack (Tools & Libraries)")

    headers = ["Category", "Tool / Library", "Purpose in the Project", "Source File"]
    col_w = [28, 30, 90, 32]
    rows = [
        ["Web UI", "Streamlit", "Reactive web framework; renders the Glassmorphism command centre, dashboards, forms, and admin terminal.", "main.py"],
        ["Data Handling", "pandas", "Builds DataFrames for the forensic event table and admin identity grid.", "main.py"],
        ["Persistence", "SQLite (WAL mode)", "Stores users, encrypted shards, transactions, and audit events in vault.db. Built-in Python sqlite3.", "database_logic.py"],
        ["Encryption", "cryptography (Fernet, PBKDF2HMAC)", "Fernet authenticated encryption (AES-128-CBC + HMAC-SHA256); PBKDF2 key derivation from the user-supplied Shard Key. Decrypted values remain in server-side session state while unlocked.", "database_logic.py"],
        ["Password Hash", "bcrypt", "Secure storage of login passwords with adaptive cost factor.", "database_logic.py"],
        ["Environment", "python-dotenv", "Loads .env fallback secrets when st.secrets (Streamlit Cloud) is unavailable.", "main.py"],
        ["Image Processing", "Pillow", "Normalises uploaded UPI payment screenshots before sending to Vision model.", "ai_analyser.py"],
        ["LLM Inference", "Google Gen AI SDK", "Calls the Gemini API for consented text and screenshot analysis.", "ai_analyser.py"],
    ]
    pdf.draw_table(headers, rows, col_w)

    # ════════════════════════════════════════════════════════
    #  SECTION 3: WORKFLOW
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("3", "Process / Workflow Overview")

    pdf.step("1", "User Authentication",
             "Email + bcrypt-hashed password are verified. The user's status (active / warned / lockdown / banned) determines whether the UI proceeds. "
             "Successful login triggers a heartbeat (update_heartbeat()) for presence tracking.")

    pdf.step("2", "Vault Operations",
             "A Shard Key (entered each session) is PBKDF2-derived to a 32-byte Fernet key (never persisted). "
             "Credential shards (site, username, password) are encrypted with this key and stored in SQLite (accounts table). "
             "Decrypted records and the active Shard Key are held in server-side Streamlit session state while the vault is unlocked; this is not strict zero-knowledge architecture.")

    pdf.step("3", "AI Oracle Consultation",
             "User sends a credential payload. Agent 1 (Aegis Oracle) consumes 1 Ether-Credit. "
             "The Oracle computes password-strength characteristics locally. Only after explicit opt-in may coarse, non-reversible characteristics be sent to Gemini for an explanation. The raw password is never sent."
             "([FORTIFIED], [COMPROMISED], [CRITICAL]) with concise recommendations.")

    pdf.step("4", "Payment & Credit Top-up",
             "User explicitly consents before the normalized payment screenshot and expected amount are sent to Gemini Vision for an advisory analysis. "
             "The agent outputs a JSON verdict (VERIFIED, SUSPICIOUS, ...) + confidence score. "
             "A Human-in-the-Loop admin must approve the verdict before Ether-Credits are credited.")

    pdf.step("5", "Admin Terminal (Forensic Dashboard)",
             "Shows live user presence, aggregate statistics (get_dashboard_stats()), and a filterable audit log (security_events). "
             "Admin can invoke Agent 3 (Shard Warden) on any identity to receive a JSON threat assessment "
             "(threat_level, risk_score, recommended_action). "
             "Admin can manually change user status, grant Ether-Credits, and approve/reject transactions.")

    pdf.step("6", "Logging & Auditing",
             "Every meaningful event (AUTH_SUCCESS, VAULT_BREACH_ATTEMPT, LOCKDOWN_TRIGGERED, etc.) is recorded via "
             "notifier.log_security_event(). Events carry timestamps, severity (INFO / WARNING / CRITICAL), source IP, "
             "and optional target email.")

    pdf.step("7", "Ban Protocol",
             "When an identity is marked 'banned', a single SQLite transaction atomically deletes all rows across "
             "users, accounts, transactions, and security_events. A system event logs the purge -- no remnants remain.")

    # ════════════════════════════════════════════════════════
    #  SECTION 4: LLMs
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("4", "Gemini Models & Their Exact Roles")

    pdf.body(
        "The AI workflows use the official Google Gen AI Python SDK (google-genai) through client.models.generate_content() inside ai_analyser.py. Password scoring remains local; the text explanation is optional, and screenshot analysis is consent-gated. "
        "The integration uses bounded retries for transient failures and validated fallbacks; it does not treat model output as an authorization decision."
    )

    # Agent 1
    pdf.sub_title("Agent 1 -- The Aegis Oracle")
    pdf.body_bold("Model: gemini-3.8-flash (text)")
    pdf.body_bold("Temperature: 0.2")
    pdf.body(
        "Role: Local-first password-strength auditor. It calculates coarse length, character-category, repetition, sequence, and entropy indicators on the server. Only coarse derived features can be sent to Gemini after opt-in; raw passwords and password hashes are never transmitted."
    )
    pdf.body_bold("Output Format (strict):")
    pdf.bullet("Tactical grade: [FORTIFIED] / [COMPROMISED] / [CRITICAL]")
    pdf.bullet("Three rapid-fire tactical opinions (max 8 words each), prefixed with: >")
    pdf.bullet("One-line RECOMMENDATION")
    pdf.body("Economy: Costs 1 Ether-Credit per consultation.")
    pdf.ln(2)

    # Agent 2
    pdf.sub_title("Agent 2 -- The Vision Sentinel")
    pdf.body_bold("Model: gemini-3.8-flash (multimodal)")
    pdf.body_bold("Temperature: 0.1")
    pdf.body(
        "Role: Advisory forensic screenshot analyst. Receives a validated, normalized image only after explicit consent. The model extracts visible amount, recipient text, reference, and possible manipulation indicators; local checks compare the extracted data with locally configured settings. Every submission remains PENDING until an administrator acts."
    )
    pdf.body_bold("Output Format (strict JSON):")
    pdf.bullet("verdict: VERIFIED / SUSPICIOUS / UNREADABLE / PENDING_ADMIN_REVIEW")
    pdf.bullet("confidence: 0.0 - 1.0")
    pdf.bullet("amount_detected, upi_ref, recipient_match, findings[]")
    pdf.body(
        "HITL Design: Even a VERIFIED verdict requires final admin sign-off -- a deliberate Human-in-the-Loop safeguard. "
        "This is the only agent that processes binary image data."
    )
    pdf.ln(2)

    # Agent 3
    pdf.sub_title("Agent 3 -- The Shard Warden")
    pdf.body_bold("Model: gemini-3.8-flash (text)")
    pdf.body_bold("Temperature: 0.1")
    pdf.body(
        "Role: Advisory behavioral monitor. Admins can request analysis of up to 20 events after event types, severity labels, and coarse recency are sanitized. Email addresses, IP addresses, and event descriptions are not sent. It cannot execute administrative actions."
    )
    pdf.body_bold("Output Format (strict JSON):")
    pdf.bullet("threat_level: NOMINAL / ELEVATED / CRITICAL")
    pdf.bullet("risk_score: 0.0 - 10.0")
    pdf.bullet("assessment: paragraph-length tactical evaluation")
    pdf.bullet("recommended_action: MONITOR / WARN / BAN / LOCKDOWN")
    pdf.bullet("indicators[]: list of behavioral red flags")
    pdf.body(
        "Passive Heartbeat: warden_heartbeat_check() computes a system-wide security posture from the active/banned "
        "user ratio -- purely in Python, with zero API calls."
    )

    # ════════════════════════════════════════════════════════
    #  SECTION 5: ARCHITECTURE DIAGRAM
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("5", "System Architecture Diagram")

    arch_lines = [
        "USER (Browser / Streamlit)",
        "      |",
        "      v",
        "main.py  --  UI ORCHESTRATOR",
        "  Streamlit Command Center + Glassmorphism Design System",
        "  Auth Gate | Dashboard | Archive Vault | Oracle | Credit-Bay | Admin",
        "      |              |               |",
        "      v              v               v",
        " Archive Vault   AI Oracle       Credit-Bay",
        " (AES/Fernet)    (1 EC/audit)    (UPI + Vision Verify)",
        "      |              |               |",
        "      +--------------+---------------+",
        "                     |",
        "                     v",
        "ai_analyser.py  --  MULTI-AGENT INTELLIGENCE CORE",
        "  Google Gemini API  |  Bounded, validated inference",
        "  +------------------+---------------------+",
        "  | AGENT 1          | AGENT 2             | AGENT 3             |",
        "  | The Aegis Oracle  | The Vision Sentinel | The Shard Warden    |",
        "  | Gemini 3.8 Flash     | Gemini 3.8 Flash Vision   | Gemini 3.8 Flash       |",
        "  | Entropy Auditor   | Transaction Verify  | Behavioral Monitor  |",
        "  +------------------+---------------------+---------------------+",
        "                     |",
        "                     v",
        "notifier.py  --  FORENSIC LOGGING & SIGNAL LAYER",
        "  Toast Alerts | Security Events | Severity Levels",
        "                     |",
        "                     v",
        "database_logic.py  --  PERSISTENCE ENGINE",
        "  AES-128-CBC (Fernet) | bcrypt | SQLite WAL",
        "  +--------+----------+----------+----------------+",
        "  | users  | accounts | transactions | security_events |",
        "  +--------+----------+----------+----------------+",
        "                     |",
        "                     v",
        "             vault.db  +  audit_screenshots/",
    ]
    pdf.set_font("Courier", "", 8)
    pdf.set_text_color(50, 50, 60)
    for line in arch_lines:
        pdf.cell(0, 4.5, line, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Quick reference
    pdf.sub_title("Quick Reference Flow")
    quick = [
        "USER (Browser / Streamlit)  -->  main.py (UI Orchestrator)",
        "   |-- Auth Gate       -->  bcrypt / SQLite (users)",
        "   |-- Vault Ops       -->  cryptography/Fernet (accounts)",
        "   |-- AI Oracle       -->  Local score + optional Gemini explanation",
        "   |-- Credit-Bay      -->  Pillow --> consented Gemini Vision --> admin approval",
        "   |-- Admin Terminal   -->  notifier.py (audit) + Agent 3 (Warden)",
    ]
    pdf.set_font("Courier", "", 9)
    for line in quick:
        pdf.cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # ════════════════════════════════════════════════════════
    #  SECTION 6: FILE REFERENCE
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("6", "File-by-File Reference")

    files = [
        ("main.py", "Primary UI Orchestrator",
         "Entry point and top-level controller. Initializes page config, injects the complete Glassmorphism CSS design "
         "system, manages st.session_state for authenticated user, credits, decrypted shard cache, and admin flag. "
         "Orchestrates six UI surfaces: Auth Gate (Login/Register) -> Command Center Dashboard -> Archive Vault -> "
         "AI Oracle -> Credit-Bay -> Admin Terminal.\n\n"
         "Internal layout: 1. Core Config -> 2. Design System (CSS) -> 3. Session Init -> 4. Auth Gate -> "
         "5. Dashboard -> 6. Lockdown Check -> 7. Sidebar Navigation -> 8. Archive Vault Module -> "
         "9. AI Oracle Module -> 10. Credit-Bay Module -> 11. Admin Terminal"),

        ("ai_analyser.py", "Multi-Agent Intelligence Core",
         "Houses the Gemini client factory and three validated analysis workflows. Oracle strength scoring is local-first and its optional explanation sends only non-reversible features; Vision Sentinel is consent-gated; Warden receives sanitized event metadata. All model outputs are validated and remain advisory."),

        ("database_logic.py", "Persistence & Encryption Engine",
         "All SQL operations, Fernet encryption, and the forensic audit trail. Uses a WAL-mode SQLite "
         "context manager with automatic rollback. setup_security() initializes all four tables with schema migration "
         "support. Five logical groups: Identity Auth -> Heartbeat/Presence -> Vault Cryptography -> EC Economy -> "
         "Transaction Ledger -> Security Event Logging.\n\n"
         "Key cryptographic function: get_fernet_key(user_key, email) derives a 32-byte Fernet key via PBKDF2HMAC "
         "(SHA-256, 100k iterations, email as salt). The key exists only in volatile function scope."),

        ("notifier.py", "Forensic Logging & Signal Layer",
         "User-facing notifications with immersive cybersecurity language. Contains EVENT_TYPES (18 event codes with "
         "icons and severity labels) and IMMERSIVE_MESSAGES (35+ themed message strings). Provides notify(), toast(), "
         "security_alert(), trigger_lockdown(), and forensic display helpers for the Admin Terminal event table."),

        ("requirements.txt", "Dependency Manifest",
         "Declares Streamlit, pandas, python-dotenv, cryptography, bcrypt, google-genai, Pillow, and document-generation/test dependencies."),

        ("Private QR asset", "Excluded local configuration",
         "A private QR image is supplied locally by the application owner and is intentionally not part of source control."),

        ("vault.db", "Local Encrypted Database (gitignored)",
         "Created locally at runtime. Never share or commit the live database; use synthetic temporary databases for tests."),
    ]

    for fname, role, desc in files:
        pdf.body_bold(f"{fname}  --  {role}")
        pdf.body(desc)

    # ════════════════════════════════════════════════════════
    #  SECTION 7: DATABASE SCHEMA
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("7", "Database Schema")

    pdf.body("Aegis-Portal maintains four SQL tables in the local vault database:")
    pdf.ln(2)

    # users
    pdf.body_bold("Table: users  --  Identity Store")
    pdf.draw_table(
        ["Column", "Type", "Description"],
        [
            ["email", "TEXT PRIMARY KEY", "User identity (email address)"],
            ["hashed_pw", "TEXT NOT NULL", "bcrypt-hashed password"],
            ["ether_credits", "INTEGER DEFAULT 5", "Current Ether-Credit balance"],
            ["last_login", "TEXT", "Timestamp of last successful login"],
            ["last_seen", "TEXT", "Timestamp of last heartbeat update"],
            ["status", "TEXT DEFAULT 'active'", "active | warned | lockdown | banned"],
        ],
        [30, 50, 100]
    )

    # accounts
    pdf.body_bold("Table: accounts  --  Encrypted Credential Shards")
    pdf.draw_table(
        ["Column", "Type", "Description"],
        [
            ["id", "INTEGER PRIMARY KEY", "Auto-incrementing shard ID"],
            ["owner_email", "TEXT NOT NULL", "References users(email)"],
            ["site", "TEXT NOT NULL", "Target website/service name"],
            ["username", "TEXT NOT NULL", "Account username"],
            ["password", "TEXT NOT NULL", "Fernet-encrypted ciphertext"],
        ],
        [30, 50, 100]
    )

    # transactions
    pdf.body_bold("Table: transactions  --  Credit-Bay Payment Ledger")
    pdf.draw_table(
        ["Column", "Type", "Description"],
        [
            ["id", "INTEGER PRIMARY KEY", "Auto-incrementing transaction ID"],
            ["user_email", "TEXT NOT NULL", "References users(email)"],
            ["amount", "INTEGER NOT NULL", "Amount in INR"],
            ["timestamp", "TEXT NOT NULL", "Transaction creation time"],
            ["status", "TEXT DEFAULT 'PENDING'", "PENDING | APPROVED | REJECTED (AI verdict is advisory only)"],
            ["image_path", "TEXT", "Path to uploaded screenshot"],
            ["verified_by", "TEXT", "Admin who approved/rejected"],
            ["verified_at", "TEXT", "Admin verification timestamp"],
        ],
        [30, 50, 100]
    )

    # security_events
    pdf.body_bold("Table: security_events  --  Forensic Audit Trail")
    pdf.draw_table(
        ["Column", "Type", "Description"],
        [
            ["id", "INTEGER PRIMARY KEY", "Auto-incrementing event ID"],
            ["timestamp", "TEXT NOT NULL", "Event timestamp"],
            ["event_type", "TEXT NOT NULL", "One of 18 event type codes"],
            ["target_email", "TEXT", "Identity the event pertains to"],
            ["details", "TEXT", "Descriptive event details"],
            ["severity", "TEXT DEFAULT 'INFO'", "INFO | WARNING | CRITICAL"],
            ["source_ip", "TEXT", "Source IP address (if available)"],
        ],
        [30, 50, 100]
    )

    # ════════════════════════════════════════════════════════
    #  SECTION 8: DEPENDENCY REFERENCE
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("8", "Dependency Reference (requirements.txt)")

    deps = [
        ["streamlit", "Latest",
         "The complete application framework. Provides the web server, reactive UI components, session state management, "
         "secrets handling, and the browser-rendered frontend."],
        ["pandas", "Latest",
         "Powers the Admin Terminal's forensic event table and identity management grid. Constructs DataFrames from raw "
         "SQLite query results."],
        ["python-dotenv", "Latest",
         "Loads environment variables from a local .env file during development. Provides the fallback mechanism for "
         "GEMINI_API_KEY, model settings, and ADMIN_KEY when st.secrets is unavailable."],
        ["cryptography", "Latest",
         "The core encryption library. Provides Fernet (AES-128-CBC with HMAC-SHA256) for symmetric encryption and "
         "PBKDF2HMAC (SHA-256, 100,000 iterations) for per-record key derivation. The active key is held in server-side session state while the vault is unlocked; the app does not claim strict zero knowledge."],
        ["bcrypt", "Latest",
         "Handles all authentication password hashing. Passwords are hashed with bcrypt.hashpw() (auto-generates salt, "
         "adaptive cost factor) and verified with bcrypt.checkpw(). Raw passwords are never stored."],
        ["google-genai", "2.x (<3.0)",
         "Google's official Python SDK. Used by ai_analyser.py for consented Gemini text and multimodal analysis. Oracle password scoring remains local."],
        ["Pillow", "Latest",
         "Python Imaging Library used in the Credit-Bay module to process uploaded payment screenshots. Handles image "
         "file-type and image-dimension validation, JPEG normalization, and metadata stripping before consented Gemini Vision processing."],
    ]
    pdf.draw_table(["Package", "Version", "Role in Aegis-Portal"], deps, [25, 18, 137])

    # ════════════════════════════════════════════════════════
    #  SECTION 9: SECURITY ARCHITECTURE
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("9", "Security Architecture Notes")

    sec_notes = [
        ("Session-scoped Key Handling (Not Strict Zero-Knowledge)",
         "The database stores Fernet-encrypted credential values. While the vault is unlocked, decrypted records and the active key are held in server-side Streamlit session state. They are cleared on logout, idle expiry, and lockdown transitions."),
        ("External AI Privacy Boundaries",
         "The raw password and password hash are never sent to Gemini. The Oracle optionally sends coarse derived features after opt-in. Payment screenshots are sent only after explicit consent. The Warden receives sanitized event metadata."),
        ("Forensic Completeness",
         "log_security_event() is called for every meaningful system action. It uses a bare try/except with silent "
         "failure to ensure logging never crashes the application -- security events are best-effort but never blocking."),
        ("Ban Protocol Atomicity",
         "The 'banned' status executes cascading deletes across all four tables within a single SQLite transaction. "
         "The identity is completely expunged before the ban event is logged under the SYSTEM target."),
        ("Global Kill-Switch",
         "Persistent status checks run on every request. If an administrator bans an identity, an instant kill-switch "
         "blocks all Oracle and Vault access for that active session without requiring re-login."),
        ("Volatile Key Management",
         "The master encryption key is generated in volatile session memory (st.session_state) and destroyed instantly "
         "upon logout. No key ever touches persistent disk storage."),
    ]
    for title, desc in sec_notes:
        pdf.body_bold(title)
        pdf.body(desc)

    # ════════════════════════════════════════════════════════
    #  SECTION 10: TL;DR
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("10", "TL;DR for the Interview")

    pdf.sub_title("Tools")
    pdf.body(
        "Streamlit, pandas, SQLite (WAL), cryptography (Fernet), bcrypt, python-dotenv, Pillow, and Google Gen AI SDK."
    )

    pdf.sub_title("Process")
    pdf.body(
        "Authenticate -> encrypt/decrypt shards in-memory -> consult the Oracle (LLM) -> optional payment "
        "verification via Vision Sentinel -> admin-driven audit & credit management -> continuous forensic logging."
    )

    pdf.sub_title("LLMs")
    pdf.body(
        "Gemini is used for optional Oracle explanations, consented screenshot analysis, and sanitized Warden assessments. The password score is computed locally. All responses are schema-checked and treated as advisory."
    )

    pdf.sub_title("Key Differentiators to Highlight")
    pdf.bullet("Encrypted Vault -- Fernet protects stored credential values; unlocked plaintext exists in session memory.")
    pdf.bullet("Multi-Agent AI Core -- three autonomous agents with distinct forensic roles.")
    pdf.bullet("Human-in-the-Loop -- AI verdicts always require admin sign-off for critical actions.")
    pdf.bullet("Privacy-first AI -- local password scoring, opt-in Oracle explanation, consented screenshot processing, and sanitized Warden events.")
    pdf.bullet("Forensic Completeness -- 18 event types, 3 severity levels, full audit trail.")
    pdf.bullet("Ether-Credit Economy -- gamified resource system with real UPI payments.")
    pdf.bullet("Glassmorphism UI -- premium command-centre aesthetic with immersive cybersecurity language.")

    pdf.ln(10)
    pdf.callout(
        '"Security is not a feature. It is an architecture."  --  Sayar Bhattacharyya'
    )

    # ── save ──
    output_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "Aegis_Portal_Interview_Document.pdf"
    )
    pdf.output(output_path)
    print(f"PDF generated successfully: {output_path}")
    return output_path


if __name__ == "__main__":
    build_pdf()