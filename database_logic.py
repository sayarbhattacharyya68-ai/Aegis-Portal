"""SQLite persistence and encrypted credential-vault operations for Aegis-Portal.

The existing schema, Fernet ciphertext format, PBKDF2-HMAC-SHA256 algorithm,
100,000 iteration count, and legacy salt fallback are intentionally preserved.
"""

from __future__ import annotations

import base64
import datetime
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

try:
    import bcrypt
except ImportError:  # The runtime dependency is declared in requirements.txt.
    bcrypt = None
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("AEGIS_DB_PATH", str(PROJECT_DIR / "vault.db"))).expanduser()
VALID_STATUSES = {"active", "warned", "lockdown", "banned"}


def _database_path() -> Path:
    configured = os.getenv("AEGIS_DB_PATH")
    path = Path(configured).expanduser() if configured else Path(DB_PATH)
    if not path.is_absolute():
        path = PROJECT_DIR / path
    return path.resolve()


@contextmanager
def get_db():
    """Open a short-lived SQLite connection with safe locking defaults."""
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=15, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def setup_security():
    """Create tables and apply only additive, backwards-compatible migrations."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            hashed_pw TEXT NOT NULL,
            ether_credits INTEGER DEFAULT 5,
            last_login TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'active'
        )""")

        cursor.execute("PRAGMA table_info(users)")
        user_columns = {column[1] for column in cursor.fetchall()}
        if "last_seen" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_seen TEXT")
        if "status" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")

        cursor.execute("""CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_email TEXT NOT NULL,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            salt TEXT,
            encryption_version INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_email) REFERENCES users(email)
        )""")
        cursor.execute("PRAGMA table_info(accounts)")
        account_columns = {column[1] for column in cursor.fetchall()}
        if "salt" not in account_columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN salt TEXT")
        if "encryption_version" not in account_columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 0")

        cursor.execute("""CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            amount INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            image_path TEXT,
            verified_by TEXT,
            verified_at TEXT,
            FOREIGN KEY (user_email) REFERENCES users(email)
        )""")

        cursor.execute("PRAGMA table_info(transactions)")
        transaction_columns = {column[1] for column in cursor.fetchall()}
        for column_name, column_type in (
            ("ai_verdict", "TEXT"),
            ("ai_confidence", "REAL"),
            ("ai_findings", "TEXT"),
            ("ai_amount_detected", "TEXT"),
            ("ai_recipient_match", "INTEGER"),
        ):
            if column_name not in transaction_columns:
                cursor.execute(f"ALTER TABLE transactions ADD COLUMN {column_name} {column_type}")

        cursor.execute("""CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            target_email TEXT,
            details TEXT,
            severity TEXT DEFAULT 'INFO',
            source_ip TEXT
        )""")

        # Additive login throttle: progressive delays, not account lockout.
        cursor.execute("""CREATE TABLE IF NOT EXISTS auth_attempts (
            email TEXT PRIMARY KEY,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            last_attempt TEXT NOT NULL
        )""")


def create_user(email, password):
    """Create a user identity with a bcrypt password hash."""
    if bcrypt is None:
        raise RuntimeError("bcrypt is required. Install the project dependencies with: python -m pip install -r requirements.txt")
    if not isinstance(email, str) or not isinstance(password, str):
        return False
    if not email or len(email) > 254 or len(password) < 8 or len(password) > 1024:
        return False
    try:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (email, hashed_pw, ether_credits, last_login, last_seen, status) "
                "VALUES (?, ?, 5, ?, ?, 'active')",
                (email, hashed, now, now),
            )
        log_security_event("IDENTITY_CREATED", email, "New identity created")
        return True
    except sqlite3.IntegrityError:
        return False
    except (sqlite3.Error, ValueError, TypeError):
        return False


def authenticate_user(email, password):
    """Verify bcrypt credentials with a progressive, non-locking throttle."""
    if bcrypt is None:
        raise RuntimeError("bcrypt is required. Install the project dependencies with: python -m pip install -r requirements.txt")
    if not isinstance(email, str) or not isinstance(password, str):
        return None

    now = datetime.datetime.now()
    now_text = now.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with get_db() as conn:
            attempt_row = conn.execute(
                "SELECT attempt_count, last_attempt FROM auth_attempts WHERE email=?", (email,)
            ).fetchone()
            row = conn.execute(
                "SELECT hashed_pw, status FROM users WHERE email=?", (email,)
            ).fetchone()

        if attempt_row:
            attempt_count, last_attempt_text = attempt_row
            try:
                last_attempt = datetime.datetime.strptime(last_attempt_text, "%Y-%m-%d %H:%M:%S")
                delay_seconds = min(30, 2 ** max(0, int(attempt_count) - 3)) if attempt_count >= 3 else 0
                if (now - last_attempt).total_seconds() < delay_seconds:
                    log_security_event("AUTH_THROTTLED", email, "Authentication retry delayed", severity="WARNING")
                    return None
            except (TypeError, ValueError):
                pass

        if row and bcrypt.checkpw(password.encode("utf-8"), row[0]):
            with get_db() as conn:
                conn.execute("DELETE FROM auth_attempts WHERE email=?", (email,))
            if row[1] != "banned":
                update_heartbeat(email)
            log_security_event("AUTH_SUCCESS", email, "Identity authentication succeeded")
            return row[1]

        with get_db() as conn:
            conn.execute(
                "INSERT INTO auth_attempts (email, attempt_count, last_attempt) VALUES (?, 1, ?) "
                "ON CONFLICT(email) DO UPDATE SET attempt_count=MIN(auth_attempts.attempt_count+1, 10), "
                "last_attempt=excluded.last_attempt",
                (email, now_text),
            )
        log_security_event("AUTH_FAILURE", email, "Authentication failed", severity="WARNING")
        return None
    except (sqlite3.Error, ValueError, TypeError):
        return None


def check_status(email):
    with get_db() as conn:
        row = conn.execute("SELECT status FROM users WHERE email=?", (email,)).fetchone()
    return row[0] if row else "banned"


def update_user_status(email, new_status):
    """Apply an administrator-requested status transition.

    The caller must authenticate as an administrator before invoking this
    function. The destructive BAN operation is atomic within one transaction.
    """
    if new_status not in VALID_STATUSES:
        return False
    try:
        with get_db() as conn:
            if new_status == "banned":
                # Retain this identity and its records so the user can authenticate
                # only to see the suspension notice and the administrator can audit.
                conn.execute("DELETE FROM auth_attempts WHERE email=?", (email,))
            result = conn.execute("UPDATE users SET status=? WHERE email=?", (new_status, email))
            changed = result.rowcount == 1
        if changed:
            event = f"IDENTITY_{new_status.upper()}"
            severity = "CRITICAL" if new_status in {"banned", "lockdown"} else "WARNING" if new_status == "warned" else "INFO"
            message = (
                "Administrator suspended identity access; records retained for audit"
                if new_status == "banned"
                else "Administrator changed identity status"
            )
            log_security_event(event, email, message, severity=severity)
        return changed
    except sqlite3.Error:
        return False


def update_heartbeat(email):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET last_seen=? WHERE email=? AND status!='banned'",
            (now, email),
        )


def get_all_users():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT email, ether_credits, status, last_seen FROM users ORDER BY email"
        ).fetchall()
    now = datetime.datetime.now()
    output = []
    for email, credits, status, last_seen in rows:
        presence = "Offline ⚪"
        if last_seen:
            try:
                observed = datetime.datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                if (now - observed).total_seconds() < 120:
                    presence = "Online 🟢"
            except (ValueError, TypeError):
                pass
        output.append((email, credits, status, presence))
    return output


# ------------------------ Encrypted credential vault -----------------------

def get_fernet_key(user_password, salt_input):
    """Preserve the original PBKDF2-HMAC-SHA256 key derivation parameters."""
    salt_bytes = salt_input.encode() if isinstance(salt_input, str) else salt_input
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(user_password.encode()))


def save_account(owner, site, user, pwd, user_provided_key):
    """Encrypt service, username, and password with the user's Master Vault Key."""
    if not all(isinstance(value, str) for value in (owner, site, user, pwd, user_provided_key)):
        raise ValueError("Credential fields must be text.")
    if (
        not site.strip() or len(site) > 200 or len(user) > 254
        or not pwd or len(pwd) > 4096 or len(user_provided_key) > 4096
    ):
        raise ValueError("Credential fields are empty or exceed the supported size.")

    raw_salt = os.urandom(16)
    cipher = Fernet(get_fernet_key(user_provided_key, raw_salt))
    encrypted_site = cipher.encrypt(site.strip().encode("utf-8")).decode("ascii")
    encrypted_user = cipher.encrypt(user.strip().encode("utf-8")).decode("ascii")
    encrypted_password = cipher.encrypt(pwd.encode("utf-8")).decode("ascii")
    encoded_salt = base64.b64encode(raw_salt).decode("ascii")

    with get_db() as conn:
        result = conn.execute(
            "INSERT INTO accounts "
            "(owner_email, site, username, password, salt, encryption_version) "
            "SELECT ?, ?, ?, ?, ?, 2 WHERE EXISTS "
            "(SELECT 1 FROM users WHERE email=? AND status='active')",
            (owner, encrypted_site, encrypted_user, encrypted_password, encoded_salt, owner),
        )
        if result.rowcount != 1:
            raise PermissionError("This identity is suspended or no longer active.")
    log_security_event("VAULT_WRITE", owner, "New encrypted credential archived")


def unlock_vault(owner, user_provided_key, key_verified=False):
    """Decrypt owner's entries with the supplied Master Vault Key.

    Returns (records, unreadable_ids) on success. Returns None when the identity is
    not active, storage fails, or the key opens no record (a wrong key). When
    key_verified is True the key has already unlocked this vault in the session, so
    an empty result set is returned instead of None. Records that cannot be opened
    with this key are reported by id so they never block the readable records.
    """
    if not isinstance(owner, str) or not isinstance(user_provided_key, str) or not user_provided_key:
        return None
    try:
        with get_db() as conn:
            standing = conn.execute(
                "SELECT status FROM users WHERE email=?",
                (owner,),
            ).fetchone()
            if not standing or standing[0] != "active":
                return None
            rows = conn.execute(
                "SELECT id, site, username, password, salt, encryption_version "
                "FROM accounts WHERE owner_email=? ORDER BY id",
                (owner,),
            ).fetchall()

        decrypted = []
        unreadable = []
        migrations = []
        for row in rows:
            try:
                salt_bytes = (
                    base64.b64decode(row[4].encode("ascii"), validate=True)
                    if row[4] else owner.encode("utf-8")
                )
                version = int(row[5] or 0)
                cipher = Fernet(get_fernet_key(user_provided_key, salt_bytes))
                if version >= 2:
                    site = cipher.decrypt(row[1].encode("ascii")).decode("utf-8")
                    username = cipher.decrypt(row[2].encode("ascii")).decode("utf-8")
                    password = cipher.decrypt(row[3].encode("ascii")).decode("utf-8")
                else:
                    # Legacy rows encrypted only Password. Upgrade only after it
                    # has been successfully decrypted with the supplied master key.
                    site, username = row[1], row[2]
                    password = cipher.decrypt(row[3].encode("ascii")).decode("utf-8")
                    new_salt = os.urandom(16)
                    new_cipher = Fernet(get_fernet_key(user_provided_key, new_salt))
                    migrations.append((
                        new_cipher.encrypt(site.encode("utf-8")).decode("ascii"),
                        new_cipher.encrypt(username.encode("utf-8")).decode("ascii"),
                        new_cipher.encrypt(password.encode("utf-8")).decode("ascii"),
                        base64.b64encode(new_salt).decode("ascii"),
                        row[0],
                    ))
                decrypted.append({
                    "id": row[0], "Site": site, "User": username, "Password": password
                })
            except (InvalidToken, ValueError, TypeError, UnicodeError):
                unreadable.append(row[0])

        if rows and not decrypted and not key_verified:
            log_security_event(
                "VAULT_ACCESS_DENIED", owner,
                "Master Vault Key did not open any saved record",
                severity="WARNING",
            )
            return None

        if migrations:
            with get_db() as conn:
                active = conn.execute(
                    "SELECT 1 FROM users WHERE email=? AND status='active'",
                    (owner,),
                ).fetchone()
                if not active:
                    return None
                for enc_site, enc_user, enc_password, encoded_salt, account_id in migrations:
                    conn.execute(
                        "UPDATE accounts SET site=?, username=?, password=?, salt=?, encryption_version=2 "
                        "WHERE id=? AND owner_email=? AND encryption_version<2",
                        (enc_site, enc_user, enc_password, encoded_salt, account_id, owner),
                    )

        if unreadable:
            log_security_event(
                "VAULT_ACCESS_DENIED", owner,
                f"{len(unreadable)} saved record(s) could not be opened with the supplied key",
                severity="WARNING",
            )
        log_security_event("VAULT_ACCESS", owner, f"Vault accessed; {len(decrypted)} records decrypted")
        return decrypted, unreadable
    except (sqlite3.Error, ValueError, TypeError):
        return None


def fetch_accounts(owner, user_provided_key):
    """Return only the readable records, or None when the key cannot unlock the vault."""
    result = unlock_vault(owner, user_provided_key)
    return None if result is None else result[0]


def update_account(account_id, new_username, new_password, user_provided_key, owner_email, new_site=None):
    """Edit each credential field and encrypt them using a fresh stored salt."""
    if not all(isinstance(value, str) for value in (new_username, new_password, user_provided_key, owner_email)):
        return False
    if new_site is not None and not isinstance(new_site, str):
        return False
    if (
        len(new_username) > 254 or not new_password or len(new_password) > 4096
        or len(user_provided_key) > 4096
        or (new_site is not None and (not new_site.strip() or len(new_site) > 200))
    ):
        return False
    try:
        if new_site is None:
            records = fetch_accounts(owner_email, user_provided_key)
            if records is None:
                return False
            record = next((item for item in records if item["id"] == account_id), None)
            if record is None:
                return False
            new_site = record["Site"]

        raw_salt = os.urandom(16)
        cipher = Fernet(get_fernet_key(user_provided_key, raw_salt))
        enc_site = cipher.encrypt(new_site.strip().encode("utf-8")).decode("ascii")
        enc_user = cipher.encrypt(new_username.strip().encode("utf-8")).decode("ascii")
        enc_password = cipher.encrypt(new_password.encode("utf-8")).decode("ascii")
        encoded_salt = base64.b64encode(raw_salt).decode("ascii")
        with get_db() as conn:
            result = conn.execute(
                "UPDATE accounts SET site=?, username=?, password=?, salt=?, encryption_version=2 "
                "WHERE id=? AND owner_email=? AND EXISTS "
                "(SELECT 1 FROM users WHERE email=? AND status='active')",
                (enc_site, enc_user, enc_password, encoded_salt, account_id, owner_email, owner_email),
            )
        if result.rowcount:
            log_security_event("VAULT_WRITE", owner_email, "Encrypted credential record updated")
            return True
        return False
    except (sqlite3.Error, ValueError, TypeError, InvalidToken):
        return False

def delete_account(account_id, owner_email):
    """Delete only a credential belonging to an active owner."""
    with get_db() as conn:
        result = conn.execute(
            "DELETE FROM accounts WHERE id=? AND owner_email=? AND EXISTS "
            "(SELECT 1 FROM users WHERE email=? AND status='active')",
            (account_id, owner_email, owner_email),
        )
    if result.rowcount:
        log_security_event("VAULT_DELETE", owner_email, "Credential record deleted")
        return True
    return False


def reset_vault_data():
    """Administrator-only emergency purge; caller must authenticate first."""
    with get_db() as conn:
        result = conn.execute("DELETE FROM accounts")
    log_security_event("VAULT_PURGE", "SYSTEM", "Administrator executed emergency vault purge", severity="CRITICAL")
    return result.rowcount


# ------------------------------- Credit economy ----------------------------

def get_user_credits(email):
    with get_db() as conn:
        row = conn.execute(
            "SELECT ether_credits, status FROM users WHERE email=?",
            (email,),
        ).fetchone()
    return int(row[0]) if row and row[1] == "active" else 0


def use_credit(email):
    with get_db() as conn:
        result = conn.execute(
            "UPDATE users SET ether_credits=ether_credits-1 WHERE email=? AND ether_credits>0 AND status='active'",
            (email,),
        )
    if result.rowcount:
        log_security_event("CREDIT_CONSUMED", email, "One Ether-Credit consumed")
        return True
    return False


def refund_credit(email):
    """Restore one credit when the associated Oracle archive fails."""
    with get_db() as conn:
        result = conn.execute(
            "UPDATE users SET ether_credits=ether_credits+1 WHERE email=? AND status='active'",
            (email,),
        )
    if result.rowcount:
        log_security_event("CREDIT_REFUNDED", email, "One Ether-Credit restored after an unsuccessful archive")
        return True
    return False


def grant_gems(email, gem_count):
    if isinstance(gem_count, bool) or not isinstance(gem_count, int) or not 1 <= gem_count <= 10000:
        return False
    with get_db() as conn:
        result = conn.execute(
            "UPDATE users SET ether_credits=ether_credits+? WHERE email=? AND status='active'",
            (gem_count, email),
        )
    if result.rowcount:
        log_security_event("CREDIT_GRANTED", email, f"{gem_count} Ether-Credits granted by administrator")
        return True
    return False


# ------------------------------- Payment ledger ----------------------------

def log_transaction(email, amount, status="PENDING", image_path=None, sentinel_result=None):
    """Persist screenshot and optional AI advisory; manual Warden review is mandatory."""
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 10 or amount > 100000 or amount % 10 != 0:
        raise ValueError("Transaction amount must be a multiple of 10 from 10 to 100000 INR.")

    advisory = sentinel_result if isinstance(sentinel_result, dict) else {}
    allowed = {"VERIFIED", "SUSPICIOUS", "UNREADABLE", "PENDING_ADMIN_REVIEW"}
    verdict = advisory.get("verdict")
    if not isinstance(verdict, str) or verdict not in allowed:
        verdict = "PENDING_ADMIN_REVIEW"
    try:
        confidence = float(advisory.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    if confidence != confidence or confidence in (float("inf"), float("-inf")):
        confidence = 0.0
    confidence = min(1.0, max(0.0, confidence))
    amount_detected = str(advisory.get("amount_detected", "N/A"))[:80]
    findings = ""
    if isinstance(advisory.get("findings"), list):
        findings = "\n".join(
            str(item).strip()[:180]
            for item in advisory["findings"][:5]
            if isinstance(item, (str, int, float)) and str(item).strip()
        )
    recipient = advisory.get("recipient_match")
    recipient_match = int(recipient) if isinstance(recipient, bool) else None
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO transactions "
            "(user_email, amount, timestamp, status, image_path, ai_verdict, ai_confidence, "
            "ai_findings, ai_amount_detected, ai_recipient_match) "
            "SELECT ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ? "
            "WHERE EXISTS (SELECT 1 FROM users WHERE email=? AND status='active')",
            (
                email, amount, now, image_path, verdict, confidence, findings,
                amount_detected, recipient_match, email,
            ),
        )
        if cursor.rowcount != 1:
            raise PermissionError("This identity is suspended or no longer active.")
        transaction_id = cursor.lastrowid
    log_security_event("CREDIT_PURCHASE", email, f"Payment submitted for manual review: INR {amount}")
    return transaction_id

def get_pending_transactions():
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM transactions WHERE status='PENDING' ORDER BY id DESC"
        ).fetchall()


def approve_transaction(t_id):
    """Atomically transition a pending payment and grant credits exactly once."""
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT t.user_email, t.amount, u.status FROM transactions AS t "
                "JOIN users AS u ON u.email=t.user_email "
                "WHERE t.id=? AND t.status='PENDING'",
                (t_id,),
            ).fetchone()
            if not row or row[2] != "active":
                return False
            email, amount = row[0], row[1]
            if not isinstance(amount, int) or amount < 10:
                return False
            changed = conn.execute(
                "UPDATE transactions SET status='APPROVED', verified_at=? WHERE id=? AND status='PENDING'",
                (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), t_id),
            )
            if changed.rowcount != 1:
                return False
            credits = amount // 10
            credit_update = conn.execute(
                "UPDATE users SET ether_credits=ether_credits+? WHERE email=? AND status='active'",
                (credits, email),
            )
            if credit_update.rowcount != 1:
                raise sqlite3.IntegrityError("Transaction owner no longer exists")
        log_security_event("TRANSACTION_APPROVED", None, f"Transaction {t_id} approved; credits granted")
        return True
    except sqlite3.Error:
        return False


def reject_transaction(t_id):
    with get_db() as conn:
        result = conn.execute(
            "UPDATE transactions SET status='REJECTED', verified_at=? WHERE id=? AND status='PENDING'",
            (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), t_id),
        )
    if result.rowcount:
        log_security_event("TRANSACTION_REJECTED", None, f"Transaction {t_id} rejected", severity="WARNING")
        return True
    return False


def clear_transaction_image_path(transaction_id):
    """Forget a screenshot path after the UI removes the underlying file."""
    with get_db() as conn:
        conn.execute("UPDATE transactions SET image_path=NULL WHERE id=?", (transaction_id,))


def cleanup_expired_screenshots(upload_dir, retention_days=30):
    """Delete expired ledger screenshots and aged orphan uploads safely.

    The ledger may no longer contain a screenshot path after an identity purge.
    A second bounded directory sweep therefore removes old, unreferenced image
    files as well. Resolved paths must remain inside the configured directory.
    """
    if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 1:
        retention_days = 30
    cutoff = datetime.datetime.now() - datetime.timedelta(days=retention_days)
    cutoff_timestamp = cutoff.timestamp()
    base_dir = Path(upload_dir).resolve()
    deleted = 0
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, image_path FROM transactions WHERE image_path IS NOT NULL"
        ).fetchall()
        for transaction_id, timestamp, image_path in rows:
            try:
                created = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                candidate = Path(image_path)
                if not candidate.is_absolute():
                    candidate = (PROJECT_DIR / candidate).resolve()
                else:
                    candidate = candidate.resolve()
                if created < cutoff and candidate.is_relative_to(base_dir):
                    candidate.unlink(missing_ok=True)
                    conn.execute("UPDATE transactions SET image_path=NULL WHERE id=?", (transaction_id,))
                    deleted += 1
            except (OSError, ValueError, TypeError):
                continue

        # Clean old uploads that became unreferenced when a transaction or
        # identity record was deleted before the normal retention sweep.
        if base_dir.is_dir():
            for candidate in base_dir.iterdir():
                try:
                    resolved = candidate.resolve()
                    if (
                        candidate.is_file()
                        and resolved.is_relative_to(base_dir)
                        and candidate.suffix.lower() in {".jpg", ".jpeg", ".png"}
                        and candidate.stat().st_mtime < cutoff_timestamp
                    ):
                        candidate.unlink(missing_ok=True)
                        deleted += 1
                except (OSError, ValueError):
                    continue
    return deleted


# ---------------------------- Forensic event log --------------------------

def log_security_event(event_type, target_email, details, severity="INFO", source_ip=None):
    try:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        safe_type = str(event_type)[:64]
        safe_details = str(details)[:500]
        safe_severity = severity if severity in {"INFO", "WARNING", "CRITICAL"} else "INFO"
        with get_db() as conn:
            conn.execute(
                "INSERT INTO security_events (timestamp, event_type, target_email, details, severity, source_ip) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, safe_type, target_email, safe_details, safe_severity, source_ip),
            )
    except Exception:
        # Audit logging must not prevent the primary operation from completing.
        return False
    return True


def get_security_events(limit=100, event_filter=None, email_filter=None):
    safe_limit = min(500, max(1, int(limit)))
    query = "SELECT id, timestamp, event_type, target_email, details, severity FROM security_events"
    conditions = []
    params = []
    if event_filter:
        conditions.append("event_type=?")
        params.append(str(event_filter)[:64])
    if email_filter:
        conditions.append("target_email LIKE ?")
        params.append(f"%{str(email_filter)[:254]}%")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(safe_limit)
    with get_db() as conn:
        return conn.execute(query, params).fetchall()


def get_dashboard_stats():
    with get_db() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active_users = conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
        total_shards = conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        threat_events = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE severity IN ('WARNING','CRITICAL')"
        ).fetchone()[0]
        pending_transactions = conn.execute(
            "SELECT COUNT(*) FROM transactions WHERE status='PENDING'"
        ).fetchone()[0]
    return {
        "total_identities": total_users,
        "active_identities": active_users,
        "total_shards": total_shards,
        "threat_events": threat_events,
        "pending_transactions": pending_transactions,
    }