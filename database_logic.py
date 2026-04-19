"""
╔══════════════════════════════════════════════════════════════╗
║  AEGIS-PORTAL: PERSISTENCE ENGINE                           ║
║  database_logic.py — Zero-Knowledge Encrypted Vault         ║
║                                                              ║
║  All cryptographic operations use user-provided session      ║
║  keys. The server NEVER stores plaintext master keys.        ║
╚══════════════════════════════════════════════════════════════╝
"""

import sqlite3
import os
import bcrypt
import datetime
from contextlib import contextmanager
from cryptography.fernet import Fernet, InvalidToken

# ─────────────────────────────────────────────
#  CONNECTION MANAGER
# ─────────────────────────────────────────────

DB_PATH = "vault.db"

@contextmanager
def get_db():
    """Thread-safe connection context manager. Prevents connection leaks."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# ─────────────────────────────────────────────
#  SCHEMA INITIALIZATION & MIGRATION
# ─────────────────────────────────────────────

def setup_security():
    """Initialize all database tables with schema migration support."""
    with get_db() as conn:
        cursor = conn.cursor()

        # ── Users Table ──
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            hashed_pw TEXT NOT NULL,
            ether_credits INTEGER DEFAULT 5,
            last_login TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'active'
        )''')

        # ── Schema migration: add missing columns ──
        cursor.execute("PRAGMA table_info(users)")
        existing_cols = {col[1] for col in cursor.fetchall()}
        if "last_seen" not in existing_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN last_seen TEXT")
        if "status" not in existing_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")

        # ── Accounts Table (Encrypted Shards) ──
        cursor.execute('''CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_email TEXT NOT NULL,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_email) REFERENCES users(email)
        )''')

        # ── Transactions Table (Credit-Bay Ledger) ──
        cursor.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            amount INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            image_path TEXT,
            verified_by TEXT,
            verified_at TEXT,
            FOREIGN KEY (user_email) REFERENCES users(email)
        )''')

        # ── Security Events Table (Forensic Audit Trail) ──
        cursor.execute('''CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            target_email TEXT,
            details TEXT,
            severity TEXT DEFAULT 'INFO',
            source_ip TEXT
        )''')

# ─────────────────────────────────────────────
#  IDENTITY AUTHENTICATION
# ─────────────────────────────────────────────

def create_user(email, password):
    """Generate a new Identity Shard in the system."""
    try:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (email, hashed_pw, ether_credits, last_login, last_seen, status) "
                "VALUES (?, ?, 5, ?, ?, 'active')",
                (email, hashed, now, now)
            )
        log_security_event("IDENTITY_CREATED", email, "New identity shard forged in the system")
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception:
        return False


def authenticate_user(email, password):
    """Verify an Identity Shard against the encrypted vault."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_pw, status FROM users WHERE email=?", (email,))
        row = cursor.fetchone()

    if row and bcrypt.checkpw(password.encode(), row[0]):
        update_heartbeat(email)
        log_security_event("AUTH_SUCCESS", email, "Identity shard successfully synchronized")
        return row[1]  # Returns 'active' or 'banned'
    
    if row:
        log_security_event("AUTH_FAILURE", email, "Invalid cipher presented — access denied", severity="WARNING")
    else:
        log_security_event("AUTH_FAILURE", email, "Unknown identity attempted connection", severity="WARNING")
    return None


def check_status(email):
    """Check the current standing of an identity shard."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
    return row[0] if row else "banned"


def update_user_status(email, new_status):
    """Update the standing of an identity shard (active/banned)."""
    with get_db() as conn:
        conn.execute("UPDATE users SET status = ? WHERE email = ?", (new_status, email))
    
    event_type = "IDENTITY_BANNED" if new_status == "banned" else "IDENTITY_RESTORED"
    severity = "CRITICAL" if new_status == "banned" else "INFO"
    log_security_event(event_type, email, f"Identity standing changed to: {new_status}", severity=severity)

# ─────────────────────────────────────────────
#  HEARTBEAT & PRESENCE
# ─────────────────────────────────────────────

def update_heartbeat(email):
    """Update the last-seen timestamp for presence detection."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute("UPDATE users SET last_seen = ? WHERE email = ?", (now, email))


def get_all_users():
    """Retrieve all identity shards with presence indicators."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT email, ether_credits, status, last_seen FROM users")
        rows = cursor.fetchall()

    processed_users = []
    now = datetime.datetime.now()
    for r in rows:
        email, credits, status, last_seen = r
        presence = "Offline ⚪"
        if last_seen:
            try:
                ls_time = datetime.datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                if (now - ls_time).total_seconds() < 120:
                    presence = "Online 🟢"
            except (ValueError, TypeError):
                pass
        processed_users.append((email, credits, status, presence))
    return processed_users

# ─────────────────────────────────────────────
#  ENCRYPTED SHARD VAULT (ZERO-KNOWLEDGE)
# ─────────────────────────────────────────────

def save_account(owner, site, user, pwd, user_key):
    """Encrypt and store a credential shard. Key is NEVER persisted."""
    cipher = Fernet(user_key.encode())
    enc_pwd = cipher.encrypt(pwd.encode()).decode()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO accounts (owner_email, site, username, password) VALUES (?, ?, ?, ?)",
            (owner, site, user, enc_pwd)
        )
    log_security_event("VAULT_WRITE", owner, f"New shard archived for service: {site}")


def fetch_accounts(owner, user_provided_key):
    """Decrypt and retrieve all shards for an identity. Returns None on key mismatch."""
    try:
        cipher = Fernet(user_provided_key.encode())
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, site, username, password FROM accounts WHERE owner_email=?",
                (owner,)
            )
            rows = cursor.fetchall()

        decrypted_data = []
        for r in rows:
            try:
                decrypted_pwd = cipher.decrypt(r[3].encode()).decode()
                decrypted_data.append({
                    "id": r[0], "Site": r[1], "User": r[2], "Password": decrypted_pwd
                })
            except InvalidToken:
                # This shard was encrypted with a different key — skip it
                continue
        
        if not decrypted_data and rows:
            # All shards failed to decrypt — wrong key entirely
            log_security_event("VAULT_ACCESS_DENIED", owner, 
                             "Invalid shard key presented — zero decryptions successful", severity="WARNING")
            return None
        
        log_security_event("VAULT_ACCESS", owner, f"Shard vault accessed — {len(decrypted_data)} entries decrypted")
        return decrypted_data
    except Exception:
        return None


def update_account(account_id, new_user, new_pwd, user_key):
    """Re-encrypt and update a specific shard."""
    try:
        cipher = Fernet(user_key.encode())
        enc_pwd = cipher.encrypt(new_pwd.encode()).decode()
        with get_db() as conn:
            conn.execute(
                "UPDATE accounts SET username = ?, password = ? WHERE id = ?",
                (new_user, enc_pwd, account_id)
            )
        return True
    except Exception:
        return False


def delete_account(account_id):
    """Permanently destroy a credential shard."""
    with get_db() as conn:
        conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    log_security_event("VAULT_DELETE", None, f"Shard #{account_id} permanently destroyed")


def reset_vault_data():
    """Emergency protocol: Wipe all credential shards from the vault."""
    with get_db() as conn:
        conn.execute("DELETE FROM accounts")
    log_security_event("VAULT_PURGE", None, "Emergency vault purge executed — all shards destroyed", severity="CRITICAL")

# ─────────────────────────────────────────────
#  ETHER-CREDIT ECONOMY
# ─────────────────────────────────────────────

def get_user_credits(email):
    """Retrieve the current Ether-Credit balance for an identity."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ether_credits FROM users WHERE email=?", (email,))
        res = cursor.fetchone()
    return res[0] if res else 0


def use_credit(email):
    """Consume one Ether-Credit for an Oracle consultation."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET ether_credits = ether_credits - 1 WHERE email=? AND ether_credits > 0",
            (email,)
        )
        if cursor.rowcount > 0:
            log_security_event("CREDIT_CONSUMED", email, "1 Ether-Credit consumed for Oracle consultation")
            return True
        return False


def grant_gems(email, gem_count):
    """Admin action: Grant Ether-Credits to an identity."""
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET ether_credits = ether_credits + ? WHERE email = ?",
            (gem_count, email)
        )
    log_security_event("CREDIT_GRANTED", email, f"{gem_count} Ether-Credits granted by administrator", severity="INFO")

# ─────────────────────────────────────────────
#  TRANSACTION LEDGER (CREDIT-BAY)
# ─────────────────────────────────────────────

def log_transaction(email, amount, status, image_path):
    """Record a Credit-Bay transaction for audit."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO transactions (user_email, amount, timestamp, status, image_path) "
            "VALUES (?, ?, ?, ?, ?)",
            (email, amount, now, status, image_path)
        )
    log_security_event("CREDIT_PURCHASE", email, f"Transaction shard submitted: ₹{amount} — Status: {status}")


def get_pending_transactions():
    """Retrieve all transactions awaiting admin verification."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM transactions WHERE status = 'PENDING' ORDER BY id DESC")
        rows = cursor.fetchall()
    return rows


def approve_transaction(t_id):
    """Admin action: Approve a transaction and grant corresponding Ether-Credits."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_email, amount FROM transactions WHERE id = ?", (t_id,))
        row = cursor.fetchone()
        if row:
            email, amount = row
            gems_to_add = amount // 10
            cursor.execute(
                "UPDATE users SET ether_credits = ether_credits + ? WHERE email = ?",
                (gems_to_add, email)
            )
            cursor.execute(
                "UPDATE transactions SET status = 'APPROVED', verified_at = ? WHERE id = ?",
                (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), t_id)
            )
    log_security_event("TRANSACTION_APPROVED", None, f"Transaction #{t_id} approved — credits dispensed")


def reject_transaction(t_id):
    """Admin action: Reject a fraudulent or invalid transaction."""
    with get_db() as conn:
        conn.execute(
            "UPDATE transactions SET status = 'REJECTED', verified_at = ? WHERE id = ?",
            (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), t_id)
        )
    log_security_event("TRANSACTION_REJECTED", None, f"Transaction #{t_id} rejected", severity="WARNING")

# ─────────────────────────────────────────────
#  SECURITY EVENT LOGGING (FORENSIC TRAIL)
# ─────────────────────────────────────────────

def log_security_event(event_type, target_email, details, severity="INFO", source_ip=None):
    """Record a forensic security event to the audit trail."""
    try:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO security_events (timestamp, event_type, target_email, details, severity, source_ip) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, event_type, target_email, details, severity, source_ip)
            )
    except Exception:
        # Logging should never crash the application
        pass


def get_security_events(limit=100, event_filter=None, email_filter=None):
    """Retrieve security events for the Admin Terminal forensic display."""
    with get_db() as conn:
        cursor = conn.cursor()
        query = "SELECT id, timestamp, event_type, target_email, details, severity FROM security_events"
        conditions = []
        params = []

        if event_filter:
            conditions.append("event_type = ?")
            params.append(event_filter)
        if email_filter:
            conditions.append("target_email LIKE ?")
            params.append(f"%{email_filter}%")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        return cursor.fetchall()


def get_dashboard_stats():
    """Aggregate statistics for the Command Center dashboard."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
        active_users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM accounts")
        total_shards = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM security_events WHERE severity IN ('WARNING', 'CRITICAL')")
        threat_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM transactions WHERE status = 'PENDING'")
        pending_tx = cursor.fetchone()[0]

    return {
        "total_identities": total_users,
        "active_identities": active_users,
        "total_shards": total_shards,
        "threat_events": threat_events,
        "pending_transactions": pending_tx
    }
