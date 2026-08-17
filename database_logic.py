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
import datetime
import bcrypt
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from contextlib import contextmanager

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

        # ── Schema migration: add missing columns in users table ──
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
            salt TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_email) REFERENCES users(email)
        )''')

        # ── Schema migration: add salt column in accounts table if missing ──
        cursor.execute("PRAGMA table_info(accounts)")
        existing_acc_cols = {col[1] for col in cursor.fetchall()}
        if "salt" not in existing_acc_cols:
            cursor.execute("ALTER TABLE accounts ADD COLUMN salt TEXT")

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
    """Admin function: Updates a user's standing (active, warned, lockdown) or completely purges them (banned)."""
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            if new_status == 'banned':
                # The BAN Protocol: Total Data Destruction
                c.execute("DELETE FROM accounts WHERE owner_email = ?", (email,))
                c.execute("DELETE FROM transactions WHERE user_email = ?", (email,))
                c.execute("DELETE FROM security_events WHERE target_email = ?", (email,))
                c.execute("DELETE FROM users WHERE email = ?", (email,))
                conn.commit()
                # Log the ban event as a system event since the user no longer exists
                log_security_event("IDENTITY_PURGED", "SYSTEM", f"Administrator completely purged identity: {email}", severity="CRITICAL")
                return True
                
            # Otherwise, just update the status
            c.execute("UPDATE users SET status = ? WHERE email = ?", (new_status, email))
            conn.commit()
            
            if new_status == 'lockdown':
                log_security_event("LOCKDOWN_ENGAGED", email, "Administrator engaged identity lockdown", severity="CRITICAL")
            elif new_status == 'warned':
                log_security_event("WARNING_ISSUED", email, "Administrator issued formal warning", severity="WARNING")
            elif new_status == 'active':
                log_security_event("IDENTITY_RESTORED", email, "Administrator restored identity to nominal status", severity="INFO")
                
            return True
    except sqlite3.Error as e:
        print(f"Error updating user status: {e}")
        return False

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

def get_fernet_key(user_password, salt_input):
    """Derive a valid 32-byte Fernet key from a human-readable password using PBKDF2."""
    salt_bytes = salt_input.encode() if isinstance(salt_input, str) else salt_input
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(user_password.encode()))


def save_account(owner, site, user, pwd, user_provided_key):
    """Encrypt and store a credential shard using a unique 16-byte random salt. Key is NEVER persisted."""
    raw_salt = os.urandom(16)
    fernet_key = get_fernet_key(user_provided_key, raw_salt)
    cipher = Fernet(fernet_key)
    enc_site = cipher.encrypt(site.encode()).decode()
    enc_user = cipher.encrypt(user.encode()).decode()
    enc_pwd = cipher.encrypt(pwd.encode()).decode()
    b64_salt = base64.b64encode(raw_salt).decode()
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO accounts (owner_email, site, username, password, salt) VALUES (?, ?, ?, ?, ?)",
            (owner, enc_site, enc_user, enc_pwd, b64_salt)
        )
    log_security_event("VAULT_WRITE", owner, f"New shard archived for service: {site}")


def fetch_accounts(owner, user_provided_key):
    """Decrypt and retrieve all shards for an identity using each shard's stored salt. Returns None on key mismatch."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, site, username, password, salt FROM accounts WHERE owner_email=?",
                (owner,)
            )
            rows = cursor.fetchall()

        decrypted_data = []
        for r in rows:
            try:
                # Use stored random salt if available; fallback to owner email for legacy entries
                if len(r) > 4 and r[4]:
                    salt_bytes = base64.b64decode(r[4].encode())
                else:
                    salt_bytes = owner.encode()

                fernet_key = get_fernet_key(user_provided_key, salt_bytes)
                cipher = Fernet(fernet_key)

                # Decrypt site and username (fallback to raw string for legacy unencrypted records)
                try:
                    decrypted_site = cipher.decrypt(r[1].encode()).decode()
                except Exception:
                    decrypted_site = r[1]

                try:
                    decrypted_user = cipher.decrypt(r[2].encode()).decode()
                except Exception:
                    decrypted_user = r[2]

                decrypted_pwd = cipher.decrypt(r[3].encode()).decode()

                decrypted_data.append({
                    "id": r[0], "Site": decrypted_site, "User": decrypted_user, "Password": decrypted_pwd
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


def update_account(account_id, new_username, new_password, user_provided_key):
    """Re-encrypt and update an existing shard with a fresh random salt."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT owner_email, site, salt FROM accounts WHERE id=?", (account_id,))
        row = cursor.fetchone()
        if not row:
            return False
            
        owner, old_enc_site, old_salt_b64 = row[0], row[1], row[2]

        if old_salt_b64:
            old_salt_bytes = base64.b64decode(old_salt_b64.encode())
        else:
            old_salt_bytes = owner.encode()

        old_fernet_key = get_fernet_key(user_provided_key, old_salt_bytes)
        old_cipher = Fernet(old_fernet_key)

        try:
            site_plain = old_cipher.decrypt(old_enc_site.encode()).decode()
        except Exception:
            site_plain = old_enc_site

        raw_salt = os.urandom(16)
        fernet_key = get_fernet_key(user_provided_key, raw_salt)
        cipher = Fernet(fernet_key)
        
        enc_site = cipher.encrypt(site_plain.encode()).decode()
        enc_user = cipher.encrypt(new_username.encode()).decode()
        enc_pwd = cipher.encrypt(new_password.encode()).decode()
        b64_salt = base64.b64encode(raw_salt).decode()
        
        cursor.execute(
            "UPDATE accounts SET site=?, username=?, password=?, salt=? WHERE id=?",
            (enc_site, enc_user, enc_pwd, b64_salt, account_id)
        )
    log_security_event("VAULT_WRITE", row[0], "Shard parameters updated")
    return True


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
        cursor.execute("SELECT * FROM transactions WHERE status NOT IN ('APPROVED', 'REJECTED') ORDER BY id DESC")
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

        cursor.execute("SELECT COUNT(*) FROM transactions WHERE status NOT IN ('APPROVED', 'REJECTED')")
        pending_tx = cursor.fetchone()[0]

    return {
        "total_identities": total_users,
        "active_identities": active_users,
        "total_shards": total_shards,
        "threat_events": threat_events,
        "pending_transactions": pending_tx
    }