import sqlite3
import os
import bcrypt
import datetime
from cryptography.fernet import Fernet

def setup_security():
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Users Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (email TEXT PRIMARY KEY, hashed_pw TEXT, 
                       ether_credits INTEGER DEFAULT 5, last_login TEXT, 
                       last_seen TEXT, status TEXT DEFAULT 'active')''')
    
    # Schema Migration for last_seen
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    if "last_seen" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN last_seen TEXT")
    
    # Accounts Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_email TEXT, 
                       site TEXT, username TEXT, password TEXT)''')
    
    # Transactions Table (Now handles Manual Approval)
    cursor.execute('''CREATE TABLE IF NOT EXISTS transactions 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, user_email TEXT, 
                       amount INTEGER, timestamp TEXT, status TEXT, image_path TEXT)''')
    conn.commit()
    conn.close()

def log_transaction(email, amount, status, image_path):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("INSERT INTO transactions (user_email, amount, timestamp, status, image_path) VALUES (?, ?, ?, ?, ?)", 
                 (email, amount, now, status, image_path))
    conn.commit()
    conn.close()

def get_pending_transactions():
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions WHERE status = 'PENDING' ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def approve_transaction(t_id):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    # 1. Get transaction details
    cursor.execute("SELECT user_email, amount FROM transactions WHERE id = ?", (t_id,))
    row = cursor.fetchone()
    if row:
        email, amount = row
        # 2. Add Credits
        cursor.execute("UPDATE users SET ether_credits = ether_credits + ? WHERE email = ?", (amount, email))
        # 3. Mark as Success
        cursor.execute("UPDATE transactions SET status = 'SUCCESS' WHERE id = ?", (t_id,))
        conn.commit()
    conn.close()

def reject_transaction(t_id):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    conn.execute("UPDATE transactions SET status = 'REJECTED' WHERE id = ?", (t_id,))
    conn.commit()
    conn.close()

# --- PREVIOUS FUNCTIONS REMAINING THE SAME ---
def update_heartbeat(email):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE users SET last_seen = ? WHERE email = ?", (now, email))
    conn.commit()
    conn.close()

def get_all_users():
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT email, ether_credits, status, last_seen FROM users")
    rows = cursor.fetchall()
    conn.close()
    processed_users = []
    now = datetime.datetime.now()
    for r in rows:
        email, credits, status, last_seen = r
        presence = "Offline ⚪"
        if last_seen:
            try:
                ls_time = datetime.datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                if (now - ls_time).total_seconds() < 120: presence = "Online 🟢"
            except: pass
        processed_users.append((email, credits, status, presence))
    return processed_users

def authenticate_user(email, password):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_pw, status FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()
    if row and bcrypt.checkpw(password.encode(), row[0]):
        update_heartbeat(email)
        return row[1]
    return None

def check_status(email):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else "banned"

def update_user_status(email, new_status):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status = ? WHERE email = ?", (new_status, email))
    conn.commit()
    conn.close()

def create_user(email, password):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO users (email, hashed_pw, ether_credits, last_login, last_seen, status) VALUES (?, ?, 5, ?, ?, 'active')", 
                       (email, hashed, now, now))
        conn.commit()
        return True
    except: return False
    finally: conn.close()

def use_credit(email):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET ether_credits = ether_credits - 1 WHERE email=? AND ether_credits > 0", (email,))
    conn.commit()
    conn.close()
    return True

def save_account(owner, site, user, pwd, user_key):
    cipher = Fernet(user_key.encode())
    enc_pwd = cipher.encrypt(pwd.encode()).decode()
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO accounts (owner_email, site, username, password) VALUES (?, ?, ?, ?)", 
                   (owner, site, user, enc_pwd))
    conn.commit()
    conn.close()

def fetch_accounts(owner, user_provided_key):
    try:
        cipher = Fernet(user_provided_key.encode())
        conn = sqlite3.connect('vault.db', check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute("SELECT site, username, password FROM accounts WHERE owner_email=?", (owner,))
        rows = cursor.fetchall()
        conn.close()
        decrypted_data = []
        for r in rows:
            decrypted_pwd = cipher.decrypt(r[2].encode()).decode()
            decrypted_data.append({"Site": r[0], "User": r[1], "Decrypted Password": decrypted_pwd})
        return decrypted_data
    except Exception: return None
