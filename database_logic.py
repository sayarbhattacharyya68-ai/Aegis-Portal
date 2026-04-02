import sqlite3
import os
import bcrypt
import datetime
from cryptography.fernet import Fernet

def setup_security():
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    # Added last_seen column to track activity
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (email TEXT PRIMARY KEY, hashed_pw TEXT, 
                       ether_credits INTEGER DEFAULT 5, last_login TEXT, 
                       last_seen TEXT, status TEXT DEFAULT 'active')''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_email TEXT, 
                       site TEXT, username TEXT, password TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS transactions 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, user_email TEXT, 
                       amount INTEGER, timestamp TEXT, status TEXT, image_path TEXT)''')
    conn.commit()
    conn.close()

def update_heartbeat(email):
    """Updates the last_seen timestamp to the current time."""
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE users SET last_seen = ? WHERE email = ?", (now, email))
    conn.commit()
    conn.close()

def get_all_users():
    """Fetches users and calculates online/offline status."""
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT email, ether_credits, status, last_seen FROM users")
    rows = cursor.fetchall()
    conn.close()
    
    processed_users = []
    now = datetime.datetime.now()
    for r in rows:
        email, credits, status, last_seen = r
        is_online = "Offline"
        if last_seen:
            ls_time = datetime.datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
            # If active in the last 120 seconds, they are Online
            if (now - ls_time).total_seconds() < 120:
                is_online = "Online 🟢"
            else:
                is_online = "Offline ⚪"
        processed_users.append((email, credits, status, is_online))
    return processed_users

def log_transaction(email, amount, status, image_path="None"):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("INSERT INTO transactions (user_email, amount, timestamp, status, image_path) VALUES (?, ?, ?, ?, ?)", 
                 (email, amount, now, status, image_path))
    conn.commit()
    conn.close()

def get_transactions():
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def authenticate_user(email, password):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_pw, status FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()
    if row and bcrypt.checkpw(password.encode(), row[0]):
        update_heartbeat(email) # Initial pulse on login
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

def recharge_credits(email, amount):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET ether_credits = ether_credits + ? WHERE email=?", (amount, email))
    conn.commit()
    conn.close()

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
    except Exception:
        return None
