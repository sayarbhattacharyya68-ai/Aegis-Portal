import sqlite3
import os
import bcrypt
import datetime
from cryptography.fernet import Fernet

def setup_security():
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (email TEXT PRIMARY KEY, 
                       hashed_pw TEXT, 
                       ether_credits INTEGER DEFAULT 5, 
                       last_login TEXT,
                       status TEXT DEFAULT 'active')''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts 
                      (id INTEGER PRIMARY KEY, 
                       owner_email TEXT, 
                       site TEXT, 
                       username TEXT, 
                       password TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS transactions 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       user_email TEXT, 
                       amount INTEGER, 
                       timestamp TEXT, 
                       status TEXT)''')
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f: f.write(key)
    conn.commit()
    conn.close()

def log_transaction(email, amount, status):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("INSERT INTO transactions (user_email, amount, timestamp, status) VALUES (?, ?, ?, ?)", 
                 (email, amount, now, status))
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

def get_all_users():
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT email, ether_credits, status FROM users")
    rows = cursor.fetchall()
    conn.close()
    return rows

def create_user(email, password):
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO users (email, hashed_pw, ether_credits, last_login, status) VALUES (?, ?, 5, ?, 'active')", 
                       (email, hashed, now))
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

def save_account(owner, site, user, pwd):
    with open("secret.key", "rb") as f: key = f.read()
    cipher = Fernet(key)
    enc_pwd = cipher.encrypt(pwd.encode()).decode()
    conn = sqlite3.connect('vault.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO accounts (owner_email, site, username, password) VALUES (?, ?, ?, ?)", 
                   (owner, site, user, enc_pwd))
    conn.commit()
    conn.close()

def fetch_accounts(owner, master_key):
    try:
        cipher = Fernet(master_key.encode())
        conn = sqlite3.connect('vault.db', check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute("SELECT site, username, password FROM accounts WHERE owner_email=?", (owner,))
        rows = cursor.fetchall()
        conn.close()
        return [{"Site": r[0], "User": r[1], "Decrypted": cipher.decrypt(r[2].encode()).decode()} for r in rows]
    except: return None