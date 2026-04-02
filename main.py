import streamlit as st
import os
import sqlite3
import pandas as pd
import datetime
from cryptography.fernet import Fernet
from database_logic import *
from ai_analyser import get_oracle_analysis
from notifier import notify_user, get_admin_contact
from dotenv import load_dotenv

load_dotenv()
st.set_page_config(page_title="Vault+ Shard", page_icon="🔓", layout="wide")
setup_security()

# Create audit folder if missing
if not os.path.exists("audit_screenshots"):
    os.makedirs("audit_screenshots")

if "current_session_key" not in st.session_state:
    st.session_state.current_session_key = Fernet.generate_key().decode()

# --- CSS THEME ---
st.markdown("""
<style>
    .stApp { background-color: #7064DF !important; }
    h1, h2, h3, label, p, .stMarkdown, [data-testid="stMetricLabel"] {
        color: #080D24 !important; font-family: 'Segoe UI', sans-serif; font-weight: bold !important;
    }
</style>
""", unsafe_allow_html=True)

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# --- LOGIN GATE ---
if not st.session_state.logged_in:
    st.title("🔓 Aegis-Portal Login")
    t1, t2 = st.tabs(["Link Identity", "New Shard"])
    with t1:
        email = st.text_input("Email ID")
        pw = st.text_input("Access Cipher", type="password")
        if st.button("Establish Connection"):
            status = authenticate_user(email, pw)
            if status == 'active':
                st.session_state.logged_in = True
                st.session_state.user_email = email
                st.rerun()
            elif status == 'banned':
                st.error(f"🚨 IDENTITY REVOKED. Contact Admin: {get_admin_contact()}")
            else: st.error("Verification Denied.")
    with t2:
        n_email = st.text_input("New Email ID")
        n_pw = st.text_input("New Access Cipher", type="password")
        if st.button("Generate Identity"):
            if create_user(n_email, n_pw): st.success("Created!")
            else: st.error("User exists.")
    st.stop()

# --- HEARTBEAT ---
update_heartbeat(st.session_state.user_email)

# --- SIDEBAR ---
st.sidebar.title("⚙️ System Control")

# Admin Terminal (User Management)
with st.sidebar.expander("🔑 Admin Terminal"):
    admin_input = st.text_input("Admin Key", type="password")
    is_admin = (admin_input == os.getenv("ADMIN_KEY", "Sayar_Admin_2026"))
    
    if is_admin:
        st.write("### Global Directory")
        all_users = get_all_users()
        u_df = pd.DataFrame(all_users, columns=["Email", "EC", "Status", "Presence"])
        st.dataframe(u_df, use_container_width=True)
        
        target = st.selectbox("Moderate User", u_df["Email"])
        if st.button("🚫 BAN USER"):
            update_user_status(target, 'banned'); st.rerun()
        if st.button("✅ RESTORE USER"):
            update_user_status(target, 'active'); st.rerun()

# NEW: Admin Evidence Audit Section (BEFORE Logout)
if is_admin:
    with st.sidebar.expander("📸 Audit Screenshots"):
        pending = get_pending_transactions()
        if not pending:
            st.write("No pending recharges.")
        for p in pending:
            st.write(f"**User:** {p[1]} (₹{p[2]})")
            if os.path.exists(p[5]):
                st.image(p[5], use_container_width=True)
            
            c1, c2 = st.columns(2)
            if c1.button(f"✅ OK #{p[0]}"):
                approve_transaction(p[0])
                st.success(f"Credits added to {p[1]}!")
                st.rerun()
            if c2.button(f"❌ Reject #{p[0]}"):
                reject_transaction(p[0])
                st.rerun()

# User Stats
conn = sqlite3.connect('vault.db')
res = conn.execute("SELECT ether_credits FROM users WHERE email=?", (st.session_state.user_email,)).fetchone()
credits = res[0] if res else 0
conn.close()

st.sidebar.metric("Ether-Credits (EC)", f"{credits} 💎")
module = st.sidebar.selectbox("Module", ["Archive Vault", "AI Oracle", "Credit-Bay (₹)"])

st.sidebar.write("---")
if st.sidebar.button("🔴 Terminate Session (Logout)"):
    st.session_state.logged_in = False
    st.session_state.user_email = None
    if "current_session_key" in st.session_state:
        del st.session_state["current_session_key"]
    st.rerun()

# --- MODULES ---
if module == "Archive Vault":
    st.subheader("📂 Shard Decryption")
    input_key = st.text_input("Enter Secret Shard Key", type="password")
    if st.button("Decrypt Shard"):
        if input_key:
            data = fetch_accounts(st.session_state.user_email, input_key)
            if data: st.table(data); notify_user("Shard Decrypted.", "success")
            else: st.error("🚨 INVALID KEY.")
        else: st.warning("Key required.")

elif module == "AI Oracle":
    st.subheader("🔮 Oracle Security Audit")
    site = st.text_input("Service")
    user = st.text_input("ID")
    pwd = st.text_input("Password", type="password")
    if st.button("Analyze & Archive"):
        if credits > 0:
            if use_credit(st.session_state.user_email):
                analysis = get_oracle_analysis(pwd)
                st.info(f"💡 Oracle Opinions: {analysis}")
                save_account(st.session_state.user_email, site, user, pwd, st.session_state.current_session_key)
                st.subheader("🛡️ Shard Archived")
                st.code(st.session_state.current_session_key)
        else: st.error("No Credits.")

elif module == "Credit-Bay (₹)":
    st.subheader("🔋 Credit-Bay")
    amount = st.number_input("Amount (₹)", min_value=10)
    c1, c2 = st.columns(2)
    with c1:
        if os.path.exists("my_upi_qr.jpeg"): st.image("my_upi_qr.jpeg", width=250)
    with c2:
        shot = st.file_uploader("Upload Payment Screenshot", type=["jpg","png","jpeg"])
        if st.button("🚀 Submit for Verification"):
            if shot:
                img_path = f"audit_screenshots/{st.session_state.user_email}_{int(datetime.datetime.now().timestamp())}.png"
                with open(img_path, "wb") as f: f.write(shot.getbuffer())
                # LOG AS PENDING - Wait for Admin
                log_transaction(st.session_state.user_email, amount, "PENDING", img_path)
                st.success("Screenshot submitted! Waiting for Admin verification.")
            else: st.error("Please upload a file.")
