import streamlit as st
import os
import sqlite3
import pandas as pd
from PIL import Image
from database_logic import *
from ai_analyser import get_oracle_analysis, verify_payment_screenshot
from dotenv import load_dotenv

# Load env variables including ADMIN_KEY
load_dotenv()

st.set_page_config(page_title="Vault+ Shard", page_icon="🔓", layout="wide")
setup_security()

# --- THEME CSS ---
st.markdown("""
<style>
    .stApp { background-color: #7064DF !important; }
    h1, h2, h3, label, p, .stMarkdown, [data-testid="stMetricLabel"] {
        color: #080D24 !important; font-family: 'Segoe UI', sans-serif; font-weight: bold !important;
    }
    div[data-baseweb="input"] input {
        background-color: #FF868F !important; color: #080D24 !important;
        -webkit-text-fill-color: #080D24 !important; border: 2px solid #080D24 !important;
    }
    div.stButton > button:first-child {
        background-color: #66FFCC !important; color: #080D24 !important;
        border: 2px solid #080D24 !important; box-shadow: 4px 4px 0px #080D24;
    }
    [data-testid="stSidebar"] { background-color: #e6e9ff !important; }
</style>
""", unsafe_allow_html=True)

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# --- AUTHENTICATION GATE ---
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
                st.error("🚨 ACCESS REVOKED BY ADMIN.")
            else: st.error("Verification Denied.")
    with t2:
        n_email = st.text_input("New Email ID", key="reg")
        n_pw = st.text_input("New Access Cipher", type="password", key="regpw")
        if st.button("Generate Identity"):
            if create_user(n_email, n_pw): st.success("Created!")
            else: st.error("User already exists.")
    st.stop()

# --- SIDEBAR & SECURE ADMIN TERMINAL ---
st.sidebar.title("⚙️ System Control")

with st.sidebar.expander("🔑 Admin Terminal"):
    admin_input = st.text_input("Admin Key", type="password")
    # Pulling the key from environment variable
    CORRECT_ADMIN_KEY = os.getenv("ADMIN_KEY", "Sayar_Admin_2026") 
    
    if admin_input == CORRECT_ADMIN_KEY:
        st.write("### User Control")
        users_df = pd.DataFrame(get_all_users(), columns=["Email", "Credits", "Status"])
        st.dataframe(users_df)
        target = st.selectbox("Select User", users_df["Email"])
        if st.button("🚫 BAN USER"):
            update_user_status(target, 'banned')
            st.rerun()
        if st.button("✅ RESTORE USER"):
            update_user_status(target, 'active')
            st.rerun()
        st.write("---")
        st.write("### Transaction Audit")
        trans_df = pd.DataFrame(get_transactions(), columns=["ID", "Email", "Amount", "Time", "Status"])
        st.dataframe(trans_df)

# --- LOCKDOWN CHECK ---
if check_status(st.session_state.user_email) == 'banned':
    st.error("🚨 IDENTITY REVOKED. System Locked.")
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()
    st.stop()

# --- MAIN DASHBOARD ---
conn = sqlite3.connect('vault.db')
credits = conn.execute("SELECT ether_credits FROM users WHERE email=?", (st.session_state.user_email,)).fetchone()[0]
conn.close()

st.sidebar.metric("Ether-Credits (EC)", f"{credits} 💎")
if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.rerun()

module = st.sidebar.selectbox("Module", ["Archive Vault", "AI Oracle", "Credit-Bay (₹)"])

if module == "Archive Vault":
    st.subheader("📂 Shard Decryption")
    m_key = st.text_input("Master Cipher-Key", type="password")
    if st.button("Retrieve Assets"):
        data = fetch_accounts(st.session_state.user_email, m_key)
        if data: st.table(data)
        else: st.error("Invalid Key.")

elif module == "AI Oracle":
    st.subheader("🔮 Oracle Security Audit")
    site = st.text_input("Service")
    user = st.text_input("ID")
    pwd = st.text_input("Password", type="password")
    if st.button("Analyze & Archive"):
        if credits > 0:
            if use_credit(st.session_state.user_email):
                feedback = get_oracle_analysis(pwd)
                st.info(feedback)
                save_account(st.session_state.user_email, site, user, pwd)
                st.rerun()
        else: st.error("No Credits.")

elif module == "Credit-Bay (₹)":
    st.subheader("🔋 Credit-Bay")
    st.warning("**POLICY:** Providing fraudulent screenshots results in PERMANENT identity revocation.")
    amount = st.number_input("Recharge Amount (₹)", min_value=10)
    c1, c2 = st.columns(2)
    with c1:
        if os.path.exists("my_upi_qr.jpeg"):
            st.image("my_upi_qr.jpeg", caption="Scan to Pay Sayar", width=250)
    with c2:
        shot = st.file_uploader("Upload Payment Screenshot", type=["jpg","png","jpeg"])
        if st.button("🚀 Verify & Recharge"):
            if shot:
                with st.spinner("Oracle verifying..."):
                    res = verify_payment_screenshot(shot, amount)
                    if "VERIFIED" in res.upper():
                        recharge_credits(st.session_state.user_email, amount)
                        log_transaction(st.session_state.user_email, amount, "SUCCESS")
                        st.success("Credits Added!")
                        st.rerun()
                    else:
                        log_transaction(st.session_state.user_email, amount, f"FAILED: {res}")
                        st.error(f"Denied: {res}")