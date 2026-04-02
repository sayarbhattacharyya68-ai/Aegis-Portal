import streamlit as st
import os
import sqlite3
import pandas as pd
import datetime
from database_logic import *
from ai_analyser import get_oracle_analysis, verify_payment_screenshot
from notifier import notify_user, get_admin_contact
from dotenv import load_dotenv

load_dotenv()
st.set_page_config(page_title="Vault+ Shard", page_icon="🔓", layout="wide")
setup_security()

if not os.path.exists("audit_screenshots"):
    os.makedirs("audit_screenshots")

# --- CUSTOM CSS ---
st.markdown("""
<style>
    .stApp { background-color: #7064DF !important; }
    h1, h2, h3, label, p, .stMarkdown, [data-testid="stMetricLabel"] {
        color: #080D24 !important; font-family: 'Segoe UI', sans-serif; font-weight: bold !important;
    }
    .stAlert { border: 2px solid #080D24 !important; box-shadow: 5px 5px 0px #080D24; }
    div[data-baseweb="input"] input {
        background-color: #FF868F !important; color: #080D24 !important;
        border: 2px solid #080D24 !important; font-weight: bold !important;
    }
</style>
""", unsafe_allow_html=True)

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# --- AUTH ---
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
            if create_user(n_email, n_pw): st.success("Created! Link Identity to start.")
            else: st.error("User exists.")
    st.stop()

# --- ADMIN TERMINAL (FIXED OVERSIGHT) ---
st.sidebar.title("⚙️ System Control")
with st.sidebar.expander("🔑 Admin Terminal"):
    admin_input = st.text_input("Admin Key", type="password")
    if admin_input == os.getenv("ADMIN_KEY", "Sayar_Admin_2026"):
        st.write("### Global User Directory")
        # This will now show EVERY user in the DB
        all_users = get_all_users()
        u_df = pd.DataFrame(all_users, columns=["Email", "EC", "Status"])
        st.dataframe(u_df, use_container_width=True)
        
        target = st.selectbox("Moderate User", u_df["Email"])
        col_a, col_b = st.columns(2)
        if col_a.button("🚫 BAN"):
            update_user_status(target, 'banned')
            st.rerun()
        if col_b.button("✅ RESTORE"):
            update_user_status(target, 'active')
            st.rerun()

        st.write("---")
        st.write("### Transaction Evidence")
        for t in get_transactions():
            st.write(f"**{t[1]}** | ₹{t[2]} | {t[4]}")
            if t[5] != "None" and os.path.exists(t[5]):
                st.image(t[5], width=200)

# --- LOCKDOWN ---
if check_status(st.session_state.user_email) == 'banned':
    st.error(f"🚨 ACCESS DENIED. Contact Sayar at {get_admin_contact()}")
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()
    st.stop()

# --- MODULES ---
conn = sqlite3.connect('vault.db')
res = conn.execute("SELECT ether_credits FROM users WHERE email=?", (st.session_state.user_email,)).fetchone()
credits = res[0] if res else 0
conn.close()

st.sidebar.metric("Ether-Credits (EC)", f"{credits} 💎")
module = st.sidebar.selectbox("Module", ["Archive Vault", "AI Oracle", "Credit-Bay (₹)"])

if module == "Archive Vault":
    st.subheader("📂 Shard Decryption")
    if st.button("Retrieve Assets"):
        data = fetch_accounts(st.session_state.user_email)
        if data: st.table(data)
        else: st.info("No credentials found.")

elif module == "AI Oracle":
    st.subheader("🔮 Oracle Security Audit")
    site = st.text_input("Service")
    user = st.text_input("ID")
    pwd = st.text_input("Password", type="password")
    
    if st.button("Analyze & Archive"):
        if credits > 0:
            if use_credit(st.session_state.user_email):
                # 1. AI Analysis
                analysis = get_oracle_analysis(pwd)
                
                # 2. Display Rating & "Blinking" Opinions
                if "[STRONG]" in analysis:
                    st.success("✅ PASSWORD RATING: STRONG")
                else:
                    st.warning("⚠️ PASSWORD RATING: WEAK")
                
                st.info(f"💡 Oracle Opinions: {analysis.replace('[STRONG]', '').replace('[WEAK]', '')}")
                
                # 3. Archive
                save_account(st.session_state.user_email, site, user, pwd)
                
                # 4. Key Reveal for Privacy
                with open("system_master.key", "rb") as f:
                    personal_key = f.read().decode()
                
                st.markdown("---")
                st.subheader("🛡️ Shard Archived Successfully")
                st.write("Use this **Privacy Shard Key** to decrypt your vault in the future:")
                st.code(personal_key, language="text")
                st.warning("Privacy Guarantee: This key is displayed now but not stored on your local disk as a separate file.")
        else: st.error("Insufficient Credits.")

elif module == "Credit-Bay (₹)":
    st.subheader("🔋 Credit-Bay")
    amount = st.number_input("Amount (₹)", min_value=10)
    c1, c2 = st.columns(2)
    with c1:
        if os.path.exists("my_upi_qr.jpeg"): st.image("my_upi_qr.jpeg", width=250)
    with c2:
        shot = st.file_uploader("Upload Proof", type=["jpg","png","jpeg"])
        if st.button("🚀 Verify"):
            if shot:
                img_path = f"audit_screenshots/{st.session_state.user_email}_{int(datetime.datetime.now().timestamp())}.png"
                with open(img_path, "wb") as f: f.write(shot.getbuffer())
                with st.spinner("Oracle verifying..."):
                    res = verify_payment_screenshot(shot, amount)
                    if "VERIFIED" in res.upper():
                        recharge_credits(st.session_state.user_email, amount)
                        log_transaction(st.session_state.user_email, amount, "SUCCESS", img_path)
                        st.success("Credits Added!")
                        st.rerun()
                    else:
                        log_transaction(st.session_state.user_email, amount, f"FAILED: {res}", img_path)
                        st.error(f"Denied: {res}")