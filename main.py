"""
╔══════════════════════════════════════════════════════════════╗
║  AEGIS-PORTAL: PRIMARY UI ORCHESTRATOR                      ║
║  main.py — The Command Center (Glassmorphism Theme)          ║
║                                                              ║
║  Features: Mesh gradients, frosted glass UI, Z-axis depth,   ║
║  real-time security alerts, and full module orchestration.   ║
╚══════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import os
import pandas as pd
import datetime
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Import local modules
from database_logic import (
    setup_security, authenticate_user, create_user, get_all_users,
    update_heartbeat, get_user_credits, use_credit, save_account,
    fetch_accounts, update_account, delete_account, check_status,
    update_user_status, reset_vault_data, grant_gems, log_transaction,
    get_pending_transactions, approve_transaction, reject_transaction,
    get_security_events, get_dashboard_stats
)
from ai_analyser import (
    get_oracle_analysis, get_oracle_grade, verify_payment_screenshot,
    get_sentinel_verdict_display, warden_assess_identity, 
    warden_heartbeat_check, get_threat_level_display
)
from notifier import (
    notify, toast, notify_admin_action, security_alert, 
    trigger_lockdown, format_event_for_display, get_severity_color
)

# Load local environment variables (if any)
load_dotenv()

# ─────────────────────────────────────────────
#  1. CORE CONFIGURATION
# ─────────────────────────────────────────────

st.set_page_config(
    page_title="Aegis-Portal | Command Center", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject PWA Manifest & Service Worker
st.markdown("""
    <link rel="manifest" href="/app/static/manifest.json">
    <script>
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/app/static/sw.js')
            .then(function(registration) {
                console.log('Registration successful, scope is:', registration.scope);
            })
            .catch(function(error) {
                console.log('Service worker registration failed, error:', error);
            });
        }
    </script>
""", unsafe_allow_html=True)

# Initialize DB schema
setup_security()

# ─────────────────────────────────────────────
#  2. GLASSMORPHISM DESIGN SYSTEM
# ─────────────────────────────────────────────

st.markdown("""
<style>
    /* ── MESH GRADIENT BACKGROUND ── */
    .stApp {
        background-color: #080D24;
        background-image: 
            radial-gradient(at 0% 0%, rgba(112, 100, 223, 0.2) 0px, transparent 50%),
            radial-gradient(at 100% 0%, rgba(148, 251, 171, 0.15) 0px, transparent 50%),
            radial-gradient(at 100% 100%, rgba(112, 100, 223, 0.2) 0px, transparent 50%),
            radial-gradient(at 0% 100%, rgba(148, 251, 171, 0.15) 0px, transparent 50%);
        background-attachment: fixed;
    }

    /* ── TYPOGRAPHY ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
        color: #E2E8F0;
    }
    
    h1, h2, h3, h4, h5, h6 {
        color: #FFFFFF !important;
        font-weight: 800 !important;
        letter-spacing: -0.5px;
    }
    
    code {
        font-family: 'JetBrains Mono', monospace !important;
        background: rgba(8, 13, 36, 0.6) !important;
        color: #94FBAB !important;
        padding: 0.2em 0.4em !important;
        border-radius: 4px !important;
        border: 1px solid rgba(148, 251, 171, 0.2);
    }

    /* ── FROSTED GLASS CONTAINERS ── */
    div[data-testid="stVerticalBlock"] > div[style*="flex-direction: column"] > div[data-testid="stVerticalBlock"],
    .element-container form {
        background: rgba(112, 100, 223, 0.05) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 16px !important;
        padding: 24px !important;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3) !important;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }

    /* ── INPUT FIELDS ── */
    .stTextInput input, .stNumberInput input {
        background: rgba(8, 13, 36, 0.4) !important;
        border: 1px solid rgba(112, 100, 223, 0.3) !important;
        color: #FFFFFF !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        font-family: 'JetBrains Mono', monospace;
    }
    
    .stTextInput input:focus, .stNumberInput input:focus {
        border-color: #94FBAB !important;
        box-shadow: 0 0 0 2px rgba(148, 251, 171, 0.2) !important;
    }

    /* ── GLOW BUTTONS ── */
    .stButton > button {
        background: linear-gradient(135deg, #7064DF 0%, #4D4599 100%) !important;
        color: #FFFFFF !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 8px !important;
        padding: 10px 24px !important;
        font-weight: 600 !important;
        letter-spacing: 0.5px !important;
        transition: all 0.3s ease !important;
        text-transform: uppercase;
        font-size: 0.85rem !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 20px rgba(112, 100, 223, 0.4) !important;
        border-color: rgba(255, 255, 255, 0.3) !important;
    }
    
    /* Primary CTA Glow */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #080D24 0%, #1A2247 100%) !important;
        border: 1px solid #94FBAB !important;
        color: #94FBAB !important;
    }
    
    .stButton > button[kind="primary"]:hover {
        box-shadow: 0 0 20px rgba(148, 251, 171, 0.4) !important;
        background: rgba(148, 251, 171, 0.1) !important;
    }

    /* ── TABS ── */
    .stTabs [data-baseweb="tab-list"] {
        background: transparent !important;
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background: rgba(112, 100, 223, 0.1) !important;
        border-radius: 8px 8px 0 0 !important;
        border: 1px solid rgba(255, 255, 255, 0.05) !important;
        border-bottom: none !important;
        color: #A0AEC0 !important;
    }
    .stTabs [aria-selected="true"] {
        background: rgba(112, 100, 223, 0.3) !important;
        color: #FFFFFF !important;
        border-color: rgba(112, 100, 223, 0.5) !important;
    }
    .stTabs [data-baseweb="tab-highlight"] {
        background-color: #94FBAB !important;
    }

    /* ── METRICS ── */
    [data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace !important;
        font-weight: 800 !important;
        color: #94FBAB !important;
        font-size: 2.5rem !important;
    }
    [data-testid="stMetricLabel"] {
        color: #A0AEC0 !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* ── SIDEBAR ── */
    [data-testid="stSidebar"] {
        background: rgba(8, 13, 36, 0.8) !important;
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.05) !important;
    }
    
    /* ── ALERTS / INFOS ── */
    .stAlert {
        background: rgba(8, 13, 36, 0.6) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        backdrop-filter: blur(8px) !important;
        border-radius: 8px !important;
        color: #E2E8F0 !important;
    }
    
    /* ── DATAFRAME ── */
    [data-testid="stDataFrame"] {
        background: rgba(8, 13, 36, 0.6) !important;
        border-radius: 8px !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
    }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  3. SESSION STATE INITIALIZATION
# ─────────────────────────────────────────────

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_email = None

if "decrypted_shard" not in st.session_state:
    st.session_state.decrypted_shard = None
    
if "active_key" not in st.session_state:
    st.session_state.active_key = None

# ─────────────────────────────────────────────
#  4. IDENTITY SYNCHRONIZATION (LOGIN)
# ─────────────────────────────────────────────

if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("<h1 style='text-align: center; font-size: 3rem; margin-bottom: 0;'>🛡️ AEGIS</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #94FBAB; letter-spacing: 4px; margin-bottom: 2rem;'>CYBER-PHYSICAL RESILIENCE</p>", unsafe_allow_html=True)
        
        t1, t2 = st.tabs(["Link Identity", "Forge Shard"])
        
        with t1:
            with st.form("login_form"):
                email = st.text_input("Identity Designation (Email)")
                pw = st.text_input("Access Cipher", type="password")
                submit = st.form_submit_button("Establish Connection", type="primary")
                
                if submit:
                    status = authenticate_user(email, pw)
                    if status in ['active', 'warned', 'lockdown']:
                        st.session_state.logged_in = True
                        st.session_state.user_email = email
                        if status == 'warned':
                            notify("login_warned", notify_type="warning")
                        elif status == 'lockdown':
                            notify("login_lockdown", notify_type="error")
                        else:
                            notify("login_success", notify_type="success")
                        st.rerun()
                    elif status == 'banned':
                        notify("login_banned", notify_type="error")
                    else:
                        notify("login_failed", notify_type="error")
                        
        with t2:
            with st.form("register_form"):
                n_email = st.text_input("New Identity Designation")
                n_pw = st.text_input("New Access Cipher", type="password")
                submit = st.form_submit_button("Forge Identity Shard")
                
                if submit:
                    if len(n_pw) < 8:
                        st.error("🚨 Cipher must be at least 8 characters.")
                    elif create_user(n_email, n_pw):
                        notify("register_success", notify_type="success")
                    else:
                        notify("register_exists", notify_type="warning")
    st.stop()

# ─────────────────────────────────────────────
#  5. THE WARDEN's PERIMETER CHECK
# ─────────────────────────────────────────────

# Update presence
update_heartbeat(st.session_state.user_email)

# Verify standing
current_status = check_status(st.session_state.user_email)
if current_status == 'banned':
    st.session_state.logged_in = False
    st.session_state.user_email = None
    trigger_lockdown("Identity revocation detected during active session.")
    st.rerun()

if current_status == 'warned':
    st.warning("⚠️ **Administrator Warning**: Your recent activity has been flagged. Please adhere to security protocols.", icon="⚠️")

if current_status == 'lockdown':
    st.error("🔒 **LOCKDOWN ENGAGED**\n\nYour vault access is frozen. Contact the Administrator immediately at **8910162728**.\n\nFailure to comply will result in permanent Identity Purge.", icon="🚨")

# ─────────────────────────────────────────────
#  6. THE COMMAND CENTER (SIDEBAR)
# ─────────────────────────────────────────────

st.sidebar.markdown("<h2 style='text-align: center; color: #94FBAB;'>SYSTEM CONTROL</h2>", unsafe_allow_html=True)
st.sidebar.markdown("---")

# Metrics
credits = get_user_credits(st.session_state.user_email)
st.sidebar.metric("Ether-Credits", f"{credits} 💎")
st.sidebar.markdown("---")

# Navigation
if current_status != 'lockdown':
    module = st.sidebar.radio(
        "Active Module", 
        ["📂 Archive Vault", "🔮 AI Oracle", "🔋 Credit-Bay"],
        label_visibility="collapsed"
    )
else:
    module = None
    st.sidebar.error("Modules Locked")

st.sidebar.markdown("---")

if st.sidebar.button("🔴 Sever Connection", use_container_width=True):
    st.session_state.logged_in = False
    st.session_state.user_email = None
    st.session_state.decrypted_shard = None
    st.session_state.active_key = None
    st.rerun()

# ─────────────────────────────────────────────
#  7. ADMINISTRATOR TERMINAL
# ─────────────────────────────────────────────

with st.sidebar.expander("⚙️ Admin Terminal", expanded=False):
    admin_input = st.text_input("Admin Key", type="password")
    
    # Load Admin Key securely
    expected_admin_key = None
    try:
        expected_admin_key = st.secrets.get("ADMIN_KEY")
    except Exception:
        pass
    if not expected_admin_key:
        expected_admin_key = os.getenv("ADMIN_KEY", "Sayar_Admin_2026")
        
    is_admin = (admin_input == expected_admin_key)

    if is_admin:
        notify_admin_action("Terminal accessed")
        st.success("Clearance Accepted.")
        
        admin_tab1, admin_tab2, admin_tab3 = st.tabs(["Identities", "Transactions", "Forensics"])
        
        with admin_tab1:
            all_users = get_all_users()
            u_df = pd.DataFrame(all_users, columns=["Email", "EC", "Status", "Presence"])
            st.dataframe(u_df, use_container_width=True, hide_index=True)

            target = st.selectbox("Select Target Identity", u_df["Email"])
            
            # Warden Assessment
            if st.button("👁️ Warden Assessment", use_container_width=True):
                with st.spinner("Warden analyzing..."):
                    history = get_security_events(limit=20, email_filter=target)
                    assessment = warden_assess_identity(target, history)
                    threat_ui = get_threat_level_display(assessment.get("threat_level"))
                    
                    st.markdown(f"**Threat:** {threat_ui['icon']} <span style='color:{threat_ui['color']}'>{assessment.get('threat_level')}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Score:** {assessment.get('risk_score')}/10.0")
                    st.info(assessment.get("assessment"))
                    st.markdown(f"**Recommended Action:** `{assessment.get('recommended_action')}`")

            # Operations
            gem_amt = st.number_input("Grant EC", min_value=1, step=1, value=5)
            if st.button("🎁 Dispense Credits", use_container_width=True):
                grant_gems(target, gem_amt)
                notify_admin_action(f"Dispensed {gem_amt} EC", target)
                st.rerun()

            st.markdown("### Warden Enforcement")
            w1, w2 = st.columns(2)
            if w1.button("🟢 Set to Active", use_container_width=True):
                update_user_status(target, 'active')
                st.rerun()
            if w2.button("🟡 Issue Warning", use_container_width=True):
                update_user_status(target, 'warned')
                st.rerun()
                
            w3, w4 = st.columns(2)
            if w3.button("🔒 Engage Lockdown", use_container_width=True):
                update_user_status(target, 'lockdown')
                st.rerun()
            if w4.button("💥 Purge Identity", use_container_width=True, type="primary"):
                update_user_status(target, 'banned')
                st.rerun()

        with admin_tab2:
            pending = get_pending_transactions()
            if not pending:
                st.info("No pending transactions.")
            
            for p in pending:
                st.markdown(f"**Transaction #{p[0]}**")
                st.markdown(f"Identity: `{p[1]}`")
                st.markdown(f"Amount: **₹{p[2]}**")
                
                if p[5] and os.path.exists(p[5]): 
                    st.image(p[5], use_container_width=True)
                
                c1, c2 = st.columns(2)
                if c1.button("✅ Approve", key=f"app_{p[0]}", use_container_width=True): 
                    approve_transaction(p[0])
                    st.rerun()
                if c2.button("❌ Reject", key=f"rej_{p[0]}", use_container_width=True): 
                    reject_transaction(p[0])
                    st.rerun()
                st.markdown("---")

        with admin_tab3:
            stats = get_dashboard_stats()
            st.markdown(f"**Total Identities:** {stats['total_identities']}")
            st.markdown(f"**Encrypted Shards:** {stats['total_shards']}")
            st.markdown(f"**Critical Events:** <span style='color:#FF6B6B'>{stats['threat_events']}</span>", unsafe_allow_html=True)
            
            if st.button("📑 Refresh Log", use_container_width=True):
                events = get_security_events(limit=50)
                formatted = [format_event_for_display(e) for e in events]
                st.dataframe(pd.DataFrame(formatted), use_container_width=True, hide_index=True)

            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("⚠️ EMERGENCY VAULT PURGE", use_container_width=True, type="primary"):
                reset_vault_data()
                st.session_state.decrypted_shard = None
                st.rerun()

# ─────────────────────────────────────────────
#  8. MODULE 1: ARCHIVE VAULT
# ─────────────────────────────────────────────

if module == "📂 Archive Vault":
    st.title("📂 Archive Vault")
    st.markdown("Zero-Knowledge Cryptographic Storage. Keys are processed in volatile memory only.")
    
    with st.container():
        st.markdown("### Shard Decryption Protocol")
        col1, col2 = st.columns([3, 1])
        with col1:
            input_key = st.text_input("Enter Secret Shard Key", type="password", help="The Master Cipher required to decrypt your vault.")
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            decrypt_btn = st.button("🔓 Decrypt Shard Vault", use_container_width=True)

        if decrypt_btn:
            if input_key:
                data = fetch_accounts(st.session_state.user_email, input_key)
                if data is not None:
                    st.session_state.decrypted_shard = data
                    st.session_state.active_key = input_key 
                    notify("vault_decrypted", notify_type="success")
                else: 
                    notify("vault_wrong_key", notify_type="warning")
                    st.session_state.decrypted_shard = None

    if st.session_state.decrypted_shard is not None:
        st.markdown("---")
        st.markdown("### 🧬 Active Shards")
        
        if not st.session_state.decrypted_shard:
            st.info("The vault is pristine. No credential shards have been archived.")
        else:
            for entry in st.session_state.decrypted_shard:
                with st.expander(f"🔹 {entry['Site']}", expanded=False):
                    edit_col1, edit_col2 = st.columns(2)
                    with edit_col1:
                        new_u = st.text_input("Designation (User)", entry['User'], key=f"u_{entry['id']}")
                    with edit_col2:
                        new_p = st.text_input("Cipher (Password)", entry['Password'], type="password", key=f"p_{entry['id']}")
                    
                    btn_col1, btn_col2, btn_col3 = st.columns([1, 1, 2])
                    with btn_col1:
                        if st.button("💾 Synchronize", key=f"s_{entry['id']}", use_container_width=True):
                            if update_account(entry['id'], new_u, new_p, st.session_state.active_key):
                                notify("shard_updated", notify_type="success")
                                st.session_state.decrypted_shard = fetch_accounts(st.session_state.user_email, st.session_state.active_key)
                                st.rerun()
                    with btn_col2:
                        if st.button("🗑️ Erase", key=f"d_{entry['id']}", use_container_width=True):
                            delete_account(entry['id'])
                            notify("shard_deleted", notify_type="warning")
                            st.session_state.decrypted_shard = fetch_accounts(st.session_state.user_email, st.session_state.active_key)
                            st.rerun()

# ─────────────────────────────────────────────
#  9. MODULE 2: AI ORACLE
# ─────────────────────────────────────────────

elif module == "🔮 AI Oracle":
    st.title("🔮 The Aegis Oracle")
    st.markdown("Adversarial Intelligence Core powered by Llama-3.3-70B via Groq LPU™")
    
    with st.container():
        st.markdown("### Submission Terminal")
        site = st.text_input("Service Identifier (e.g., Target System)")
        user = st.text_input("Identity Designation")
        pwd = st.text_input("Payload Cipher (Password)", type="password")
        
        st.markdown("---")
        master_key = st.text_input("Master Vault Key", type="password", help="The single Master Key you use to encrypt and decrypt all your shards.")
        
        col1, col2 = st.columns([1, 3])
        with col1:
            analyze_btn = st.button("🚀 Analyze & Archive", type="primary", use_container_width=True)
            
        if analyze_btn:
            if not site or not user or not pwd or not master_key:
                st.warning("🚨 All parameters (including your Master Vault Key) are required for Oracle consultation.")
            elif credits > 0:
                if use_credit(st.session_state.user_email):
                    with st.spinner("Oracle is performing entropy analysis..."):
                        # 1. Get AI Analysis
                        analysis = get_oracle_analysis(pwd)
                        grade, color = get_oracle_grade(analysis)
                        
                        # 2. Display Analysis
                        st.markdown("---")
                        st.markdown(f"### Oracle Assessment: <span style='color:{color}'>{grade}</span>", unsafe_allow_html=True)
                        st.info(analysis)
                        
                        # 3. Archive to Vault
                        save_account(st.session_state.user_email, site, user, pwd, master_key)
                        toast("shard_saved")
                        
                        st.success("✅ Shard successfully encrypted with your Master Vault Key.")
            else: 
                notify("no_credits", notify_type="error")

# ─────────────────────────────────────────────
#  10. MODULE 3: CREDIT-BAY
# ─────────────────────────────────────────────

elif module == "🔋 Credit-Bay":
    st.title("🔋 Credit-Bay Operations")
    st.markdown("Acquire Ether-Credits to power the Aegis Oracle. Conversion: `₹10 = 1 EC`")
    
    col_qr, col_form = st.columns([1, 1.5])
    
    with col_qr:
        with st.container():
            st.markdown("### 🏦 Secure Transfer")
            # Fallback if image is missing
            try:
                st.image("my_upi_qr.jpeg", use_container_width=True)
            except Exception:
                st.error("QR Code missing from repository.")
            
            st.markdown("""
            <div style="background: rgba(8,13,36,0.6); padding: 15px; border-radius: 8px; border: 1px solid #7064DF; text-align: center;">
                <p style="margin:0; color:#A0AEC0;">Verified Payment Address (VPA)</p>
                <h3 style="margin:5px 0; color:#94FBAB;">sayarbhattacharyya9@oksbi</h3>
                <p style="margin:0; color:#FFFFFF;">Recipient: Sayar Bhattacharyya</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("<br><p style='text-align: center; font-size: 0.8em; color:#A0AEC0;'>🛡️ Transaction Security Guarantee — Verified by Vision Sentinel</p>", unsafe_allow_html=True)

    with col_form:
        with st.container():
            st.markdown("### 📡 Submit Verification Shard")
            
            amount = st.number_input("Transferred Amount (₹)", min_value=10, step=10, value=50)
            st.markdown(f"### 💎 Yield: <span style='color:#94FBAB'>{amount // 10} Ether-Credits</span>", unsafe_allow_html=True)
            
            shot = st.file_uploader("Upload Transaction Screenshot", type=["jpg", "png", "jpeg"])
            
            if st.button("🚀 Engage Vision Sentinel", type="primary", use_container_width=True):
                if shot:
                    with st.spinner("Vision Sentinel is analyzing the cryptographic proof..."):
                        # 1. Save Image Locally (Simulating cloud bucket for this demo)
                        if not os.path.exists("audit_screenshots"):
                            os.makedirs("audit_screenshots")
                        img_path = f"audit_screenshots/{st.session_state.user_email.replace('@','_')}_{int(datetime.datetime.now().timestamp())}.png"
                        
                        img_bytes = shot.getbuffer()
                        with open(img_path, "wb") as f: 
                            f.write(img_bytes)
                        
                        # 2. Vision Sentinel Analysis
                        sentinel_result = verify_payment_screenshot(img_bytes.tobytes(), amount)
                        verdict = sentinel_result.get("verdict", "PENDING_ADMIN_REVIEW")
                        display = get_sentinel_verdict_display(verdict)
                        
                        # 3. Log to Ledger
                        log_transaction(st.session_state.user_email, amount, verdict, img_path)
                        
                        # 4. Display Results
                        st.markdown("---")
                        st.markdown(f"### Sentinel Verdict: {display['icon']} <span style='color:{display['color']}'>{display['label']}</span>", unsafe_allow_html=True)
                        
                        if verdict == "VERIFIED":
                            # Auto-approve if vision is absolutely certain (Optional: you can force admin review always)
                            # For safety, let's keep it pending admin review but mark it as VERIFIED by AI
                            st.success("Vision Sentinel has verified the transaction. Awaiting final Administrator sign-off.")
                            for finding in sentinel_result.get("findings", []):
                                st.markdown(f"▸ {finding}")
                        else:
                            st.warning("Vision Sentinel flagged anomalies. Manual administrator review required.")
                            for finding in sentinel_result.get("findings", []):
                                st.markdown(f"▸ {finding}")
                else:
                    st.error("🚨 Verification shard (screenshot) is required.")
