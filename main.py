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
import re
import hmac
import io
import time
import uuid
from pathlib import Path
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from PIL import Image, UnidentifiedImageError

# Import local modules
from database_logic import (
    setup_security, authenticate_user, create_user, get_all_users,
    update_heartbeat, get_user_credits, use_credit, save_account,
    fetch_accounts, update_account, delete_account, check_status,
    update_user_status, reset_vault_data, grant_gems, refund_credit, log_transaction,
    get_pending_transactions, approve_transaction, reject_transaction,
    get_security_events, get_dashboard_stats, cleanup_expired_screenshots,
    clear_transaction_image_path
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

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = (BASE_DIR / os.getenv("AUDIT_UPLOAD_DIR", "audit_screenshots")).resolve()
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024
SESSION_IDLE_SECONDS = 30 * 60


def _get_app_setting(name, default=None):
    """Read private configuration from Streamlit secrets, then environment."""
    try:
        value = st.secrets.get(name)
        if value:
            return str(value).strip()
    except Exception:
        pass
    value = os.getenv(name)
    return value.strip() if value else default


def _clear_sensitive_session():
    """Remove decrypted vault data and schedule sensitive widget values for clearing."""
    st.session_state.decrypted_shard = None
    st.session_state.active_key = None
    st.session_state.clear_vault_key_next_run = True
    st.session_state.clear_oracle_secrets_next_run = True
    st.session_state.oracle_result = None
    st.session_state.oracle_error = None


def _prepare_uploaded_screenshot(uploaded_file):
    """Validate and normalize an uploaded image, stripping EXIF metadata."""
    if uploaded_file is None:
        raise ValueError("Select a screenshot first.")
    raw = uploaded_file.getvalue()
    if not raw or len(raw) > MAX_SCREENSHOT_BYTES:
        raise ValueError("Screenshot must be non-empty and no larger than 5 MB.")
    suffix = Path(uploaded_file.name or "").suffix.lower()
    if suffix not in {".jpg", ".jpeg", ".png"}:
        raise ValueError("Only JPG and PNG screenshots are accepted.")
    try:
        with Image.open(io.BytesIO(raw)) as probe:
            expected_format = "PNG" if suffix == ".png" else "JPEG"
            if probe.format != expected_format:
                raise ValueError("The file extension does not match the actual image format.")
            if probe.width > 8000 or probe.height > 8000 or probe.width * probe.height > 20_000_000:
                raise ValueError("Screenshot dimensions exceed the safe processing limit.")
            probe.verify()
        with Image.open(io.BytesIO(raw)) as image:
            image = image.convert("RGB")
            output = io.BytesIO()
            image.save(output, format="JPEG", quality=88, optimize=True)
            return output.getvalue()
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("The uploaded screenshot could not be decoded safely.") from exc


def _safe_screenshot_path(relative_path):
    if not relative_path:
        return None
    candidate = (BASE_DIR / str(relative_path)).resolve()
    try:
        candidate.relative_to(UPLOAD_DIR)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def is_valid_email(email):
    """Simple email validation with a bounded input length."""
    if not isinstance(email, str) or len(email) > 254:
        return False
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

# ─────────────────────────────────────────────
#  1. CORE CONFIGURATION
# ─────────────────────────────────────────────

st.set_page_config(
    page_title="Aegis-Portal | Command Center", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize DB schema
setup_security()
try:
    retention_days = int(_get_app_setting("SCREENSHOT_RETENTION_DAYS", "30"))
except (TypeError, ValueError):
    retention_days = 30
cleanup_expired_screenshots(UPLOAD_DIR, retention_days)

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

    /* ── BRANDING OPTIMIZATION ── */
    [data-testid="stFooter"] {display: none !important;}
    [data-testid="stHeader"] {background: transparent !important;}
    #MainMenu {visibility: hidden !important;}
    .stDeployButton {display: none !important;}
    #stDecoration {display: none !important;}
    .viewerBadge_container__1QS1Y {display: none !important;}
    .viewerBadge_link__1LSvE {display: none !important;}
    
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

    /* ── MOBILE OPTIMIZATION ── */
    @media (max-width: 768px) {
        .stApp { padding: 0 !important; }
        .main .block-container {
            padding-bottom: 2rem !important;
            padding-left: 1rem !important;
            padding-right: 1rem !important;
        }
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
        font-size: 1.8rem !important;
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

for state_key, default_value in {
    "logged_in": False,
    "user_email": None,
    "decrypted_shard": None,
    "active_key": None,
    "last_activity": None,
    "admin_access_logged": False,
    "admin_authenticated": False,
    "admin_auth_failures": 0,
    "admin_lock_until": 0.0,
    "admin_auth_error": False,
    "clear_admin_key_next_run": False,
}.items():
    if state_key not in st.session_state:
        st.session_state[state_key] = default_value

# Clear secret-bearing widgets before they are recreated on the next Streamlit run.
if st.session_state.pop("clear_admin_key_next_run", False):
    st.session_state["admin_key_input"] = ""
if st.session_state.pop("clear_vault_key_next_run", False):
    st.session_state["vault_master_key_input"] = ""
if st.session_state.pop("clear_oracle_secrets_next_run", False):
    st.session_state["oracle_password_input"] = ""
    st.session_state["oracle_master_key_input"] = ""
    st.session_state["oracle_site_input"] = ""
    st.session_state["oracle_user_input"] = ""

if st.session_state.logged_in:
    now_epoch = time.time()
    previous_activity = st.session_state.last_activity
    if previous_activity and now_epoch - previous_activity > SESSION_IDLE_SECONDS:
        st.session_state.logged_in = False
        st.session_state.user_email = None
        st.session_state.last_activity = None
        st.session_state.admin_access_logged = False
        st.session_state.admin_authenticated = False
        if "admin_key_input" in st.session_state:
            st.session_state.admin_key_input = ""
        _clear_sensitive_session()
        notify("session_expired", notify_type="warning")
        st.rerun()
    st.session_state.last_activity = now_epoch

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
            with st.container():
                email = st.text_input("Identity Designation (Email)", key="login_email").strip().lower()
                pw = st.text_input("Access Cipher", type="password", key="login_pw")
                submit = st.button("Establish Connection", type="primary", use_container_width=True)
                
                if submit:
                    if not is_valid_email(email):
                        st.error("🚨 Invalid Identity Format. Please use a valid email address.")
                    else:
                        status = authenticate_user(email, pw)
                        if status in ['active', 'warned', 'lockdown', 'banned']:
                            st.session_state.logged_in = True
                            st.session_state.user_email = email
                            st.session_state.last_activity = time.time()
                            if status == 'banned':
                                notify("login_banned", notify_type="error")
                            elif status == 'warned':
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
            with st.container():
                n_email = st.text_input("New Identity Designation", key="reg_email").strip().lower()
                n_pw = st.text_input("New Access Cipher", type="password", key="reg_pw")
                submit = st.button("Forge Identity Shard", use_container_width=True)
                
                if submit:
                    if not is_valid_email(n_email):
                        st.error("🚨 Invalid Identity Format. Shards must be forged using a valid email address.")
                    elif len(n_pw) < 8:
                        st.error("🚨 Cipher must be at least 8 characters.")
                    elif create_user(n_email, n_pw):
                        notify("register_success", notify_type="success")
                    else:
                        notify("register_exists", notify_type="warning")
    st.stop()

# ─────────────────────────────────────────────
#  5. THE WARDEN's PERIMETER CHECK
# ─────────────────────────────────────────────

# Check account status before rendering any portal module or sidebar action.
current_status = check_status(st.session_state.user_email)
if current_status == "banned":
    _clear_sensitive_session()
    st.session_state.admin_access_logged = False
    st.session_state.admin_authenticated = False
    st.title("🚫 Identity Access Suspended")
    st.error(
        "This account has been banned by the Aegis Warden. You may sign in only to view this announcement. "
        "All portal privileges and functions are disabled, including Archive Vault, Aegis Oracle, Credit-Bay, "
        "credits, and account actions."
    )
    contact_name = _get_app_setting("ADMIN_CONTACT_NAME", "Sayar Bhattacharyya")
    contact_email = _get_app_setting("ADMIN_CONTACT_EMAIL")
    contact_phone = _get_app_setting("ADMIN_CONTACT_PHONE")
    contact_url = _get_app_setting(
        "ADMIN_CONTACT_URL",
        "https://github.com/sayarbhattacharyya68-ai",
    )
    st.markdown("### Contact the Administrator")
    st.write(f"**Administrator:** {contact_name}")
    st.write(f"**Email:** {contact_email or 'Not configured'}")
    st.write(f"**Phone:** {contact_phone or 'Not configured'}")
    if isinstance(contact_url, str) and contact_url.startswith(("https://", "http://")):
        st.link_button("Contact Sayar / Aegis Administrator", contact_url)
    st.caption("Only an authorized administrator can restore this account.")
    if st.button("Log Out", type="primary"):
        st.session_state.logged_in = False
        st.session_state.user_email = None
        st.session_state.last_activity = None
        _clear_sensitive_session()
        st.rerun()
    st.stop()

update_heartbeat(st.session_state.user_email)

if current_status == 'warned':
    st.warning("⚠️ **Administrator Warning**: Your recent activity has been flagged. Please adhere to security protocols.", icon="⚠️")

if current_status == 'lockdown':
    _clear_sensitive_session()
    st.session_state.admin_access_logged = False
    st.session_state.admin_authenticated = False
    st.error("🔒 **LOCKDOWN ENGAGED**\n\nVault access is frozen. Contact the configured administrator through the official support channel.", icon="🚨")

# ─────────────────────────────────────────────
#  6. THE COMMAND CENTER (SIDEBAR)
# ─────────────────────────────────────────────

st.sidebar.markdown("<h2 style='text-align: center; color: #94FBAB;'>SYSTEM CONTROL</h2>", unsafe_allow_html=True)
st.sidebar.markdown("---")

# Metrics & Identity
credits = get_user_credits(st.session_state.user_email)
st.sidebar.metric("Ether-Credits", f"{credits} 💎")
st.sidebar.markdown(f"**Identity:** `{st.session_state.user_email}`")
st.sidebar.markdown("---")

# Mobile installation is intentionally omitted; no service worker is configured.

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
    st.session_state.last_activity = None
    st.session_state.admin_access_logged = False
    st.session_state.admin_authenticated = False
    if "admin_key_input" in st.session_state:
        st.session_state.admin_key_input = ""
    _clear_sensitive_session()
    st.rerun()

# ─────────────────────────────────────────────
#  7. ADMINISTRATOR TERMINAL
# ─────────────────────────────────────────────

with st.sidebar.expander("⚙️ Admin Terminal", expanded=False):
    expected_admin_key = _get_app_setting("ADMIN_KEY")
    if not expected_admin_key:
        st.session_state.admin_authenticated = False
        st.session_state.admin_access_logged = False
        st.warning("Administrator access is disabled. Configure ADMIN_KEY in Streamlit secrets or the local .env file.")
    elif not st.session_state.admin_authenticated:
        lock_remaining = max(0, int(st.session_state.admin_lock_until - time.time()))
        if st.session_state.admin_auth_error:
            st.error("Administrator authentication failed. Check the key and try again.")
            st.session_state.admin_auth_error = False
        if lock_remaining:
            st.warning(f"Administrator sign-in is temporarily paused. Retry in {lock_remaining} seconds.")
        admin_input = st.text_input("Admin Key", type="password", key="admin_key_input")
        if st.button("🔐 Unlock Admin Terminal", use_container_width=True, disabled=bool(lock_remaining)):
            st.session_state.clear_admin_key_next_run = True
            if admin_input and hmac.compare_digest(str(admin_input), str(expected_admin_key)):
                st.session_state.admin_authenticated = True
                st.session_state.admin_access_logged = False
                st.session_state.admin_auth_failures = 0
                st.session_state.admin_lock_until = 0.0
                st.session_state.admin_auth_error = False
            else:
                st.session_state.admin_auth_failures += 1
                st.session_state.admin_auth_error = True
                if st.session_state.admin_auth_failures >= 5:
                    st.session_state.admin_auth_failures = 0
                    st.session_state.admin_lock_until = time.time() + 30
            st.rerun()
    else:
        if st.button("🔒 Lock Admin Terminal", use_container_width=True):
            st.session_state.admin_authenticated = False
            st.session_state.admin_access_logged = False
            st.session_state.clear_admin_key_next_run = True
            st.rerun()
        if not st.session_state.admin_access_logged:
            notify_admin_action("Terminal accessed")
        st.session_state.admin_access_logged = True
        st.success("Clearance Accepted.")
        
        admin_tab1, admin_tab2, admin_tab3 = st.tabs(["Identities", "Transactions", "Forensics"])
        
        with admin_tab1:
            all_users = get_all_users()
            u_df = pd.DataFrame(all_users, columns=["Email", "EC", "Status", "Presence"])
            st.dataframe(u_df, use_container_width=True, hide_index=True)

            if u_df.empty:
                st.info("No user identities are registered yet.")
            else:
                target = st.selectbox("Select Target Identity", u_df["Email"].tolist())

                if st.button("👁️ Warden Assessment", use_container_width=True):
                    with st.spinner("Warden analyzing sanitized security metadata..."):
                        history = get_security_events(limit=20, email_filter=target)
                        assessment = warden_assess_identity(target, history)
                        threat_ui = get_threat_level_display(assessment.get("threat_level"))
                        st.markdown(f"**Threat:** {threat_ui['icon']} <span style='color:{threat_ui['color']}'>{assessment.get('threat_level')}</span>", unsafe_allow_html=True)
                        st.markdown(f"**Score:** {assessment.get('risk_score')}/10.0")
                        st.write(assessment.get("assessment", "No assessment available."))
                        st.markdown(f"**Advisory only — recommended action:** `{assessment.get('recommended_action', 'MONITOR')}`")
                        for indicator in assessment.get("indicators", []):
                            st.write(f"• {indicator}")

                gem_amt = st.number_input("Grant EC", min_value=1, max_value=10000, step=1, value=5)
                if st.button("🎁 Dispense Credits", use_container_width=True):
                    if grant_gems(target, int(gem_amt)):
                        notify_admin_action(f"Dispensed {gem_amt} EC", target)
                        st.rerun()
                    else:
                        st.error("Credit grant could not be completed.")

                st.markdown("### Warden Enforcement — Human Administrator Only")
                w1, w2 = st.columns(2)
                if w1.button("🟢 Set to Active", use_container_width=True):
                    update_user_status(target, "active")
                    st.rerun()
                if w2.button("🟡 Issue Warning", use_container_width=True):
                    update_user_status(target, "warned")
                    st.rerun()

                w3, w4 = st.columns(2)
                if w3.button("🔒 Engage Lockdown", use_container_width=True):
                    update_user_status(target, "lockdown")
                    st.rerun()
                confirm_identity_ban = st.checkbox(
                    "I understand this bans the account while retaining records for administrator audit.",
                    key=f"confirm_identity_ban_{target}",
                )
                if w4.button("🚫 Ban Account", use_container_width=True, type="primary", disabled=not confirm_identity_ban):
                    if update_user_status(target, "banned"):
                        notify_admin_action("Banned account", target)
                    st.rerun()

        with admin_tab2:
            pending = get_pending_transactions()
            st.info(
                "Warden review queue: inspect the original payment screenshot and AI findings. "
                "AI cannot approve payments or grant credits; a human administrator makes the final decision."
            )
            if not pending:
                st.info("No pending transactions.")

            for p in pending:
                st.markdown(f"**Transaction #{p[0]}**")
                st.markdown(f"Identity: `{p[1]}`")
                st.markdown(f"Amount: **₹{p[2]}**")
                verdict = p[8] if len(p) > 8 and p[8] else "PENDING_ADMIN_REVIEW"
                display = get_sentinel_verdict_display(verdict)
                confidence = float(p[9] or 0.0) if len(p) > 9 else 0.0
                st.markdown(
                    f"**AI advisory:** {display['icon']} "
                    f"<span style='color:{display['color']}'>{display['label']}</span>",
                    unsafe_allow_html=True,
                )
                st.caption(f"AI confidence: {confidence:.0%}")
                if len(p) > 11:
                    st.caption(f"AI detected amount: {p[11] or 'Unavailable'}")
                if len(p) > 12 and p[12] is not None:
                    st.caption(f"AI recipient match: {'Yes' if p[12] else 'No'}")
                if len(p) > 10 and p[10]:
                    st.write("AI findings:")
                    for finding in str(p[10]).splitlines():
                        st.write(f"• {finding}")

                image_path = _safe_screenshot_path(p[5]) if len(p) > 5 else None
                if image_path:
                    st.image(
                        str(image_path),
                        use_container_width=True,
                        caption="Original payment screenshot submitted by the user — manual verification required",
                    )
                else:
                    st.error("Original payment screenshot is unavailable. Approval and rejection are disabled.")

                reviewed = st.checkbox(
                    "I have personally reviewed the original screenshot and transaction details.",
                    key=f"warden_reviewed_{p[0]}",
                )
                c1, c2 = st.columns(2)
                if c1.button(
                    "✅ Approve and Grant Credits",
                    key=f"app_{p[0]}",
                    use_container_width=True,
                    disabled=not (reviewed and image_path),
                ):
                    if approve_transaction(p[0]):
                        if image_path:
                            image_path.unlink(missing_ok=True)
                        clear_transaction_image_path(p[0])
                        notify_admin_action("Payment manually approved", p[1])
                    st.rerun()
                if c2.button(
                    "❌ Reject Payment",
                    key=f"rej_{p[0]}",
                    use_container_width=True,
                    disabled=not (reviewed and image_path),
                ):
                    if reject_transaction(p[0]):
                        if image_path:
                            image_path.unlink(missing_ok=True)
                        clear_transaction_image_path(p[0])
                        notify_admin_action("Payment manually rejected", p[1])
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
            confirm_vault_purge = st.checkbox(
                "I understand this permanently deletes every stored credential record.",
                key="confirm_global_vault_purge",
            )
            if st.button("⚠️ EMERGENCY VAULT PURGE", use_container_width=True, type="primary", disabled=not confirm_vault_purge):
                reset_vault_data()
                _clear_sensitive_session()
                st.rerun()

# ─────────────────────────────────────────────
#  8. MODULE 1: ARCHIVE VAULT
# ─────────────────────────────────────────────

if module == "📂 Archive Vault":
    st.title("📂 Archive Vault")
    st.markdown(
        "Newly archived service names, usernames, and passwords are encrypted with Fernet. "
        "The key is derived from your Master Vault Key and the fresh random salt stored with each record. "
        "Use the same Master Vault Key you entered in Aegis Oracle. Older records migrate after a correct unlock."
    )
    vault_notice = st.session_state.pop("vault_notice", None)
    if vault_notice == "unlocked":
        st.success("Vault unlocked. The input key has been cleared from the form.")
    elif vault_notice == "wrong_key":
        st.warning("The supplied vault key could not decrypt the saved records. The key field was cleared.")
    
    with st.container():
        st.markdown("### Shard Decryption Protocol")
        col1, col2 = st.columns([3, 1])
        with col1:
            input_key = st.text_input(
            "Enter Master Vault Key",
            type="password",
            key="vault_master_key_input",
            help="Enter the exact Master Vault Key you used when archiving credentials in Aegis Oracle.",
        )
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            decrypt_btn = st.button("🔓 Decrypt Shard Vault", use_container_width=True)

        if decrypt_btn:
            if input_key:
                data = fetch_accounts(st.session_state.user_email, input_key)
                if data is not None:
                    st.session_state.decrypted_shard = data
                    st.session_state.active_key = input_key
                    st.session_state.vault_notice = "unlocked"
                    st.session_state.clear_vault_key_next_run = True
                    st.rerun()
                else:
                    st.session_state.vault_notice = "wrong_key"
                    _clear_sensitive_session()
                    st.rerun()

    if st.session_state.decrypted_shard is not None:
        lock_col, _ = st.columns([1, 4])
        if lock_col.button("🔒 Lock Vault", use_container_width=True):
            _clear_sensitive_session()
            st.rerun()
        st.markdown("---")
        st.markdown("### 🧬 Active Shards")
        
        if not st.session_state.decrypted_shard:
            st.info("The vault is pristine. No credential shards have been archived.")
        else:
            for entry in st.session_state.decrypted_shard:
                with st.expander(f"🔹 {entry['Site']}", expanded=False):
                    edit_col1, edit_col2, edit_col3 = st.columns(3)
                    with edit_col1:
                        new_site = st.text_input("Service Identifier", entry['Site'], key=f"site_{entry['id']}")
                    with edit_col2:
                        new_u = st.text_input("Designation (User)", entry['User'], key=f"u_{entry['id']}")
                    with edit_col3:
                        new_p = st.text_input("Cipher (Password)", entry['Password'], type="password", key=f"p_{entry['id']}")

                    btn_col1, btn_col2 = st.columns(2)
                    with btn_col1:
                        if st.button("💾 Save Changes", key=f"save_{entry['id']}", use_container_width=True):
                            if update_account(
                                entry['id'], new_u, new_p, st.session_state.active_key,
                                st.session_state.user_email, new_site=new_site,
                            ):
                                notify("shard_updated", notify_type="success")
                                st.session_state.decrypted_shard = fetch_accounts(
                                    st.session_state.user_email, st.session_state.active_key
                                )
                                st.rerun()
                            else:
                                st.error("The credential changes could not be saved.")
                    with btn_col2:
                        confirm_delete = st.checkbox(
                            "Confirm permanent deletion",
                            key=f"confirm_d_{entry['id']}",
                        )
                        if st.button(
                            "🗑️ Delete Credential",
                            key=f"d_{entry['id']}",
                            use_container_width=True,
                            disabled=not confirm_delete,
                        ):
                            if delete_account(entry['id'], st.session_state.user_email):
                                notify("shard_deleted", notify_type="warning")
                                st.session_state.decrypted_shard = fetch_accounts(
                                    st.session_state.user_email, st.session_state.active_key
                                )
                                st.rerun()

# ─────────────────────────────────────────────
#  9. MODULE 2: AI ORACLE
# ─────────────────────────────────────────────

elif module == "🔮 AI Oracle":
    st.title("🔮 The Aegis Oracle")
    st.markdown(
        "Run the security assessment first. Archiving is a separate optional action; "
        "analysis never stores a credential automatically."
    )

    oracle_result = st.session_state.get("oracle_result")
    oracle_error = st.session_state.pop("oracle_error", None)
    archive_notice = st.session_state.pop("oracle_archive_notice", None)
    if oracle_result:
        st.markdown("---")
        st.markdown(
            f"### Oracle Assessment: <span style='color:{oracle_result['color']}'>{oracle_result['grade']}</span>",
            unsafe_allow_html=True,
        )
        st.info(oracle_result["analysis"])
        st.caption("Analysis complete. No credential is archived unless you separately choose Archive Encrypted Credential.")
    if archive_notice:
        st.success(archive_notice)
    if oracle_error:
        st.error(oracle_error)

    with st.container():
        st.markdown("### Submission Terminal")
        site = st.text_input("Service Identifier (e.g., Target System)", key="oracle_site_input")
        user = st.text_input("Identity Designation", key="oracle_user_input")
        pwd = st.text_input("Payload Cipher (Password)", type="password", key="oracle_password_input")
        st.markdown("---")
        master_key = st.text_input(
            "Master Vault Key (required only for archiving)",
            type="password",
            key="oracle_master_key_input",
            help="This master key and a fresh per-record salt derive the Fernet encryption key.",
        )
        allow_ai_explanation = st.checkbox(
            "Optional: send non-reversible password characteristics (never the password) to Google Gemini for an explanation.",
            value=False,
        )

        left, right = st.columns(2)
        with left:
            analyze_btn = st.button("🧠 Analyze with AI", type="primary", use_container_width=True)
        with right:
            archive_btn = st.button("🔐 Archive Encrypted Credential", use_container_width=True)

        if analyze_btn:
            if not site.strip() or not user.strip() or not pwd:
                st.warning("Enter service, identity, and password before analysis.")
            elif len(site) > 200 or len(user) > 254 or len(pwd) > 4096:
                st.error("One or more fields exceed the supported length. Shorten the input and try again.")
            elif use_credit(st.session_state.user_email):
                try:
                    with st.spinner("Aegis Oracle is analyzing the credential..."):
                        analysis = get_oracle_analysis(pwd, allow_ai=allow_ai_explanation)
                        grade, color = get_oracle_grade(analysis)
                    st.session_state.oracle_result = {
                        "analysis": analysis, "grade": grade, "color": color
                    }
                    st.session_state.oracle_error = None
                    st.rerun()
                except Exception:
                    try:
                        refunded = refund_credit(st.session_state.user_email)
                    except Exception:
                        refunded = False
                    st.session_state.oracle_error = (
                        "The analysis could not be completed. The Ether-Credit was restored."
                        if refunded else
                        "The analysis failed and the credit balance could not be confirmed. Contact the administrator before retrying."
                    )
                    st.rerun()
            elif get_user_credits(st.session_state.user_email) <= 0:
                notify("no_credits", notify_type="error")
            else:
                st.warning("The credit could not be reserved. Please retry once.")

        if archive_btn:
            if not site.strip() or not user.strip() or not pwd or not master_key:
                st.warning("Enter service, identity, password, and Master Vault Key to archive this credential.")
            elif len(site) > 200 or len(user) > 254 or len(pwd) > 4096 or len(master_key) > 4096:
                st.error("One or more fields exceed the supported length. Shorten the input and try again.")
            else:
                try:
                    with st.spinner("Encrypting all credential fields using your Master Vault Key and a fresh salt..."):
                        save_account(st.session_state.user_email, site, user, pwd, master_key)
                    st.session_state.oracle_archive_notice = (
                        "Credential archived. Service, username, and password are encrypted. "
                        "Use the same Master Vault Key to unlock it in Archive Vault."
                    )
                    st.session_state.clear_oracle_secrets_next_run = True
                    toast("shard_saved")
                    st.rerun()
                except Exception:
                    st.error("The credential could not be archived. No plaintext credential was stored in the vault.")

# ─────────────────────────────────────────────
#  10. MODULE 3: CREDIT-BAY
# ─────────────────────────────────────────────

elif module == "🔋 Credit-Bay":
    st.title("🔋 Credit-Bay Operations")
    st.markdown("Acquire Ether-Credits to power the Aegis Oracle. Conversion: `₹10 = 1 EC`.")

    qr_path = Path(_get_app_setting("PAYMENT_QR_IMAGE", "Sayar_UPI.jpeg"))
    if not qr_path.is_absolute():
        qr_path = (BASE_DIR / qr_path).resolve()
    recipient_name = _get_app_setting("PAYMENT_RECIPIENT_NAME", "Sayar Bhattacharyya")
    recipient_vpa = _get_app_setting("PAYMENT_RECIPIENT_VPA", "sayarbhattacharyya9@okhdfcbank")

    col_qr, col_form = st.columns([1, 1.5])
    with col_qr:
        with st.container():
            st.markdown("### 🏦 Secure Transfer")
            if qr_path.is_file() and qr_path.resolve().is_relative_to(BASE_DIR):
                st.image(str(qr_path), use_container_width=True)
            else:
                st.info("Payment QR image is not configured. The owner can add the private QR locally and set PAYMENT_QR_IMAGE.")
            st.markdown("**Payment recipient details**")
            st.text(f"Recipient: {recipient_name or 'Not configured'}")
            st.text(f"VPA: {recipient_vpa or 'Not configured'}")
            st.caption("Verify recipient details in your payment app before transferring funds.")

    with col_form:
        with st.container():
            st.markdown("### 📡 Submit Verification Screenshot")
            amount = st.number_input("Transferred Amount (₹)", min_value=10, max_value=100000, step=10, value=50)
            st.markdown(f"### 💎 Yield: **{int(amount) // 10} Ether-Credits**")
            shot = st.file_uploader("Upload Transaction Screenshot", type=["jpg", "png", "jpeg"])
            payment_consent = st.checkbox(
                "Optional: I consent to sending this screenshot and expected amount to Google's Gemini API for an AI pre-check. AI findings are advisory only.",
                value=False,
            )

            if st.button("📨 Submit Payment for Warden Review", type="primary", use_container_width=True):
                if int(amount) % 10 != 0:
                    st.error("Payment amount must be a multiple of ₹10.")
                elif not shot:
                    st.error("A payment screenshot is required.")
                else:
                    saved_path = None
                    transaction_logged = False
                    try:
                        normalized_image = _prepare_uploaded_screenshot(shot)
                        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                        upload_name = f"{uuid.uuid4().hex}.jpg"
                        saved_path = UPLOAD_DIR / upload_name
                        saved_path.write_bytes(normalized_image)
                        relative_path = str(saved_path.relative_to(BASE_DIR))
                        if payment_consent:
                            try:
                                with st.spinner("Vision Sentinel is reviewing your consented screenshot..."):
                                    sentinel_result = verify_payment_screenshot(normalized_image, int(amount))
                            except Exception:
                                # AI is advisory: an outage must not discard the user's
                                # receipt or prevent a manual Warden review.
                                sentinel_result = {
                                    "verdict": "PENDING_ADMIN_REVIEW",
                                    "confidence": 0.0,
                                    "amount_detected": "AI check unavailable",
                                    "recipient_match": False,
                                    "findings": [
                                        "Automated pre-check failed. The original screenshot has still been queued for manual Warden review."
                                    ],
                                }
                        else:
                            sentinel_result = {
                                "verdict": "PENDING_ADMIN_REVIEW",
                                "confidence": 0.0,
                                "amount_detected": "Not analyzed",
                                "recipient_match": False,
                                "findings": [
                                    "AI analysis was not authorized. Original screenshot is ready for manual Warden review."
                                ],
                            }
                        transaction_id = log_transaction(
                            st.session_state.user_email,
                            int(amount),
                            "PENDING",
                            relative_path,
                            sentinel_result=sentinel_result,
                        )
                        transaction_logged = True
                        display = get_sentinel_verdict_display(sentinel_result.get("verdict", "PENDING_ADMIN_REVIEW"))
                        st.markdown("---")
                        st.markdown(
                            f"### Sentinel Advisory: {display['icon']} "
                            f"<span style='color:{display['color']}'>{display['label']}</span>",
                            unsafe_allow_html=True,
                        )
                        st.info(
                            f"Transaction #{transaction_id} remains PENDING. The Warden must inspect the screenshot "
                            "and manually approve it before credits are granted."
                        )
                        st.caption(f"AI confidence: {float(sentinel_result.get('confidence', 0.0)):.0%}")
                        for finding in sentinel_result.get("findings", []):
                            st.write(f"• {finding}")
                    except (ValueError, OSError) as exc:
                        if saved_path and not transaction_logged:
                            saved_path.unlink(missing_ok=True)
                        st.error(str(exc))
                    except Exception:
                        if saved_path and not transaction_logged:
                            saved_path.unlink(missing_ok=True)
                        st.error("The screenshot could not be processed or queued. No automated approval was performed.")