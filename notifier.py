"""
╔══════════════════════════════════════════════════════════════╗
║  AEGIS-PORTAL: SIGNAL LAYER                                 ║
║  notifier.py — Forensic Logging & Notification Engine       ║
║                                                              ║
║  All security events are persisted to the database via       ║
║  database_logic.log_security_event(). This module handles    ║
║  user-facing notifications with immersive, themed language.  ║
╚══════════════════════════════════════════════════════════════╝
"""

import datetime
import streamlit as st
from database_logic import log_security_event

# ─────────────────────────────────────────────
#  EVENT CATEGORIES
# ─────────────────────────────────────────────

EVENT_TYPES = {
    "AUTH_SUCCESS":          {"icon": "🔓", "severity": "INFO",     "label": "Identity Sync"},
    "AUTH_FAILURE":          {"icon": "🚨", "severity": "WARNING",  "label": "Access Denied"},
    "IDENTITY_CREATED":      {"icon": "🧬", "severity": "INFO",     "label": "Shard Forged"},
    "IDENTITY_BANNED":       {"icon": "⛔", "severity": "CRITICAL", "label": "Identity Revoked"},
    "IDENTITY_RESTORED":     {"icon": "✅", "severity": "INFO",     "label": "Identity Restored"},
    "VAULT_ACCESS":          {"icon": "🔐", "severity": "INFO",     "label": "Vault Accessed"},
    "VAULT_ACCESS_DENIED":   {"icon": "🛑", "severity": "WARNING",  "label": "Vault Breach Attempt"},
    "VAULT_WRITE":           {"icon": "📝", "severity": "INFO",     "label": "Shard Archived"},
    "VAULT_DELETE":          {"icon": "🗑️", "severity": "WARNING",  "label": "Shard Destroyed"},
    "VAULT_PURGE":           {"icon": "💥", "severity": "CRITICAL", "label": "Emergency Purge"},
    "CREDIT_CONSUMED":       {"icon": "💎", "severity": "INFO",     "label": "Credit Consumed"},
    "CREDIT_GRANTED":        {"icon": "🎁", "severity": "INFO",     "label": "Credits Granted"},
    "CREDIT_PURCHASE":       {"icon": "💳", "severity": "INFO",     "label": "Transaction Submitted"},
    "TRANSACTION_APPROVED":  {"icon": "✅", "severity": "INFO",     "label": "Transaction Verified"},
    "TRANSACTION_REJECTED":  {"icon": "❌", "severity": "WARNING",  "label": "Transaction Rejected"},
    "ADMIN_ACTION":          {"icon": "⚙️", "severity": "INFO",     "label": "Admin Override"},
    "LOCKDOWN_TRIGGERED":    {"icon": "🔒", "severity": "CRITICAL", "label": "Global Lockdown"},
    "WARDEN_ALERT":          {"icon": "👁️", "severity": "WARNING",  "label": "Warden Alert"},
}

# ─────────────────────────────────────────────
#  IMMERSIVE NOTIFICATION MESSAGES
# ─────────────────────────────────────────────

IMMERSIVE_MESSAGES = {
    # ── Authentication ──
    "login_success":        "Identity Shard successfully synchronized. Welcome to the Command Center.",
    "login_failed":         "Cipher verification denied. The presented credentials do not match any known identity.",
    "login_banned":         "⛔ IDENTITY REVOKED — This shard has been permanently deactivated by the Shard Warden.",
    "register_success":     "New Identity Shard forged and committed to the vault. Your digital presence has been established.",
    "register_exists":      "Identity collision detected. This designation already exists within the system.",
    
    # ── Vault Operations ──
    "vault_decrypted":      "Shard vault unlocked. Encrypted data streams are now visible in plaintext.",
    "vault_wrong_key":      "⚠️ CIPHER MISMATCH — The provided key does not correspond to any encrypted shards.",
    "vault_empty":          "The vault is pristine. No credential shards have been archived under this identity.",
    "shard_saved":          "Credential shard encrypted and committed to the secure vault.",
    "shard_updated":        "Shard parameters recalibrated. Changes have been synchronized to the vault.",
    "shard_deleted":        "Credential shard has been permanently erased from the system.",
    "vault_purged":         "⚠️ EMERGENCY PROTOCOL — All credential shards have been irreversibly destroyed.",
    
    # ── Oracle ──
    "oracle_analyzing":     "The Aegis Oracle is performing adversarial entropy analysis...",
    "oracle_complete":      "Oracle audit complete. Tactical assessment delivered.",
    "oracle_offline":       "The Oracle is currently unreachable. Verify your Groq API configuration.",
    "no_credits":           "Insufficient Ether-Credits. Visit the Credit-Bay to acquire additional resources.",
    
    # ── Credit-Bay ──
    "transaction_submitted":"Transaction shard submitted for verification. The Vision Sentinel is processing your proof.",
    "transaction_approved": "Transaction verified and approved. Ether-Credits have been dispensed to your identity.",
    "transaction_rejected": "Transaction rejected. The submitted proof did not pass verification protocols.",
    
    # ── Admin ──
    "admin_authenticated":  "Administrator clearance confirmed. Full system access granted.",
    "gems_granted":         "Ether-Credits successfully dispensed to the target identity.",
    "user_banned":          "Identity shard deactivated. All active sessions will be terminated.",
    "user_restored":        "Identity shard reactivated. Access privileges have been restored.",
    
    # ── Session ──
    "session_expired":      "Your session cipher has been invalidated. Please re-authenticate.",
    "key_displayed":        "⚠️ CRITICAL — Copy this Shard Key immediately. It will NOT be stored or displayed again.",
}

# ─────────────────────────────────────────────
#  USER-FACING NOTIFICATIONS
# ─────────────────────────────────────────────

def notify(message_key, fallback_msg=None, notify_type="info"):
    """
    Display a themed notification using immersive language.
    
    Args:
        message_key: Key from IMMERSIVE_MESSAGES dict, or a raw string
        fallback_msg: Fallback message if key not found
        notify_type: One of 'success', 'error', 'warning', 'info'
    """
    msg = IMMERSIVE_MESSAGES.get(message_key, fallback_msg or message_key)
    
    if notify_type == "success":
        st.success(f"✅ {msg}")
    elif notify_type == "error":
        st.error(f"🚨 {msg}")
    elif notify_type == "warning":
        st.warning(f"⚠️ {msg}")
    else:
        st.info(f"ℹ️ {msg}")


def toast(message_key, fallback_msg=None, icon="🛡️"):
    """Display a brief toast notification with immersive messaging."""
    msg = IMMERSIVE_MESSAGES.get(message_key, fallback_msg or message_key)
    st.toast(msg, icon=icon)


def notify_admin_action(action_description, target_email=None):
    """
    Log and display an admin action notification.
    Records the event in the forensic audit trail.
    """
    log_security_event("ADMIN_ACTION", target_email, action_description)
    st.toast(f"⚙️ Admin: {action_description}", icon="⚙️")

# ─────────────────────────────────────────────
#  SECURITY ALERT SYSTEM
# ─────────────────────────────────────────────

def security_alert(event_type, target_email, details, severity=None):
    """
    Raise a security alert — logs to database and optionally displays to UI.
    
    Args:
        event_type: Key from EVENT_TYPES dict
        target_email: The identity involved
        details: Human-readable description of the event
        severity: Override severity (defaults to EVENT_TYPES mapping)
    """
    event_info = EVENT_TYPES.get(event_type, {"icon": "⚠️", "severity": "INFO", "label": event_type})
    final_severity = severity or event_info["severity"]
    
    # Persist to forensic database
    log_security_event(event_type, target_email, details, severity=final_severity)
    
    # Display critical alerts visually
    if final_severity == "CRITICAL":
        st.error(f"{event_info['icon']} **{event_info['label']}** — {details}")
    elif final_severity == "WARNING":
        st.warning(f"{event_info['icon']} **{event_info['label']}** — {details}")


def trigger_lockdown(reason, admin_email=None):
    """
    Activate the Global Lockdown protocol.
    Logs a CRITICAL event and returns lockdown status.
    """
    log_security_event(
        "LOCKDOWN_TRIGGERED", 
        admin_email, 
        f"Global Lockdown activated — Reason: {reason}",
        severity="CRITICAL"
    )
    st.error("🔒 **GLOBAL LOCKDOWN ENGAGED** — All non-admin operations have been suspended.")
    return True

# ─────────────────────────────────────────────
#  FORENSIC DISPLAY HELPERS
# ─────────────────────────────────────────────

def format_event_for_display(event_row):
    """
    Format a raw security_events database row into a display-ready dict.
    Expected row format: (id, timestamp, event_type, target_email, details, severity)
    """
    event_id, timestamp, event_type, target_email, details, severity = event_row
    event_info = EVENT_TYPES.get(event_type, {"icon": "📌", "label": event_type})
    
    return {
        "ID": event_id,
        "Timestamp": timestamp,
        "Icon": event_info["icon"],
        "Event": event_info["label"],
        "Identity": target_email or "SYSTEM",
        "Details": details,
        "Severity": severity,
    }


def get_severity_color(severity):
    """Return the CSS color for a severity level — matches the glassmorphism palette."""
    colors = {
        "INFO":     "#94FBAB",   # Mint-Teal
        "WARNING":  "#FFB347",   # Amber
        "CRITICAL": "#FF6B6B",   # Coral Red
    }
    return colors.get(severity, "#94FBAB")


def format_timestamp(timestamp_str):
    """Convert a raw timestamp into a human-friendly forensic format."""
    try:
        dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%d %b %Y • %H:%M:%S")
    except (ValueError, TypeError):
        return timestamp_str or "Unknown"


def get_admin_contact():
    """Return the system administrator contact information."""
    return "8910162728"
