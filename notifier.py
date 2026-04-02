import datetime
import streamlit as st

def notify_user(message, type="info"):
    if type == "success": st.toast(f"✅ {message}")
    elif type == "error": st.error(f"🚨 {message}")
    elif type == "warning": st.warning(f"⚠️ {message}")
    else: st.info(f"ℹ️ {message}")

def get_admin_contact():
    return "8910162728"

def security_alert(event_name, user_email):
    print(f"[SECURITY CRITICAL] {datetime.datetime.now()} | {event_name} | Target: {user_email}")
