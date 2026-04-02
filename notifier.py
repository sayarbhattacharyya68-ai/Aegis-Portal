import datetime 
import streamlit as st

def notify_user(message, type="info"):
    if type == "success":
        st.toast(f"✅ {message}")
    elif type == "error":
        st.error(f"🚨 {message}")
    elif type == "warning":
        st.warning(f"⚠️ {message}")
    else:
        st.info(f"ℹ️ {message}")

def get_admin_contact():
    return "8910162728"

def display_oracle_opinion(rating, opinion):
    if "[STRONG]" in rating.upper():
        st.success(f"**ORACLE STATUS:** STRONG")
    else:
        st.warning(f"**ORACLE STATUS:** WEAK")
    st.write(f"**Tactical Opinions:** _{opinion}_")

def security_alert(event_name, user_email):
    # Now this line will work because datetime is imported
    print(f"[SECURITY CRITICAL] {datetime.datetime.now()} | {event_name} | Target: {user_email}")