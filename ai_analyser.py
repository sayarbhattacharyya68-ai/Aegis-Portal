"""
╔══════════════════════════════════════════════════════════════╗
║  AEGIS-PORTAL: MULTI-AGENT INTELLIGENCE CORE                ║
║  ai_analyser.py — Powered Exclusively by Groq API           ║
║                                                              ║
║  Three Logic-Bound Agents:                                   ║
║    1. The Aegis Oracle   — Security Auditor (Llama-3.3)      ║
║    2. The Vision Sentinel — Transaction Verifier (Vision)    ║
║    3. The Shard Warden   — Access Control (Llama-3.3)        ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import base64
import json
import datetime
from groq import Groq

# ─────────────────────────────────────────────
#  GROQ CLIENT INITIALIZATION
# ─────────────────────────────────────────────

def _get_groq_client():
    """
    Initialize Groq client with API key from Streamlit secrets or .env.
    Streamlit Cloud uses st.secrets; local dev uses environment variables.
    """
    api_key = None
    
    # Priority 1: Streamlit secrets (for Streamlit Cloud deployment)
    try:
        import streamlit as st
        api_key = st.secrets.get("GROQ_API_KEY", None)
    except Exception:
        pass
    
    # Priority 2: Environment variable (for local development)
    if not api_key:
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
        api_key = os.getenv("GROQ_API_KEY")
    
    if not api_key:
        return None
    
    return Groq(api_key=api_key)


# ─────────────────────────────────────────────
#  AGENT 1: THE AEGIS ORACLE
#  Role: Security Auditor & Credential Entropy Analyst
#  Model: Llama-3.3-70B via Groq LPU™
# ─────────────────────────────────────────────

ORACLE_SYSTEM_PROMPT = """You are THE AEGIS ORACLE — an elite cybersecurity AI auditor embedded within 
the Aegis-Portal defense ecosystem. Your purpose is to perform rapid adversarial entropy analysis 
on credential payloads.

RESPONSE FORMAT (strict):
1. Begin with a tactical grade in brackets:
   - [FORTIFIED] — Excellent entropy, resistant to brute-force and dictionary attacks
   - [COMPROMISED] — Moderate weakness detected, exploitable under targeted attacks  
   - [CRITICAL] — Severe vulnerability, trivially crackable by automated tools

2. Follow with exactly THREE rapid-fire tactical opinions (max 8 words each), prefixed with ▸

3. End with a one-line RECOMMENDATION prefixed with ⚡

Example output:
[FORTIFIED]
▸ High entropy with mixed character classes
▸ No dictionary words or common patterns
▸ Length exceeds brute-force threshold
⚡ This credential meets military-grade standards.

RULES:
- NEVER repeat the password back in your response
- Focus on entropy, pattern analysis, and attack surface
- Be direct, tactical, and authoritative
- Use cybersecurity terminology"""

def get_oracle_analysis(password):
    """
    The Aegis Oracle performs adversarial entropy analysis on a credential.
    Returns a tactical security assessment with grade and recommendations.
    """
    client = _get_groq_client()
    if not client:
        return "[ERROR] ⚠️ Oracle neural link severed — Groq API key not configured. Navigate to Settings → Secrets."
    
    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": ORACLE_SYSTEM_PROMPT},
                {"role": "user", "content": f"Perform adversarial entropy analysis on this credential payload: {password}"}
            ],
            temperature=0.3,
            max_tokens=300,
            top_p=0.9,
        )
        return completion.choices[0].message.content
    except Exception as e:
        error_msg = str(e)
        if "rate_limit" in error_msg.lower():
            return "[ERROR] ⚠️ Oracle rate-limited — Too many consultations. Wait 60 seconds and retry."
        elif "invalid_api_key" in error_msg.lower() or "authentication" in error_msg.lower():
            return "[ERROR] ⚠️ Oracle authentication failed — Invalid Groq API key detected."
        else:
            return f"[ERROR] ⚠️ Oracle encountered an anomaly — {error_msg[:100]}"


def get_oracle_grade(analysis_text):
    """Extract the tactical grade from an Oracle analysis response."""
    if "[FORTIFIED]" in analysis_text:
        return "FORTIFIED", "#94FBAB"    # Mint-Teal
    elif "[COMPROMISED]" in analysis_text:
        return "COMPROMISED", "#FFB347"  # Amber
    elif "[CRITICAL]" in analysis_text:
        return "CRITICAL", "#FF6B6B"     # Coral Red
    elif "[ERROR]" in analysis_text:
        return "ERROR", "#FF6B6B"        # Coral Red
    else:
        return "ANALYZING", "#7064DF"    # Electric Violet


# ─────────────────────────────────────────────
#  AGENT 2: THE VISION SENTINEL
#  Role: Transaction Verifier & UPI Screenshot Analyst
#  Model: Llama-3.2-90B-Vision via Groq
# ─────────────────────────────────────────────

SENTINEL_SYSTEM_PROMPT = """You are THE VISION SENTINEL — a forensic transaction verification AI 
within the Aegis-Portal defense ecosystem. You analyze UPI payment screenshots to verify 
transaction authenticity.

RESPONSE FORMAT (strict JSON):
{
    "verdict": "VERIFIED" | "SUSPICIOUS" | "UNREADABLE",
    "confidence": 0.0 to 1.0,
    "amount_detected": "<amount found in screenshot or 'N/A'>",
    "upi_ref": "<UPI reference number if visible or 'N/A'>",
    "recipient_match": true | false,
    "findings": ["<finding 1>", "<finding 2>", "<finding 3>"]
}

VERIFICATION CRITERIA:
- Check if transaction shows status "Success" or "Completed"
- Verify the amount matches the expected value
- Look for recipient name "Sayar Bhattacharyya" or VPA "sayarbhattacharyya9@oksbi"
- Check for UPI reference/transaction ID
- Flag any signs of image manipulation (misaligned text, inconsistent fonts, artifacts)

RULES:
- Be forensically thorough
- If the image is unclear or cropped, verdict should be "UNREADABLE"
- If anything looks manipulated, verdict should be "SUSPICIOUS"
- Only "VERIFIED" if all criteria are clearly met"""


def verify_payment_screenshot(image_bytes, expected_amount):
    """
    The Vision Sentinel analyzes a UPI payment screenshot using Groq's 
    vision-capable model to verify transaction authenticity.
    
    Args:
        image_bytes: Raw bytes of the uploaded screenshot
        expected_amount: The expected transaction amount in INR
    
    Returns:
        dict with verdict, confidence, and findings
    """
    client = _get_groq_client()
    if not client:
        return {
            "verdict": "PENDING_ADMIN_REVIEW",
            "confidence": 0.0,
            "amount_detected": "N/A",
            "upi_ref": "N/A",
            "recipient_match": False,
            "findings": ["Vision Sentinel offline — Groq API key not configured. Falling back to manual admin review."]
        }
    
    try:
        # Encode image to base64 for the vision model
        b64_image = base64.b64encode(image_bytes).decode("utf-8")
        
        completion = client.chat.completions.create(
            model="llama-3.2-90b-vision-preview",
            messages=[
                {"role": "system", "content": SENTINEL_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"Analyze this UPI payment screenshot. "
                                f"Expected amount: ₹{expected_amount}. "
                                f"Expected recipient: Sayar Bhattacharyya (VPA: sayarbhattacharyya9@oksbi). "
                                f"Return your analysis in the specified JSON format."
                            )
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{b64_image}"
                            }
                        }
                    ]
                }
            ],
            temperature=0.1,
            max_tokens=500,
        )
        
        response_text = completion.choices[0].message.content
        
        # Attempt to parse JSON from response
        try:
            # Handle cases where model wraps JSON in markdown code blocks
            if "```json" in response_text:
                json_str = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                json_str = response_text.split("```")[1].split("```")[0].strip()
            else:
                json_str = response_text.strip()
            
            result = json.loads(json_str)
            
            # Ensure all expected keys exist
            result.setdefault("verdict", "UNREADABLE")
            result.setdefault("confidence", 0.0)
            result.setdefault("amount_detected", "N/A")
            result.setdefault("upi_ref", "N/A")
            result.setdefault("recipient_match", False)
            result.setdefault("findings", ["Analysis complete"])
            
            return result
            
        except (json.JSONDecodeError, IndexError):
            # If JSON parsing fails, return a structured fallback
            return {
                "verdict": "PENDING_ADMIN_REVIEW",
                "confidence": 0.0,
                "amount_detected": "N/A",
                "upi_ref": "N/A",
                "recipient_match": False,
                "findings": [
                    "Vision Sentinel returned unstructured response — falling back to manual review.",
                    f"Raw analysis: {response_text[:200]}"
                ]
            }
    
    except Exception as e:
        error_msg = str(e)
        # Graceful fallback for any vision model issues
        return {
            "verdict": "PENDING_ADMIN_REVIEW",
            "confidence": 0.0,
            "amount_detected": "N/A",
            "upi_ref": "N/A",
            "recipient_match": False,
            "findings": [f"Vision Sentinel encountered an anomaly: {error_msg[:150]}. Falling back to manual admin review."]
        }


def get_sentinel_verdict_display(verdict):
    """Get display properties for a Vision Sentinel verdict."""
    verdicts = {
        "VERIFIED":             {"icon": "✅", "color": "#94FBAB", "label": "Transaction Verified"},
        "SUSPICIOUS":           {"icon": "⚠️", "color": "#FFB347", "label": "Suspicious — Admin Review Required"},
        "UNREADABLE":           {"icon": "❓", "color": "#FFB347", "label": "Unreadable — Manual Verification Needed"},
        "PENDING_ADMIN_REVIEW": {"icon": "⏳", "color": "#7064DF", "label": "Pending Administrator Review"},
    }
    return verdicts.get(verdict, verdicts["PENDING_ADMIN_REVIEW"])


# ─────────────────────────────────────────────
#  AGENT 3: THE SHARD WARDEN
#  Role: Access Control, Behavioral Monitor & Lockdown Authority
#  Model: Llama-3.3-70B via Groq LPU™
# ─────────────────────────────────────────────

WARDEN_SYSTEM_PROMPT = """You are THE SHARD WARDEN — the autonomous access control intelligence of the 
Aegis-Portal ecosystem. You monitor identity behavior patterns and make tactical security decisions.

Your responsibilities:
1. Analyze login patterns for anomalous behavior
2. Assess threat levels for specific identities
3. Recommend ban/lockdown actions based on behavioral evidence
4. Generate security posture reports

RESPONSE FORMAT (strict JSON):
{
    "threat_level": "NOMINAL" | "ELEVATED" | "CRITICAL",
    "risk_score": 0.0 to 10.0,
    "assessment": "<one paragraph tactical assessment>",
    "recommended_action": "MONITOR" | "WARN" | "BAN" | "LOCKDOWN",
    "indicators": ["<indicator 1>", "<indicator 2>", "<indicator 3>"]
}

RULES:
- Be decisive but fair — false positives damage trust
- Consider the full behavioral context
- LOCKDOWN is reserved for system-wide threats only
- BAN requires strong evidence of malicious intent"""


def warden_assess_identity(email, event_history):
    """
    The Shard Warden performs a behavioral analysis on an identity 
    based on their recent security event history.
    
    Args:
        email: The identity to assess
        event_history: List of recent security events for this identity
    
    Returns:
        dict with threat assessment and recommended action
    """
    client = _get_groq_client()
    if not client:
        return {
            "threat_level": "NOMINAL",
            "risk_score": 0.0,
            "assessment": "Shard Warden offline — unable to perform behavioral analysis. Manual review recommended.",
            "recommended_action": "MONITOR",
            "indicators": ["Warden neural link severed — Groq API not configured"]
        }
    
    # Format event history for the Warden
    events_summary = "\n".join([
        f"  [{e[1]}] {e[2]}: {e[4]} (Severity: {e[5]})"
        for e in event_history[:20]  # Limit to last 20 events
    ]) if event_history else "  No events recorded for this identity."
    
    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": WARDEN_SYSTEM_PROMPT},
                {
                    "role": "user", 
                    "content": (
                        f"Perform behavioral threat assessment for identity: {email}\n\n"
                        f"Recent Security Events:\n{events_summary}\n\n"
                        f"Current timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"Return your assessment in the specified JSON format."
                    )
                }
            ],
            temperature=0.2,
            max_tokens=500,
        )
        
        response_text = completion.choices[0].message.content
        
        try:
            if "```json" in response_text:
                json_str = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                json_str = response_text.split("```")[1].split("```")[0].strip()
            else:
                json_str = response_text.strip()
            
            result = json.loads(json_str)
            result.setdefault("threat_level", "NOMINAL")
            result.setdefault("risk_score", 0.0)
            result.setdefault("assessment", "Assessment complete.")
            result.setdefault("recommended_action", "MONITOR")
            result.setdefault("indicators", [])
            return result
            
        except (json.JSONDecodeError, IndexError):
            return {
                "threat_level": "NOMINAL",
                "risk_score": 0.0,
                "assessment": f"Warden returned unstructured response: {response_text[:200]}",
                "recommended_action": "MONITOR",
                "indicators": ["Response parsing anomaly detected"]
            }
    
    except Exception as e:
        return {
            "threat_level": "NOMINAL",
            "risk_score": 0.0,
            "assessment": f"Warden encountered an error: {str(e)[:150]}",
            "recommended_action": "MONITOR",
            "indicators": ["Warden system error — manual oversight required"]
        }


def warden_heartbeat_check(all_users_data):
    """
    The Shard Warden performs a system-wide heartbeat analysis.
    Returns a summary of the overall security posture.
    
    Args:
        all_users_data: List of (email, credits, status, presence) tuples
    """
    total = len(all_users_data)
    active = sum(1 for u in all_users_data if u[2] == 'active')
    banned = sum(1 for u in all_users_data if u[2] == 'banned')
    online = sum(1 for u in all_users_data if '🟢' in u[3])
    
    if total == 0:
        posture = "DORMANT"
        posture_color = "#7064DF"
    elif banned / max(total, 1) > 0.3:
        posture = "ELEVATED THREAT"
        posture_color = "#FFB347"
    elif banned / max(total, 1) > 0.5:
        posture = "CRITICAL"
        posture_color = "#FF6B6B"
    else:
        posture = "NOMINAL"
        posture_color = "#94FBAB"
    
    return {
        "posture": posture,
        "posture_color": posture_color,
        "total_identities": total,
        "active_identities": active,
        "banned_identities": banned,
        "online_now": online,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_threat_level_display(threat_level):
    """Get display properties for a Warden threat level."""
    levels = {
        "NOMINAL":  {"icon": "🟢", "color": "#94FBAB", "label": "Nominal — No threats detected"},
        "ELEVATED": {"icon": "🟡", "color": "#FFB347", "label": "Elevated — Increased monitoring active"},
        "CRITICAL": {"icon": "🔴", "color": "#FF6B6B", "label": "Critical — Immediate action required"},
    }
    return levels.get(threat_level, levels["NOMINAL"])
