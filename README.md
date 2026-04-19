# Aegis-Portal (ACRE)

Aegis-Portal is a high-security, research-driven credential management and risk-analysis ecosystem. Developed as an Innovative Project (PRJCS681), the platform serves as a production-ready interface for encrypting sensitive "shards" (credentials) while utilizing a custom Ether-Credit (EC) resource economy.

The system bridges the gap between traditional vaulting and modern AI-driven defense, moving beyond simple storage into a **Zero-Knowledge Architecture** featuring real-time adversarial auditing and a **Multi-Agent Intelligence Core**.

---

### 1. Zero-Knowledge Cryptographic Architecture
- **Volatile Key Management**: The master key is completely removed from persistent server-side storage. Encryption keys are generated in the system's volatile memory (`st.session_state`) and are **destroyed instantly** upon logout. No "keys to the kingdom" exist on the disk.
- **Client-Side Decryption**: The "Archive Vault" strictly requires the manual entry of a Secret Shard Key. Without this specific key, the data remains mathematically unrecoverable, upholding military-grade privacy standards.
- **Global Status Enforcement**: Persistent status checks monitor identities. If an Admin bans an identity, the system triggers an instant "kill-switch" (Global Lockdown) that locks access to the AI Oracle and Archive Vault modules for that active session.

### 2. Multi-Agent Intelligence Core (Powered by Groq LPU™)
The entire intelligence core has been rewritten to utilize Groq API exclusively, achieving sub-second inference times via three autonomous agents:
- 🔮 **The Aegis Oracle**: Performs adversarial entropy analysis on credentials. Explicitly categorizes payloads as `[FORTIFIED]`, `[COMPROMISED]`, or `[CRITICAL]`, followed by rapid-fire tactical security opinions.
- 👁️ **The Vision Sentinel**: An autonomous transaction verifier that uses Groq's Vision models (Llama-3.2-90B-Vision) to forensically analyze UPI screenshots and extract transaction verdicts.
- 🛡️ **The Shard Warden**: A behavioral monitor that assesses an identity's threat level based on their forensic audit trail and recommends lockdowns or bans.

### 3. Economy & "Credit-Bay" 2.0
- **Calibrated Exchange**: The economy is fixed at ₹10 = 1 Ether-Gem (EC). The UI dynamically calculates gem value based on the INR amount entered.
- **AI + Human-in-the-loop (HITL)**: Users upload a "Transaction Shard" (screenshot). The Vision Sentinel performs an initial AI verification, and the transaction is queued for final Administrator sign-off.
- **Admin Dispenser**: Admins can manually grant Ether-Credits to any user identity for research testing or system rewards.

### 4. Forensics & Admin Terminal
- **Live Presence Heartbeat**: Real-time indicators show whether an identity is Online 🟢 (active within 2 minutes) or Offline ⚪.
- **Forensic Event Logging**: A new structured SQL table (`security_events`) tracks every critical event—auth successes, failures, vault access, and lockdown triggers—with severity levels (INFO, WARNING, CRITICAL).
- **Warden Threat Assessment**: Admins can instantly query the Shard Warden to generate a risk score and behavioral threat assessment for any specific identity.

### 5. UI/UX: The Glassmorphism Command Center
- **Aesthetic Identity**: Completely redesigned using a high-end **Glassmorphism** theme. Features frosted glass containers, Z-axis depth shadowing, and Mint-Teal interactive glows.
- **Dynamic Mesh Gradients**: CSS-driven fluid backgrounds using the signature palette (Deep Indigo, Electric Violet, Mint-Teal).
- **Immersive Language**: Standard UI copy replaced with immersive cybersecurity phrasing (e.g., "Forge Shard", "Sever Connection", "Identity Synchronized").
- **Progressive Web App (PWA)**: The platform is now installable on mobile devices (Android/iOS) with a custom 3D high-res app icon.

---

## 📂 System Architecture
```text
📁 AEGIS_PORTAL
├── main.py                 # Primary UI Orchestrator & Command Center
├── database_logic.py       # SQL Logic, AES Encryption & Persistence Engine
├── ai_analyser.py          # Groq Multi-Agent Intelligence Core
├── notifier.py             # Forensic Logging & Signal Layer
├── manifest.json           # PWA Web App Manifest
├── sw.js                   # PWA Service Worker
├── vault.db                # Local Encrypted Database (DO NOT COMMIT)
└── audit_screenshots/      # Repository for payment verification (DO NOT COMMIT)
```

## ⚙️ Deployment Instructions (Streamlit Cloud)
1. Fork or clone this repository.
2. Deploy the app via [Streamlit Community Cloud](https://share.streamlit.io).
3. **CRITICAL**: Configure your secrets in the Streamlit Dashboard (App Settings -> Secrets):
```toml
GROQ_API_KEY = "gsk_your_actual_api_key_here"
ADMIN_KEY = "Sayar_Admin_2026"
```
*(Do not use GitHub Repository Secrets. The app checks `st.secrets` first, then falls back to `.env` for local testing).*

## 🔑 Presentation Reference (Admin)
```
[REDACTED]
PRJCS681
```

## 🛡️ Security Disclaimer
This application was developed as a research project into Autonomous Cyber-Physical Resilience. It is intended for educational and research presentation purposes. Any attempt to manipulate the payment system or bypass encryption results in the immediate revocation of the Shard Identity.

**Developer**: Sayar Bhattacharyya
*Computer Science Engineering @ IEM, Kolkata.*
