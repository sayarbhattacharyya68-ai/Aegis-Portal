Aegis-Portal: Autonomous Cyber-Physical Resilience Engine (ACRE)
Aegis-Portal is a high-security, AI-driven credential management and risk-analysis ecosystem. Built for research in Applied Cryptography and Adversarial AI, the platform provides a production-ready interface for encrypting sensitive shards (account credentials) while utilizing a custom Ether-Credit (EC) economy. It features a sophisticated, vector-flat themed dashboard and an integrated AI Oracle for real-time security auditing.

🚀 Key Features & Modules
1. Secure Identity & Shard Encryption
Encrypted Authentication: Uses bcrypt for salted password hashing during login/registration, ensuring that user identities are protected from the database level.

Military-Grade Vaulting: Implements AES-256 (Fernet) encryption for all stored credentials. Each user must provide a Master Cipher-Key to decrypt their data; the server never stores plain-text keys.

Shard Isolation: Each user's data is strictly isolated within a SQLite-powered backend, preventing cross-tenant data leaks.

2. The AI Oracle (Powered by Llama-3.3 & Groq)
Real-time Security Auditing: Integrates the Llama-3.3-70B model via the Groq API to perform tactical analysis of password payloads.

Vulnerability Assessment: The Oracle provides a security grade and a one-sentence tactical recommendation for every entry before it is archived in the vault.

Adversarial Prevention: Designed to detect and warn against common LLM vulnerabilities and weak entropy patterns.

3. Ether-Credit (EC) Economy & Credit-Bay
Resource-Gated AI Usage: Access to the AI Oracle is regulated by "Ether-Credits." This simulates a SaaS environment where high-compute tasks are metered.

AI-Verified Recharge System: Features a "Credit-Bay" where users can recharge EC.

Vision-Based Verification: Implements Gemini-1.5-Flash (Vision AI) to scan uploaded UPI payment screenshots. The AI autonomously verifies the status (Success), the recipient (Sayar Bhattacharyya), and the transaction amount before updating the database.

4. Admin Control & Revocation Terminal
Identity Revocation: A hidden Admin Terminal (protected by a Master Admin Key) allows for the immediate banning of fraudulent users.

Transaction Audit Log: Admins have access to a full audit trail of all payment attempts, including timestamps and success/failure logs, to manually verify legitimacy.

Global Lockdown: Once a user is banned, a Security Lockdown protocol instantly revokes access to the AI Oracle and Archive Vault modules, even if the user has a valid session.

5. Aesthetic & UX Design
Flat-Vector Theme: A custom-designed UI using a Purple, Pink, and Mint-Teal palette inspired by modern flat-vector illustrations.

High-Contrast Readability: Optimized CSS for high visibility, featuring dark-indigo text labels on pastel input fields to ensure a seamless professional experience.

🛠️ Tech Stack
Frontend: Streamlit (Custom CSS injected for Vector-Flat styling)

Backend: Python 3.10+

Database: SQLite3

Cryptography: cryptography (Fernet/AES), bcrypt

LLM Integration: Groq (Llama-3.3-70B), Google Generative AI (Gemini-1.5-Flash for Vision)

Environment Management: python-dotenv

Image Processing: Pillow (PIL)

📂 System Architecture:
📁 SECURE_PASSWORD_MANAGER
 
 ├── main.py              # Central UI & Module Controller

 ├── database_logic.py    # SQL Logic, AES Encryption & Auth
 
 ├── ai_analyser.py       # Groq (Text) & Gemini (Vision) Integration
 
 ├── .env                 # API Keys & Secrets (Groq/Google)
 
 ├── vault.db             # Local Encrypted Database
 
 ├── secret.key           # Fernet Encryption Key
 
 └── my_upi_qr.jpeg       # Payment Gateway QR Asset

⚠️ Security Disclaimer
This application is developed as a part of a research project into Autonomous Cyber-Physical Resilience. All payment simulations are intended for research presentation purposes. Fraudulent activity or manipulation of the payment screenshot system results in immediate revocation of Shard Identity and data access.
