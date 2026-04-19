"""
╔══════════════════════════════════════════════════════════════╗
║  AEGIS-PORTAL: NEURAL API BRIDGE                            ║
║  api.py — FastAPI Backend for Native Mobile Integration     ║
║                                                              ║
║  This module exposes the core Aegis logic as a REST API,     ║
║  allowing native mobile apps to perform authentication,      ║
║  oracle analysis, and credit management securely.            ║
╚══════════════════════════════════════════════════════════════╝
"""

from fastapi import FastAPI, Depends, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
import os

# Import existing Aegis core logic
from database_logic import (
    authenticate_user, get_user_credits, use_credit, 
    fetch_accounts, save_account, check_status, log_security_event
)
from ai_analyser import get_oracle_analysis

app = FastAPI(
    title="Aegis Neural API",
    description="Forensic REST API for the Aegis-Portal Ecosystem",
    version="1.0.0"
)

# Enable CORS for Mobile App integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  MODELS
# ─────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

class OracleRequest(BaseModel):
    email: str
    payload_cipher: str

class VaultRequest(BaseModel):
    email: str
    master_key: str

# ─────────────────────────────────────────────
#  ENDPOINT: IDENTITY SYNCHRONIZATION
# ─────────────────────────────────────────────

@app.post("/identity/sync", tags=["Authentication"])
async def sync_identity(request: LoginRequest):
    """Verify an Identity Shard and return current status."""
    user_status = authenticate_user(request.email, request.password)
    
    if not user_status:
        log_security_event("API_AUTH_FAILURE", request.email, "Failed API authentication attempt", severity="WARNING")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identity synchronization failed. Invalid credentials."
        )
    
    credits = get_user_credits(request.email)
    
    return {
        "status": "synchronized",
        "identity": request.email,
        "standing": user_status,
        "ether_credits": credits
    }

# ─────────────────────────────────────────────
#  ENDPOINT: THE AEGIS ORACLE
# ─────────────────────────────────────────────

@app.post("/oracle/consult", tags=["Intelligence"])
async def consult_oracle(request: OracleRequest):
    """Perform adversarial entropy analysis on a credential payload."""
    # Check standing
    standing = check_status(request.email)
    if standing == 'lockdown' or standing == 'banned':
        raise HTTPException(status_code=403, detail="Identity is under lockdown or revoked.")
    
    # Consume credit
    if not use_credit(request.email):
        raise HTTPException(status_code=402, detail="Insufficient Ether-Credits.")
    
    analysis = get_oracle_analysis(request.payload_cipher)
    
    return {
        "analysis": analysis,
        "remaining_credits": get_user_credits(request.email)
    }

# ─────────────────────────────────────────────
#  ENDPOINT: VAULT RETRIEVAL
# ─────────────────────────────────────────────

@app.post("/vault/decrypt", tags=["Persistence"])
async def decrypt_vault(request: VaultRequest):
    """Retrieve and decrypt all shards associated with an identity."""
    data = fetch_accounts(request.email, request.master_key)
    
    if data is None:
        raise HTTPException(
            status_code=401,
            detail="Vault decryption failed. Invalid master key presented."
        )
    
    return {
        "shards_decrypted": len(data),
        "payload": data
    }

# ─────────────────────────────────────────────
#  SYSTEM STATUS
# ─────────────────────────────────────────────

@app.get("/status", tags=["System"])
async def system_status():
    """Check the health of the Neural API Bridge."""
    return {"status": "operational", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
