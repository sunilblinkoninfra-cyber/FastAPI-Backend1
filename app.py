from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel
from typing import List
from datetime import datetime, timedelta
import os

# =====================
# CONFIG
# =====================
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_THIS_IN_PROD")
JWT_ALGO = "HS256"
TOKEN_EXPIRE_MINUTES = 60

# =====================
# APP
# =====================
app = FastAPI(
    title="SOC Phishing Platform API",
    version="1.0.0",
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# =====================
# MODELS
# =====================
class TokenData(BaseModel):
    sub: str
    role: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class EmailScan(BaseModel):
    subject: str
    body: str
    urls: List[str] = []

# =====================
# AUTH HELPERS
# =====================
def create_token(user_id: str, role: str):
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenData:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return TokenData(**payload)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

def require_role(*allowed_roles):
    def checker(user: TokenData = Depends(get_current_user)):
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user
    return checker

# =====================
# HEALTH
# =====================
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "SOC Phishing Platform",
        "timestamp": datetime.utcnow().isoformat(),
    }

# =====================
# AUTH
# =====================
@app.post("/token", response_model=LoginResponse)
def login():
    """
    Demo token endpoint.
    Replace with real auth later.
    """
    return {
        "access_token": create_token("user-123", "analyst"),
    }

# =====================
# PROTECTED ROUTES
# =====================
@app.post("/scan")
def scan_email(
    email: EmailScan,
    user: TokenData = Depends(require_role("analyst", "admin")),
):
    score = 0
    keywords = ["urgent", "verify", "password", "login"]
    content = (email.subject + email.body).lower()

    for k in keywords:
        if k in content:
            score += 20

    return {
        "requested_by": user.sub,
        "role": user.role,
        "risk_score": min(score, 100),
        "verdict": "PHISHING" if score >= 60 else "SAFE",
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.get("/soc-metrics")
def soc_metrics(
    user: TokenData = Depends(require_role("admin")),
):
    return {
        "total_threats": 245,
        "blocked": 180,
        "investigating": 42,
        "critical": 23,
        "requested_by": user.sub,
    }

@app.get("/tenant")
def tenant_info(
    user: TokenData = Depends(require_role("admin", "analyst")),
):
    return {
        "tenant_id": "default",
        "name": "PhishGuard SOC",
        "status": "active",
    }
