from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import random

app = FastAPI(title="PhishGuard SOC API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "ok", "service": "PhishGuard SOC API"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/soc")
def get_soc_events():
    events = []
    threat_types = ["phishing", "malware", "ransomware", "credential_theft", "social_engineering"]
    severities = ["critical", "high", "medium", "low"]
    
    for i in range(20):
        events.append({
            "id": f"EVT-{1000+i}",
            "timestamp": datetime.now().isoformat(),
            "threat_type": random.choice(threat_types),
            "severity": random.choice(severities),
            "source_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            "destination": f"user{random.randint(1,100)}@company.com",
            "status": random.choice(["detected", "blocked", "investigating"]),
            "description": f"Suspicious activity detected - Event {i+1}"
        })
    return {"events": events, "total": len(events)}

@app.get("/soc-metrics")
def get_metrics():
    return {
        "total_threats": random.randint(150, 300),
        "blocked": random.randint(100, 200),
        "investigating": random.randint(10, 30),
        "resolved": random.randint(50, 100),
        "critical_count": random.randint(5, 15),
        "high_count": random.randint(20, 40),
        "medium_count": random.randint(40, 80),
        "low_count": random.randint(30, 60)
    }

@app.get("/tenant")
def get_tenant():
    return {"tenant_id": "default", "name": "PhishGuard SOC", "status": "active"}
