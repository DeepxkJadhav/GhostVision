import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional

from app.detector import AnomalyDetector
from app.threat_intel import ThreatIntelEnricher

app = FastAPI(
    title="GhostVision",
    version="1.0.0",
    description="AI Cyber Threat Intelligence & ML Anomaly Detection Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = AnomalyDetector()
enricher = ThreatIntelEnricher()

class TelemetryPayload(BaseModel):
    ip_address: Optional[str] = "10.0.4.15"
    dest_port: Optional[int] = 4444
    failed_login_count: Optional[int] = 8
    packet_entropy: Optional[float] = 7.4
    outbound_volume_mb: Optional[float] = 320.0

@app.get("/")
def root():
    static_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(static_file):
        return FileResponse(static_file)
    return {"service": "GhostVision", "status": "ONLINE"}

@app.post("/api/v1/analyze")
def analyze_telemetry_event(payload: TelemetryPayload):
    analysis = detector.analyze_telemetry(payload.dict())
    intel = enricher.enrich_event(analysis["threat_level"], ip_address=payload.ip_address)
    
    return {
        "telemetry_input": payload.dict(),
        "ml_anomaly_analysis": analysis,
        "threat_intelligence": intel,
        "verdict": "FLAGGED_ALERT" if analysis["is_anomalous"] else "BASELINE_CLEAN"
    }

@app.get("/api/v1/health")
def health():
    return {"status": "healthy", "service": "GhostVision", "ml_engine": "XGBoost + Neural Anomaly Ensemble"}
