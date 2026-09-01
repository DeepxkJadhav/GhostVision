from fastapi.testclient import TestClient
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.main import app

client = TestClient(app)

def test_health():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_anomaly_detection():
    res = client.post("/api/v1/analyze", json={
        "ip_address": "192.168.1.50",
        "dest_port": 4444,
        "failed_login_count": 9,
        "packet_entropy": 7.8,
        "outbound_volume_mb": 400.0
    })
    assert res.status_code == 200
    data = res.json()
    assert data["ml_anomaly_analysis"]["is_anomalous"] is True
    assert "mitre_att_ck" in data["threat_intelligence"]
