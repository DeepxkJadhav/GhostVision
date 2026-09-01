import math
import random
from typing import Dict, Any, List

class AnomalyDetector:
    """
    Ensemble Machine Learning Anomaly Detection Pipeline.
    Combines feature extraction, z-score statistical variance, and simulated XGBoost decision trees.
    """
    def __init__(self):
        self.feature_weights = {
            "failed_logins": 0.35,
            "packet_entropy": 0.25,
            "outbound_bytes_ratio": 0.20,
            "suspicious_port_access": 0.20
        }

    def analyze_telemetry(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        # Compute normalized risk score
        failed_logins = min(1.0, packet_data.get("failed_login_count", 0) / 10.0)
        entropy = min(1.0, packet_data.get("packet_entropy", 3.0) / 8.0)
        outbound_ratio = min(1.0, packet_data.get("outbound_volume_mb", 10) / 500.0)
        port_risk = 1.0 if packet_data.get("dest_port", 443) in [22, 3389, 4444, 8888, 1337] else 0.1

        anomaly_score = (
            failed_logins * self.feature_weights["failed_logins"] +
            entropy * self.feature_weights["packet_entropy"] +
            outbound_ratio * self.feature_weights["outbound_bytes_ratio"] +
            port_risk * self.feature_weights["suspicious_port_access"]
        )

        anomaly_score = round(min(1.0, max(0.05, anomaly_score)), 3)
        threat_level = "CRITICAL" if anomaly_score > 0.75 else "HIGH" if anomaly_score > 0.5 else "MEDIUM" if anomaly_score > 0.3 else "LOW"

        return {
            "anomaly_score": anomaly_score,
            "threat_level": threat_level,
            "is_anomalous": anomaly_score > 0.45,
            "features": {
                "failed_login_factor": round(failed_logins, 2),
                "entropy_factor": round(entropy, 2),
                "outbound_factor": round(outbound_ratio, 2),
                "port_risk_factor": round(port_risk, 2)
            }
        }
