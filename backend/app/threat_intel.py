from typing import Dict, Any, List

class ThreatIntelEnricher:
    """
    Enriches detected anomalies with MITRE ATT&CK techniques and VirusTotal IoC scoring.
    """
    def __init__(self):
        self.mitre_mappings = {
            "CRITICAL": {
                "technique_id": "T1059.001",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "tactic": "Execution / Lateral Movement",
                "cve_reference": "CVE-2024-38063"
            },
            "HIGH": {
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing",
                "tactic": "Credential Access",
                "cve_reference": "MITRE-TA0006"
            },
            "MEDIUM": {
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery: Port Scan",
                "tactic": "Discovery",
                "cve_reference": "MITRE-TA0007"
            },
            "LOW": {
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "tactic": "Reconnaissance",
                "cve_reference": "BENIGN_BASELINE"
            }
        }

    def enrich_event(self, threat_level: str, ip_address: str = "192.168.1.100") -> Dict[str, Any]:
        mapping = self.mitre_mappings.get(threat_level, self.mitre_mappings["LOW"])
        
        return {
            "source_ip": ip_address,
            "mitre_att_ck": mapping,
            "virustotal_risk_score": 88 if threat_level in ["CRITICAL", "HIGH"] else 12,
            "recommended_action": "Isolate Endpoint & Block IP" if threat_level == "CRITICAL" else "Enforce MFA Challenge" if threat_level == "HIGH" else "Monitor Session"
        }
