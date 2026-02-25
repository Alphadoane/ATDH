from typing import List
from datetime import datetime, timedelta
from .base_rule import DetectionRule
from ...models import NormalizedLog, Alert

class PortScanRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Port Scan Detection",
            severity="Medium",
            threshold=10,
            window_seconds=60,
            mitre_technique="Network Service Scanning",
            mitre_id="T1046"
        )

    def evaluate(self, events: List[NormalizedLog]) -> List[Alert]:
        alerts = []
        # Analyzes unique target indicators (IPs/Ports) found within the log stream
        # to identify scanning behavior patterns.
        ip_targets = {}
        
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)

        for event in events:
            if event.timestamp > cutoff and event.source_ip:
                if event.source_ip not in ip_targets:
                    ip_targets[event.source_ip] = set()
                
                # Identify unique destination signatures from raw log
                if "port" in (event.raw_log or "").lower():
                    ip_targets[event.source_ip].add(event.raw_log) 
        
        for ip, unique_events in ip_targets.items():
            if len(unique_events) >= self.threshold:
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Detected potential port scan from {ip} ({len(unique_events)} unique touches).",
                    source_ip=ip,
                    risk_score=40,
                    mitre_technique=self.mitre_technique,
                    mitre_id=self.mitre_id
                ))
        
        return alerts
