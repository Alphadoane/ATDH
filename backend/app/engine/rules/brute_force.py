from typing import List
from datetime import datetime, timedelta
from .base_rule import DetectionRule
from ...models import NormalizedLog, Alert

class SSHBruteForceRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="SSH Brute Force",
            severity="High",
            threshold=5,
            window_seconds=120
        )

    def evaluate(self, events: List[NormalizedLog]) -> List[Alert]:
        alerts = []
        # Group by source IP
        ip_attempts = {}
        
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)

        for event in events:
            if event.event_type == "Failed Login" and event.timestamp > cutoff:
                ip_attempts[event.source_ip] = ip_attempts.get(event.source_ip, 0) + 1
        
        for ip, count in ip_attempts.items():
            if count >= self.threshold:
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Detected {count} failed login attempts from {ip} in {self.window_seconds}s.",
                    source_ip=ip,
                    risk_score=70
                ))
        
        return alerts
