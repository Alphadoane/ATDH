from typing import List
from .base_rule import DetectionRule
from ...models import NormalizedLog, Alert

class SuspiciousProcessRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Suspicious Process Execution",
            severity="High",
            threshold=1,
            window_seconds=0 # Immediate
        )

    def evaluate(self, events: List[NormalizedLog]) -> List[Alert]:
        alerts = []
        suspicious_keywords = ["powershell -enc", "base64", "encodedcommand", "mimikatz", "vssadmin delete shadows"]

        for event in events:
            proc_name = (event.process_name or "").lower()
            raw = (event.raw_log or "").lower()
            
            is_suspicious = any(kw in raw for kw in suspicious_keywords) or "powershell" in proc_name
            
            if is_suspicious:
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Suspicious process execution: {event.process_name} by {event.username}",
                    source_ip=event.source_ip,
                    risk_score=80
                ))
        
        return alerts
