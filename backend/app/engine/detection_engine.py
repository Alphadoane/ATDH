from typing import List
from ..models import NormalizedLog, Alert
from .rules.brute_force import SSHBruteForceRule
from .rules.port_scan import PortScanRule
from .rules.suspicious_process import SuspiciousProcessRule

class DetectionEngine:
    def __init__(self):
        self.rules = [
            SSHBruteForceRule(),
            PortScanRule(),
            SuspiciousProcessRule()
        ]

    def process_events(self, events: List[NormalizedLog]) -> List[Alert]:
        all_alerts = []
        for rule in self.rules:
            alerts = rule.evaluate(events)
            all_alerts.extend(alerts)
        return all_alerts
