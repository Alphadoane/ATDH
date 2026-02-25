from ..models import NormalizedLog, Alert

class RiskScorer:
    def calculate_risk(self, log: NormalizedLog) -> int:
        if log.event_type == "Failed Login":
            return 10
        elif log.event_type == "Process Creation":
            if "powershell" in (log.process_name or "").lower():
                return 40
            return 5
        return 1

    def calculate_alert_risk(self, alert: Alert) -> int:
        if alert.severity == "High":
            return 70
        elif alert.severity == "Critical":
            return 90
        elif alert.severity == "Medium":
            return 40
        return 20
