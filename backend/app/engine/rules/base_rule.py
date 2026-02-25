from abc import ABC, abstractmethod
from typing import List, Optional
from ...models import NormalizedLog, Alert

class DetectionRule(ABC):
    def __init__(self, name: str, severity: str, threshold: int, window_seconds: int, mitre_technique: str = None, mitre_id: str = None):
        self.name = name
        self.severity = severity
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.mitre_technique = mitre_technique
        self.mitre_id = mitre_id

    @abstractmethod
    def evaluate(self, events: List[NormalizedLog]) -> List[Alert]:
        pass
