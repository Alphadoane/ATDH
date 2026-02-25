from abc import ABC, abstractmethod
from typing import List, Optional
from ...models import NormalizedLog, Alert

class DetectionRule(ABC):
    def __init__(self, name: str, severity: str, threshold: int, window_seconds: int):
        self.name = name
        self.severity = severity
        self.threshold = threshold
        self.window_seconds = window_seconds

    @abstractmethod
    def evaluate(self, events: List[NormalizedLog]) -> List[Alert]:
        pass
