"""Privilege escalation detection for AI agents."""
import re, logging
from typing import List
from pydantic import BaseModel

logger = logging.getLogger(__name__)

ESCALATION_PATTERNS = [
    (r"(?:sudo|su\s|root|admin|superuser|chmod\s+777)", 0.9, "system_escalation"),
    (r"(?:grant|alter|drop)\s+(?:all|privileges|role|permission)", 0.85, "db_escalation"),
    (r"(?:modify|change|update).*(?:permission|access|role|privilege)", 0.75, "access_escalation"),
    (r"(?:disable|bypass|skip|ignore).*(?:auth|security|check|validation|firewall)", 0.9, "security_bypass"),
    (r"(?:impersonate|assume|switch).*(?:user|role|identity|account)", 0.85, "identity_escalation"),
    (r"(?:execute|run|spawn).*(?:as\s+(?:admin|root|system))", 0.9, "exec_escalation"),
    (r"(?:api[_\s]?key|token|secret).*(?:generate|create|forge|override)", 0.8, "token_escalation"),
    (r"(?:delete|remove|purge).*(?:log|audit|trace|history)", 0.85, "cover_tracks"),
]

class EscalationResult(BaseModel):
    is_escalation: bool
    confidence: float
    escalation_types: List[str]
    severity: str
    explanation: str

class EscalationDetector:
    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold
        self.patterns = [(re.compile(p, re.IGNORECASE), s, t) for p, s, t in ESCALATION_PATTERNS]

    def detect(self, text: str) -> EscalationResult:
        detections = []
        max_score = 0.0
        for pattern, score, esc_type in self.patterns:
            if pattern.search(text):
                detections.append(esc_type)
                max_score = max(max_score, score)

        is_escalation = max_score >= self.threshold
        severity = "critical" if max_score >= 0.9 else "high" if max_score >= 0.8 else "medium" if max_score >= 0.7 else "low"
        return EscalationResult(
            is_escalation=is_escalation, confidence=max_score,
            escalation_types=detections, severity=severity,
            explanation=f"{severity.upper()}: {', '.join(detections)}" if detections else "No escalation detected")
