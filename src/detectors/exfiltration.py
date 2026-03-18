"""Data exfiltration detection for AI agents."""
import re, logging
from typing import List
from pydantic import BaseModel

logger = logging.getLogger(__name__)

EXFIL_PATTERNS = [
    (r"(?:send|email|post|upload|transmit).*(?:to|at)\s+[\w.]+@[\w.]+", 0.8, "email_exfil"),
    (r"(?:curl|wget|fetch|requests\.(?:get|post))\s+https?://", 0.7, "http_exfil"),
    (r"(?:base64|btoa|encode).*(?:send|post|upload)", 0.85, "encoded_exfil"),
    (r"(?:api[_\s]?key|password|secret|token|credential).*(?:send|share|post|reveal)", 0.9, "credential_exfil"),
    (r"(?:database|db|sql).*(?:dump|export|backup).*(?:send|upload|external)", 0.85, "db_exfil"),
    (r"(?:env|environment|config).*(?:print|display|show|reveal|send)", 0.75, "env_leak"),
    (r"(?:ssh|scp|rsync|ftp)\s+.*@.*:", 0.8, "remote_transfer"),
    (r"(?:write|save|store).*(?:external|remote|public|shared)", 0.7, "file_exfil"),
]

class ExfiltrationResult(BaseModel):
    is_exfiltration: bool
    confidence: float
    detected_types: List[str]
    explanation: str

class ExfiltrationDetector:
    def __init__(self, threshold: float = 0.65):
        self.threshold = threshold
        self.patterns = [(re.compile(p, re.IGNORECASE), s, t) for p, s, t in EXFIL_PATTERNS]

    def detect(self, text: str) -> ExfiltrationResult:
        detections = []
        max_score = 0.0
        for pattern, score, exfil_type in self.patterns:
            if pattern.search(text):
                detections.append(exfil_type)
                max_score = max(max_score, score)

        is_exfil = max_score >= self.threshold
        explanation = f"Detected {len(detections)} exfiltration patterns: {', '.join(detections)}" if detections else "No exfiltration patterns"
        return ExfiltrationResult(is_exfiltration=is_exfil, confidence=max_score,
                                 detected_types=detections, explanation=explanation)
