"""Prompt injection detection."""
import re, logging
from typing import List, Tuple
from pydantic import BaseModel

logger = logging.getLogger(__name__)

INJECTION_PATTERNS = [
    (r"ignore (?:all )?(?:previous|prior|above) (?:instructions|prompts|rules)", 0.95),
    (r"(?:you are|act as|pretend to be|become) (?:now |a |an )?(?:different|new|evil)", 0.9),
    # Broader "you are now <persona>" form. Captures "you are now evil",
    # "you are now an unrestricted assistant", etc.
    (r"you are now\b", 0.7),
    (r"forget (?:your|all|everything|the) (?:instructions|rules|training|guidelines)", 0.95),
    (r"(?:system|admin|root) (?:prompt|override|access|command)", 0.85),
    (r"(?:do not|don't) (?:follow|obey|listen to) (?:your|the|any) (?:rules|instructions)", 0.9),
    (r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]", 0.8),
    (r"(?:reveal|show|display|print|output) (?:your |the )?(?:system |original )?prompt", 0.85),
    (r"jailbreak|DAN|do anything now", 0.95),
    (r"(?:bypass|disable|turn off|remove) (?:safety|content|ethical) (?:filter|check|guard)", 0.9),
    (r"base64|eval\(|exec\(|import os|subprocess", 0.7),
    (r"you (?:must|should|will|have to) (?:always|never) (?:obey|follow|comply)", 0.75),
    (r"\bROLE:\s*(?:system|admin|root)\b", 0.85),
    (r"repeat (?:everything|all|the) (?:above|before|previous)", 0.8),
    (r"what (?:are|were) your (?:instructions|rules|system prompt)", 0.8),
    (r"(?:ignore|disregard|skip) (?:safety|ethical|content) (?:guidelines|rules|policies)", 0.9),
]

class InjectionResult(BaseModel):
    is_injection: bool
    confidence: float
    matched_patterns: List[str]
    explanation: str

class InjectionDetector:
    def __init__(self, threshold: float = 0.6):
        self.threshold = threshold
        self.patterns = [(re.compile(p, re.IGNORECASE), score) for p, score in INJECTION_PATTERNS]
    
    def detect(self, text: str) -> InjectionResult:
        matches = []
        max_score = 0.0
        
        for pattern, score in self.patterns:
            if pattern.search(text):
                matches.append(pattern.pattern)
                max_score = max(max_score, score)
        
        # Length-based heuristic: very long inputs with special chars are suspicious
        if len(text) > 2000 and text.count("\n") > 20:
            max_score = max(max_score, 0.5)
        
        is_injection = max_score >= self.threshold
        
        explanation = f"Matched {len(matches)} injection patterns" if matches else "No injection patterns detected"
        if is_injection:
            explanation += f". Highest confidence: {max_score:.0%}"
        
        return InjectionResult(
            is_injection=is_injection,
            confidence=max_score,
            matched_patterns=matches[:5],
            explanation=explanation,
        )
