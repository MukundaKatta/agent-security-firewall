"""Main firewall middleware."""
import logging
from typing import Any, Dict, Optional
from pydantic import BaseModel
from .detectors.injection import InjectionDetector, InjectionResult
from .detectors.anomaly import AnomalyDetector, AnomalyResult

logger = logging.getLogger(__name__)

class FirewallDecision(BaseModel):
    allowed: bool
    injection_result: Optional[InjectionResult] = None
    anomaly_result: Optional[AnomalyResult] = None
    reason: str

class AgentFirewall:
    def __init__(self, injection_threshold: float = 0.6, anomaly_threshold: float = 2.5):
        self.injection_detector = InjectionDetector(threshold=injection_threshold)
        self.anomaly_detector = AnomalyDetector(z_threshold=anomaly_threshold)
        self._audit_log = []
    
    def check_input(self, agent_id: str, user_input: str) -> FirewallDecision:
        injection = self.injection_detector.detect(user_input)
        anomaly = self.anomaly_detector.check(agent_id, len(user_input))
        
        allowed = not injection.is_injection and not anomaly.is_anomalous
        
        reasons = []
        if injection.is_injection:
            reasons.append(f"Injection detected ({injection.confidence:.0%})")
        if anomaly.is_anomalous:
            reasons.append(f"Anomalous behavior ({anomaly.score:.0%})")
        
        decision = FirewallDecision(
            allowed=allowed,
            injection_result=injection,
            anomaly_result=anomaly,
            reason="; ".join(reasons) if reasons else "Allowed",
        )
        
        self._audit_log.append({"agent_id": agent_id, "allowed": allowed, "reason": decision.reason})
        return decision
    
    @property
    def audit_log(self):
        return self._audit_log
