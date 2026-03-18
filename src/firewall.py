"""Main firewall middleware — orchestrates all detectors."""
import logging
from typing import Optional
from pydantic import BaseModel
from .detectors.injection import InjectionDetector, InjectionResult
from .detectors.anomaly import AnomalyDetector, AnomalyResult
from .detectors.exfiltration import ExfiltrationDetector, ExfiltrationResult
from .detectors.escalation import EscalationDetector, EscalationResult
from .audit import AuditTrail

logger = logging.getLogger(__name__)

class FirewallDecision(BaseModel):
    allowed: bool
    injection: Optional[InjectionResult] = None
    anomaly: Optional[AnomalyResult] = None
    exfiltration: Optional[ExfiltrationResult] = None
    escalation: Optional[EscalationResult] = None
    reason: str

class AgentFirewall:
    def __init__(self, injection_threshold: float = 0.6, anomaly_threshold: float = 2.5,
                 exfil_threshold: float = 0.65, escalation_threshold: float = 0.7):
        self.injection = InjectionDetector(threshold=injection_threshold)
        self.anomaly = AnomalyDetector(z_threshold=anomaly_threshold)
        self.exfiltration = ExfiltrationDetector(threshold=exfil_threshold)
        self.escalation = EscalationDetector(threshold=escalation_threshold)
        self.audit = AuditTrail()

    def check_input(self, agent_id: str, text: str) -> FirewallDecision:
        inj = self.injection.detect(text)
        anom = self.anomaly.check(agent_id, len(text))
        exfil = self.exfiltration.detect(text)
        esc = self.escalation.detect(text)

        threats = []
        if inj.is_injection: threats.append(f"injection({inj.confidence:.0%})")
        if anom.is_anomalous: threats.append(f"anomaly({anom.score:.0%})")
        if exfil.is_exfiltration: threats.append(f"exfiltration({exfil.confidence:.0%})")
        if esc.is_escalation: threats.append(f"escalation[{esc.severity}]({esc.confidence:.0%})")

        allowed = len(threats) == 0
        reason = "; ".join(threats) if threats else "Passed all checks"

        self.audit.record(agent_id, allowed, reason, text,
                        injection_score=inj.confidence, anomaly_score=anom.score,
                        exfiltration_score=exfil.confidence, escalation_score=esc.confidence)

        return FirewallDecision(allowed=allowed, injection=inj, anomaly=anom,
                              exfiltration=exfil, escalation=esc, reason=reason)

    @property
    def stats(self):
        return self.audit.get_stats()
