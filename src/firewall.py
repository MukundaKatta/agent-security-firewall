"""Three-mode firewall for AI agents.

This module exposes:

    AgentFirewall   - back-compat: legacy inbound-only firewall used by api.py
    Firewall        - new 0.2 unified facade with three modes:
                       * inbound    (untrusted text the model is about to read)
                       * tool_call  (RBAC + action sandbox + rate limit)
                       * egress     (delegated to a user callable, typically agentguard)

agent-security-firewall is the inbound + tool-call sibling of agentguard.
Egress is intentionally delegated: agentguard already does that one thing well.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel

from .audit import AuditTrail
from .detectors.anomaly import AnomalyDetector, AnomalyResult
from .detectors.escalation import EscalationDetector, EscalationResult
from .detectors.exfiltration import ExfiltrationDetector, ExfiltrationResult
from .detectors.injection import InjectionDetector, InjectionResult
from .policies.access_control import (
    AccessController,
    Permission,
    Principal,
    Role,
)
from .policies.action_sandbox import ActionSandbox, SandboxPolicy
from .policies.rate_limiter import RateLimitConfig, RateLimiter

logger = logging.getLogger(__name__)


# ----- legacy inbound-only API (kept so api.py and old callers still work) ---

class FirewallDecision(BaseModel):
    allowed: bool
    injection: Optional[InjectionResult] = None
    anomaly: Optional[AnomalyResult] = None
    exfiltration: Optional[ExfiltrationResult] = None
    escalation: Optional[EscalationResult] = None
    reason: str


class AgentFirewall:
    """Legacy inbound-only firewall, retained for the existing FastAPI route."""

    def __init__(
        self,
        injection_threshold: float = 0.6,
        anomaly_threshold: float = 2.5,
        exfil_threshold: float = 0.65,
        escalation_threshold: float = 0.7,
    ):
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
        if inj.is_injection:
            threats.append(f"injection({inj.confidence:.0%})")
        if anom.is_anomalous:
            threats.append(f"anomaly({anom.score:.0%})")
        if exfil.is_exfiltration:
            threats.append(f"exfiltration({exfil.confidence:.0%})")
        if esc.is_escalation:
            threats.append(f"escalation[{esc.severity}]({esc.confidence:.0%})")

        allowed = len(threats) == 0
        reason = "; ".join(threats) if threats else "Passed all checks"

        self.audit.record(
            agent_id,
            allowed,
            reason,
            text,
            injection_score=inj.confidence,
            anomaly_score=anom.score,
            exfiltration_score=exfil.confidence,
            escalation_score=esc.confidence,
        )

        return FirewallDecision(
            allowed=allowed,
            injection=inj,
            anomaly=anom,
            exfiltration=exfil,
            escalation=esc,
            reason=reason,
        )

    @property
    def stats(self):
        return self.audit.get_stats()


# ----- 0.2 unified three-mode Firewall ---------------------------------------

# Egress checks are intentionally delegated to a user-supplied callable. The
# expected shape lines up with agentguard.check: (url, opts) -> Decision-like.
EgressCheck = Callable[[str, Dict[str, Any]], Any]


@dataclass
class FirewallResult:
    """Outcome of any of the three Firewall.check_* calls."""

    mode: str  # 'inbound' | 'tool_call' | 'egress'
    allowed: bool
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


class Firewall:
    """Composable inbound + tool-call firewall for AI agents.

    Three modes:

        check_inbound(agent_id, text)
            Scrub untrusted text the model is about to read (user message,
            scraped webpage, retrieved document, tool output that came back
            from an external source). Catches: prompt injection, exfiltration
            language, escalation language, behavioral anomalies in length.

        check_tool_call(agent_id, tool, args=None)
            Validate a proposed tool call. Catches: RBAC violations
            (agent can't invoke this tool), action sandbox violations
            (dangerous shell/eval/etc. inside args), rate-limit busts.

        check_egress(url, method='GET', egress_check=...)
            Optional pluggable hook for the egress mode. agent-security-firewall
            does NOT do egress itself; pass agentguard.check (or any callable
            with the same shape). Returned for free so a host application can
            put all three behind one Firewall object.

    Construct once, share across the process. Thread-safe enough for typical
    single-process agent runtimes; not designed for shared-memory clustering.
    """

    def __init__(
        self,
        *,
        injection_threshold: float = 0.6,
        anomaly_threshold: float = 2.5,
        exfil_threshold: float = 0.65,
        escalation_threshold: float = 0.7,
        rate_limit: Optional[RateLimitConfig] = None,
        default_sandbox: Optional[SandboxPolicy] = None,
        egress_check: Optional[EgressCheck] = None,
    ):
        # Inbound detectors.
        self._injection = InjectionDetector(threshold=injection_threshold)
        self._anomaly = AnomalyDetector(z_threshold=anomaly_threshold)
        self._exfil = ExfiltrationDetector(threshold=exfil_threshold)
        self._escalation = EscalationDetector(threshold=escalation_threshold)

        # Tool-call enforcement.
        self._access = AccessController()
        self._sandbox = ActionSandbox(default_policy=default_sandbox)
        self._rate = RateLimiter(default_config=rate_limit)

        # Optional egress delegate.
        self._egress_check = egress_check

        # Audit trail (shared across modes).
        self._audit = AuditTrail()
        self._results: List[FirewallResult] = []

    # ----- principal / policy registration -------------------------------

    @property
    def access(self) -> AccessController:
        """Direct handle to the access controller for registering principals/policies."""
        return self._access

    @property
    def sandbox(self) -> ActionSandbox:
        """Direct handle to the action sandbox for per-agent policies/rollbacks."""
        return self._sandbox

    @property
    def rate(self) -> RateLimiter:
        """Direct handle to the rate limiter for per-agent/per-action limits."""
        return self._rate

    def register_agent(
        self,
        agent_id: str,
        name: str = "",
        *,
        extra_permissions: Optional[set] = None,
        sandbox_policy: Optional[SandboxPolicy] = None,
        rate_limit: Optional[RateLimitConfig] = None,
    ) -> Principal:
        """Convenience: register an agent across all three modes in one call."""
        principal = self._access.create_agent(
            agent_id, name or agent_id, extra_permissions=extra_permissions
        )
        if sandbox_policy is not None:
            self._sandbox.set_policy(agent_id, sandbox_policy)
        if rate_limit is not None:
            self._rate.configure_agent(agent_id, rate_limit)
        return principal

    # ----- mode 1: inbound -----------------------------------------------

    def check_inbound(self, agent_id: str, text: str) -> FirewallResult:
        """Inspect untrusted text before the model sees it."""
        start = time.time()
        inj = self._injection.detect(text)
        anom = self._anomaly.check(agent_id, len(text))
        exfil = self._exfil.detect(text)
        esc = self._escalation.detect(text)

        threats: List[str] = []
        if inj.is_injection:
            threats.append(f"injection({inj.confidence:.0%})")
        if anom.is_anomalous:
            threats.append(f"anomaly({anom.score:.0%})")
        if exfil.is_exfiltration:
            threats.append(f"exfiltration({exfil.confidence:.0%})")
        if esc.is_escalation:
            threats.append(f"escalation[{esc.severity}]({esc.confidence:.0%})")

        allowed = not threats
        reason = "; ".join(threats) if threats else "inbound clean"

        self._audit.record(
            agent_id,
            allowed,
            reason,
            text,
            injection_score=inj.confidence,
            anomaly_score=anom.score,
            exfiltration_score=exfil.confidence,
            escalation_score=esc.confidence,
        )

        result = FirewallResult(
            mode="inbound",
            allowed=allowed,
            reason=reason,
            details={
                "injection": inj.model_dump(),
                "anomaly": anom.model_dump(),
                "exfiltration": exfil.model_dump(),
                "escalation": esc.model_dump(),
            },
            elapsed_ms=round((time.time() - start) * 1000, 2),
        )
        self._results.append(result)
        return result

    # ----- mode 2: tool_call ---------------------------------------------

    def check_tool_call(
        self,
        agent_id: str,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        *,
        required_permission: Optional[Permission] = None,
    ) -> FirewallResult:
        """Validate a proposed tool call against RBAC, sandbox, and rate limits.

        `tool` is a dotted resource path, e.g. "tools.shell.bash",
        "tools.network.fetch", "tools.database.query". The same string is
        passed to the access controller's policy matcher and to the rate
        limiter as the action name.
        """
        start = time.time()
        args = args or {}
        # Flatten args to a single string for pattern-based sandbox checks.
        arg_blob = " ".join(str(v) for v in args.values())

        # 1. RBAC.
        access = self._access.check_access(agent_id, tool, required_permission)
        if not access.allowed:
            result = FirewallResult(
                mode="tool_call",
                allowed=False,
                reason=f"rbac: {access.reason}",
                details={"stage": "rbac", "policy": access.policy_matched},
                elapsed_ms=round((time.time() - start) * 1000, 2),
            )
            self._results.append(result)
            return result

        # 2. Action sandbox.
        # Translate dotted tool path -> short action name for the sandbox's
        # whitelist. The last segment is what callers care about (bash/fetch/
        # query/etc.).
        action = tool.split(".")[-1]
        violations = self._sandbox.check_action(agent_id, action, arg_blob)
        if violations:
            result = FirewallResult(
                mode="tool_call",
                allowed=False,
                reason=f"sandbox: {violations[0].violation_type} ({violations[0].severity})",
                details={
                    "stage": "sandbox",
                    "violations": [
                        {"type": v.violation_type, "severity": v.severity, "details": v.details}
                        for v in violations
                    ],
                },
                elapsed_ms=round((time.time() - start) * 1000, 2),
            )
            self._results.append(result)
            return result

        # 3. Rate limit.
        rate = self._rate.check(agent_id, action)
        if not rate.allowed:
            result = FirewallResult(
                mode="tool_call",
                allowed=False,
                reason=f"rate: {rate.reason}",
                details={
                    "stage": "rate",
                    "retry_after_seconds": rate.retry_after_seconds,
                    "tokens_remaining": rate.tokens_remaining,
                },
                elapsed_ms=round((time.time() - start) * 1000, 2),
            )
            self._results.append(result)
            return result

        result = FirewallResult(
            mode="tool_call",
            allowed=True,
            reason="tool call allowed",
            details={"stage": "ok", "tool": tool, "action": action},
            elapsed_ms=round((time.time() - start) * 1000, 2),
        )
        self._results.append(result)
        return result

    # ----- mode 3: egress (delegated) ------------------------------------

    def check_egress(
        self,
        url: str,
        method: str = "GET",
        *,
        egress_check: Optional[EgressCheck] = None,
    ) -> FirewallResult:
        """Egress check, delegated to a user callable (typically agentguard.check).

        If neither this call nor the Firewall constructor was given an
        `egress_check`, the result is `allowed=True` with a clear reason that
        the host opted out of egress filtering. We do NOT silently no-op.
        """
        start = time.time()
        delegate = egress_check or self._egress_check
        if delegate is None:
            result = FirewallResult(
                mode="egress",
                allowed=True,
                reason="egress mode not configured (pass egress_check= or wire agentguard)",
                details={"url": url, "method": method, "delegated": False},
                elapsed_ms=round((time.time() - start) * 1000, 2),
            )
            self._results.append(result)
            return result

        decision = delegate(url, {"method": method})
        # Best-effort adapter for an agentguard-style Decision: anything with
        # an .action attribute equal to "allow" / "deny".
        action = getattr(decision, "action", None)
        reason = getattr(decision, "reason", "") or ""
        detail = getattr(decision, "detail", "") or ""
        allowed = action != "deny" if action else True

        result = FirewallResult(
            mode="egress",
            allowed=allowed,
            reason=f"egress: {action or 'no-decision'} {reason} {detail}".strip(),
            details={"url": url, "method": method, "delegated": True, "raw": str(decision)},
            elapsed_ms=round((time.time() - start) * 1000, 2),
        )
        self._results.append(result)
        return result

    # ----- introspection -------------------------------------------------

    def history(self, limit: int = 100) -> List[FirewallResult]:
        """Return the most recent firewall decisions across all modes."""
        return self._results[-limit:]

    def stats(self) -> Dict[str, Any]:
        """Aggregate per-mode allow/deny counts."""
        per_mode: Dict[str, Dict[str, int]] = {}
        for r in self._results:
            bucket = per_mode.setdefault(r.mode, {"allowed": 0, "blocked": 0})
            bucket["allowed" if r.allowed else "blocked"] += 1
        return {
            "total": len(self._results),
            "per_mode": per_mode,
            "rbac": self._access.get_stats(),
            "sandbox": self._sandbox.get_stats(),
            "rate": self._rate.get_stats(),
            "inbound_audit": self._audit.get_stats(),
        }
