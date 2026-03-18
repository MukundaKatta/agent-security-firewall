"""Action sandboxing: whitelist allowed actions, block dangerous patterns,
rollback on policy violation.
"""
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class SandboxPolicy:
    """Policy defining what actions are allowed in the sandbox."""
    name: str
    allowed_actions: Set[str] = field(default_factory=set)
    blocked_patterns: List[str] = field(default_factory=list)
    max_execution_time_seconds: float = 30.0
    max_output_size_bytes: int = 1_000_000
    allow_network: bool = False
    allow_filesystem_write: bool = False
    allow_subprocess: bool = False
    allow_env_access: bool = False


@dataclass
class SandboxViolation:
    """A recorded sandbox violation."""
    timestamp: float = field(default_factory=time.time)
    agent_id: str = ""
    action: str = ""
    violation_type: str = ""
    details: str = ""
    blocked: bool = True
    severity: str = "high"


@dataclass
class ActionResult:
    """Result of a sandboxed action execution."""
    success: bool
    output: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    was_sandboxed: bool = True
    violations: List[SandboxViolation] = field(default_factory=list)
    rolled_back: bool = False


# Dangerous patterns to block
DANGEROUS_PATTERNS = [
    (re.compile(r"\b(?:rm\s+-rf|rmdir|del\s+/[sS])\b"), "destructive_command", "Destructive file deletion command"),
    (re.compile(r"\b(?:chmod\s+777|chmod\s+666)\b"), "insecure_permissions", "Insecure file permissions"),
    (re.compile(r"\b(?:eval|exec|compile)\s*\("), "code_injection", "Dynamic code execution"),
    (re.compile(r"\b(?:os\.system|subprocess\.(?:call|run|Popen))\s*\("), "subprocess", "Process execution"),
    (re.compile(r"\b(?:__import__|importlib\.import_module)\s*\("), "dynamic_import", "Dynamic module import"),
    (re.compile(r"\b(?:pickle\.loads?|marshal\.loads?|shelve\.open)\s*\("), "deserialization", "Unsafe deserialization"),
    (re.compile(r"\b(?:socket|urllib|requests|httpx|aiohttp)\.\w+\("), "network", "Network access attempt"),
    (re.compile(r"\bopen\s*\(.*['\"]w['\"]"), "file_write", "File write operation"),
    (re.compile(r"\b(?:shutil\.rmtree|os\.remove|os\.unlink)\s*\("), "file_delete", "File deletion operation"),
    (re.compile(r"\b(?:os\.environ|getenv)\b"), "env_access", "Environment variable access"),
    (re.compile(r"""(?:DROP\s+TABLE|DELETE\s+FROM|TRUNCATE|ALTER\s+TABLE)""", re.I), "sql_danger", "Dangerous SQL operation"),
    (re.compile(r"\bsudo\b"), "privilege_escalation", "Privilege escalation attempt"),
    (re.compile(r"\b(?:curl|wget)\s+.*\|.*(?:sh|bash)\b"), "remote_code", "Remote code execution via pipe"),
]


class ActionSandbox:
    """Sandbox for safe action execution with policy enforcement."""

    def __init__(self, default_policy: Optional[SandboxPolicy] = None):
        self.default_policy = default_policy or SandboxPolicy(
            name="default",
            allowed_actions={"read", "search", "compute", "format", "summarize"},
            max_execution_time_seconds=30.0,
        )
        self._agent_policies: Dict[str, SandboxPolicy] = {}
        self._violations: List[SandboxViolation] = []
        self._execution_count = 0
        self._blocked_count = 0
        self._rollback_handlers: Dict[str, Callable] = {}

    def set_policy(self, agent_id: str, policy: SandboxPolicy) -> None:
        """Set sandbox policy for a specific agent."""
        self._agent_policies[agent_id] = policy
        logger.info(f"Set sandbox policy '{policy.name}' for agent {agent_id}")

    def register_rollback(self, action: str, handler: Callable) -> None:
        """Register a rollback handler for an action type."""
        self._rollback_handlers[action] = handler
        logger.info(f"Registered rollback handler for action: {action}")

    def check_action(self, agent_id: str, action: str,
                     action_input: str = "") -> List[SandboxViolation]:
        """Check if an action is allowed by the sandbox policy.

        Returns list of violations (empty if action is allowed).
        """
        policy = self._agent_policies.get(agent_id, self.default_policy)
        violations: List[SandboxViolation] = []

        # Check action whitelist
        if policy.allowed_actions and action not in policy.allowed_actions:
            violations.append(SandboxViolation(
                agent_id=agent_id, action=action,
                violation_type="action_not_allowed",
                details=f"Action '{action}' not in whitelist: {policy.allowed_actions}",
                severity="high",
            ))

        # Check dangerous patterns in action input
        for pattern, vtype, desc in DANGEROUS_PATTERNS:
            if pattern.search(action_input):
                # Check if policy allows this type
                if vtype == "network" and policy.allow_network:
                    continue
                if vtype == "file_write" and policy.allow_filesystem_write:
                    continue
                if vtype == "subprocess" and policy.allow_subprocess:
                    continue
                if vtype == "env_access" and policy.allow_env_access:
                    continue

                violations.append(SandboxViolation(
                    agent_id=agent_id, action=action,
                    violation_type=vtype, details=desc,
                    severity="critical" if vtype in ("code_injection", "destructive_command", "remote_code") else "high",
                ))

        # Check blocked patterns from policy
        for pat in policy.blocked_patterns:
            if re.search(pat, action_input, re.I):
                violations.append(SandboxViolation(
                    agent_id=agent_id, action=action,
                    violation_type="custom_pattern",
                    details=f"Matched blocked pattern: {pat}",
                    severity="high",
                ))

        if violations:
            self._violations.extend(violations)
            self._blocked_count += len(violations)
            for v in violations:
                logger.warning(f"Sandbox violation [{v.severity}]: {v.violation_type} by {agent_id}: {v.details}")

        return violations

    def execute(self, agent_id: str, action: str, action_input: str,
                executor: Callable[[str], Any]) -> ActionResult:
        """Execute an action within the sandbox, with policy checks and rollback."""
        self._execution_count += 1

        # Pre-execution check
        violations = self.check_action(agent_id, action, action_input)
        if violations:
            return ActionResult(
                success=False, error="Action blocked by sandbox policy",
                violations=violations, was_sandboxed=True,
            )

        policy = self._agent_policies.get(agent_id, self.default_policy)
        start = time.time()

        try:
            # Execute with timeout tracking (actual timeout requires threading)
            output = executor(action_input)
            elapsed_ms = (time.time() - start) * 1000

            # Post-execution checks
            if elapsed_ms > policy.max_execution_time_seconds * 1000:
                violation = SandboxViolation(
                    agent_id=agent_id, action=action,
                    violation_type="timeout",
                    details=f"Execution took {elapsed_ms:.0f}ms (max {policy.max_execution_time_seconds * 1000:.0f}ms)",
                    severity="medium",
                )
                self._violations.append(violation)
                # Rollback
                rolled_back = self._try_rollback(action, action_input)
                return ActionResult(
                    success=False, output=output, error="Execution timeout exceeded",
                    execution_time_ms=elapsed_ms, violations=[violation],
                    rolled_back=rolled_back,
                )

            # Check output size
            output_str = str(output)
            if len(output_str) > policy.max_output_size_bytes:
                logger.warning(f"Output size {len(output_str)} exceeds max {policy.max_output_size_bytes}")

            return ActionResult(
                success=True, output=output,
                execution_time_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = (time.time() - start) * 1000
            rolled_back = self._try_rollback(action, action_input)
            return ActionResult(
                success=False, error=str(e),
                execution_time_ms=elapsed_ms,
                rolled_back=rolled_back,
            )

    def _try_rollback(self, action: str, action_input: str) -> bool:
        """Attempt to rollback an action."""
        handler = self._rollback_handlers.get(action)
        if handler:
            try:
                handler(action_input)
                logger.info(f"Rollback successful for action: {action}")
                return True
            except Exception as e:
                logger.error(f"Rollback failed for {action}: {e}")
        return False

    def get_violations(self, agent_id: Optional[str] = None, limit: int = 100) -> List[SandboxViolation]:
        """Get recent violations."""
        violations = self._violations
        if agent_id:
            violations = [v for v in violations if v.agent_id == agent_id]
        return violations[-limit:]

    def get_stats(self) -> Dict:
        return {
            "total_executions": self._execution_count,
            "total_blocked": self._blocked_count,
            "total_violations": len(self._violations),
            "block_rate": self._blocked_count / max(self._execution_count, 1),
            "agents_with_policies": len(self._agent_policies),
        }
