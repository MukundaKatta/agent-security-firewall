"""agent-security-firewall — inbound + tool-call security firewall for AI agents.

Sibling of agentguard (which owns egress). Three modes:

    firewall.check_inbound(agent_id, text)
    firewall.check_tool_call(agent_id, tool, args)
    firewall.check_egress(url, method, egress_check=agentguard.check)
"""
from .firewall import (
    AgentFirewall,  # legacy 0.1 surface, retained
    Firewall,
    FirewallDecision,
    FirewallResult,
)
from .policies.access_control import (
    AccessController,
    AccessPolicy,
    Permission,
    Principal,
    Role,
)
from .policies.action_sandbox import (
    ActionSandbox,
    SandboxPolicy,
    SandboxViolation,
)
from .policies.rate_limiter import (
    RateLimitConfig,
    RateLimitDecision,
    RateLimiter,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "Firewall",
    "FirewallResult",
    "AgentFirewall",
    "FirewallDecision",
    "AccessController",
    "AccessPolicy",
    "Permission",
    "Principal",
    "Role",
    "ActionSandbox",
    "SandboxPolicy",
    "SandboxViolation",
    "RateLimiter",
    "RateLimitConfig",
    "RateLimitDecision",
]
