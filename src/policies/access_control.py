"""Role-based access control: roles (admin, user, agent), permissions per role,
access checks before tool execution.
"""
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """System roles with hierarchical access."""
    ADMIN = "admin"
    USER = "user"
    AGENT = "agent"
    VIEWER = "viewer"
    SYSTEM = "system"


class Permission(str, Enum):
    """Fine-grained permissions."""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    CONFIGURE = "configure"
    MANAGE_USERS = "manage_users"
    MANAGE_AGENTS = "manage_agents"
    VIEW_AUDIT = "view_audit"
    EXECUTE_TOOL = "execute_tool"
    ACCESS_NETWORK = "access_network"
    ACCESS_FILESYSTEM = "access_filesystem"
    ACCESS_DATABASE = "access_database"
    EXECUTE_CODE = "execute_code"


# Default role -> permissions mapping
DEFAULT_ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: set(Permission),  # All permissions
    Role.USER: {
        Permission.READ, Permission.WRITE, Permission.EXECUTE,
        Permission.EXECUTE_TOOL, Permission.VIEW_AUDIT,
    },
    Role.AGENT: {
        Permission.READ, Permission.EXECUTE, Permission.EXECUTE_TOOL,
        Permission.ACCESS_NETWORK,
    },
    Role.VIEWER: {Permission.READ, Permission.VIEW_AUDIT},
    Role.SYSTEM: set(Permission),
}


@dataclass
class Principal:
    """An identity (user or agent) with roles and permissions."""
    principal_id: str
    name: str
    roles: Set[Role] = field(default_factory=set)
    extra_permissions: Set[Permission] = field(default_factory=set)
    denied_permissions: Set[Permission] = field(default_factory=set)
    is_active: bool = True
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def effective_permissions(self) -> Set[Permission]:
        """Compute effective permissions: role perms + extra - denied."""
        perms: Set[Permission] = set()
        for role in self.roles:
            perms |= DEFAULT_ROLE_PERMISSIONS.get(role, set())
        perms |= self.extra_permissions
        perms -= self.denied_permissions
        return perms

    def has_permission(self, perm: Permission) -> bool:
        """Check if principal has a specific permission."""
        if not self.is_active:
            return False
        return perm in self.effective_permissions

    def has_role(self, role: Role) -> bool:
        return role in self.roles


@dataclass
class AccessPolicy:
    """A policy rule for resource access."""
    resource_pattern: str  # glob-like pattern (e.g., "tools.*", "files./etc/*")
    required_permissions: Set[Permission] = field(default_factory=set)
    required_roles: Set[Role] = field(default_factory=set)
    allowed_principals: Set[str] = field(default_factory=set)  # Empty = all
    denied_principals: Set[str] = field(default_factory=set)
    description: str = ""

    def matches_resource(self, resource: str) -> bool:
        """Check if resource matches this policy's pattern."""
        import fnmatch
        return fnmatch.fnmatch(resource, self.resource_pattern)


@dataclass
class AccessDecision:
    """Result of an access check."""
    allowed: bool
    principal_id: str
    resource: str
    reason: str
    timestamp: float = field(default_factory=time.time)
    policy_matched: Optional[str] = None


class AccessController:
    """Role-based access control system."""

    def __init__(self):
        self._principals: Dict[str, Principal] = {}
        self._policies: List[AccessPolicy] = []
        self._audit_log: List[AccessDecision] = []
        self._setup_default_policies()
        logger.info("AccessController initialized")

    def _setup_default_policies(self) -> None:
        """Set up default security policies."""
        self._policies.extend([
            AccessPolicy(
                resource_pattern="tools.shell.*",
                required_permissions={Permission.EXECUTE_CODE},
                required_roles={Role.ADMIN},
                description="Shell access requires admin",
            ),
            AccessPolicy(
                resource_pattern="files./etc/*",
                required_permissions={Permission.ACCESS_FILESYSTEM},
                required_roles={Role.ADMIN, Role.SYSTEM},
                description="System config files restricted",
            ),
            AccessPolicy(
                resource_pattern="tools.database.*",
                required_permissions={Permission.ACCESS_DATABASE},
                description="Database access requires explicit permission",
            ),
            AccessPolicy(
                resource_pattern="tools.network.*",
                required_permissions={Permission.ACCESS_NETWORK},
                description="Network access requires explicit permission",
            ),
        ])

    def register_principal(self, principal: Principal) -> None:
        """Register a user or agent."""
        self._principals[principal.principal_id] = principal
        logger.info(f"Registered principal: {principal.principal_id} (roles: {principal.roles})")

    def create_agent(self, agent_id: str, name: str,
                     extra_permissions: Optional[Set[Permission]] = None) -> Principal:
        """Create and register an agent principal."""
        agent = Principal(
            principal_id=agent_id, name=name, roles={Role.AGENT},
            extra_permissions=extra_permissions or set(),
        )
        self.register_principal(agent)
        return agent

    def create_user(self, user_id: str, name: str, role: Role = Role.USER) -> Principal:
        """Create and register a user principal."""
        user = Principal(principal_id=user_id, name=name, roles={role})
        self.register_principal(user)
        return user

    def add_policy(self, policy: AccessPolicy) -> None:
        """Add an access policy."""
        self._policies.append(policy)

    def check_access(self, principal_id: str, resource: str,
                     required_permission: Optional[Permission] = None) -> AccessDecision:
        """Check if a principal can access a resource."""
        principal = self._principals.get(principal_id)
        if not principal:
            decision = AccessDecision(
                allowed=False, principal_id=principal_id, resource=resource,
                reason="Unknown principal",
            )
            self._audit_log.append(decision)
            return decision

        if not principal.is_active:
            decision = AccessDecision(
                allowed=False, principal_id=principal_id, resource=resource,
                reason="Principal is deactivated",
            )
            self._audit_log.append(decision)
            return decision

        # Check policies in order (first match wins)
        for policy in self._policies:
            if not policy.matches_resource(resource):
                continue

            # Check denied principals
            if principal_id in policy.denied_principals:
                decision = AccessDecision(
                    allowed=False, principal_id=principal_id, resource=resource,
                    reason=f"Explicitly denied by policy: {policy.description}",
                    policy_matched=policy.resource_pattern,
                )
                self._audit_log.append(decision)
                return decision

            # Check allowed principals (if specified)
            if policy.allowed_principals and principal_id not in policy.allowed_principals:
                decision = AccessDecision(
                    allowed=False, principal_id=principal_id, resource=resource,
                    reason=f"Not in allowed list for: {policy.description}",
                    policy_matched=policy.resource_pattern,
                )
                self._audit_log.append(decision)
                return decision

            # Check required roles
            if policy.required_roles and not any(principal.has_role(r) for r in policy.required_roles):
                decision = AccessDecision(
                    allowed=False, principal_id=principal_id, resource=resource,
                    reason=f"Missing required role for: {policy.description}",
                    policy_matched=policy.resource_pattern,
                )
                self._audit_log.append(decision)
                return decision

            # Check required permissions
            for perm in policy.required_permissions:
                if not principal.has_permission(perm):
                    decision = AccessDecision(
                        allowed=False, principal_id=principal_id, resource=resource,
                        reason=f"Missing permission {perm.value} for: {policy.description}",
                        policy_matched=policy.resource_pattern,
                    )
                    self._audit_log.append(decision)
                    return decision

        # Check specific required permission
        if required_permission and not principal.has_permission(required_permission):
            decision = AccessDecision(
                allowed=False, principal_id=principal_id, resource=resource,
                reason=f"Missing permission: {required_permission.value}",
            )
            self._audit_log.append(decision)
            return decision

        decision = AccessDecision(
            allowed=True, principal_id=principal_id, resource=resource,
            reason="Access granted",
        )
        self._audit_log.append(decision)
        return decision

    def get_audit_log(self, principal_id: Optional[str] = None,
                      limit: int = 100) -> List[AccessDecision]:
        """Get recent access decisions."""
        log = self._audit_log
        if principal_id:
            log = [d for d in log if d.principal_id == principal_id]
        return log[-limit:]

    def get_stats(self) -> Dict:
        total = len(self._audit_log)
        denied = sum(1 for d in self._audit_log if not d.allowed)
        return {
            "total_checks": total, "denied": denied,
            "allowed": total - denied,
            "principals": len(self._principals),
            "policies": len(self._policies),
        }
