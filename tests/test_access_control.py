"""Tests for role-based access control."""
import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.policies.access_control import (
    AccessController, Principal, Role, Permission, AccessPolicy,
)


class TestPrincipal:
    def test_admin_has_all_permissions(self):
        p = Principal(principal_id="admin1", name="Admin", roles={Role.ADMIN})
        assert p.has_permission(Permission.EXECUTE_CODE)
        assert p.has_permission(Permission.MANAGE_USERS)

    def test_agent_limited_permissions(self):
        p = Principal(principal_id="agent1", name="Agent", roles={Role.AGENT})
        assert p.has_permission(Permission.READ)
        assert p.has_permission(Permission.EXECUTE_TOOL)
        assert not p.has_permission(Permission.MANAGE_USERS)
        assert not p.has_permission(Permission.DELETE)

    def test_viewer_read_only(self):
        p = Principal(principal_id="v1", name="Viewer", roles={Role.VIEWER})
        assert p.has_permission(Permission.READ)
        assert not p.has_permission(Permission.WRITE)
        assert not p.has_permission(Permission.EXECUTE)

    def test_denied_permissions_override(self):
        p = Principal(principal_id="a1", name="A", roles={Role.ADMIN},
                      denied_permissions={Permission.DELETE})
        assert not p.has_permission(Permission.DELETE)
        assert p.has_permission(Permission.READ)

    def test_inactive_principal(self):
        p = Principal(principal_id="a1", name="A", roles={Role.ADMIN}, is_active=False)
        assert not p.has_permission(Permission.READ)


class TestAccessController:
    def test_unknown_principal_denied(self):
        ac = AccessController()
        decision = ac.check_access("nonexistent", "tools.shell.bash")
        assert not decision.allowed

    def test_admin_shell_access(self):
        ac = AccessController()
        ac.create_user("admin1", "Admin", Role.ADMIN)
        decision = ac.check_access("admin1", "tools.shell.bash")
        assert decision.allowed

    def test_agent_shell_denied(self):
        ac = AccessController()
        ac.create_agent("agent1", "Agent")
        decision = ac.check_access("agent1", "tools.shell.bash")
        assert not decision.allowed

    def test_agent_can_read(self):
        ac = AccessController()
        ac.create_agent("agent1", "Agent")
        decision = ac.check_access("agent1", "files.readme.md", Permission.READ)
        assert decision.allowed

    def test_custom_policy(self):
        ac = AccessController()
        ac.create_agent("agent1", "Agent")
        ac.add_policy(AccessPolicy(
            resource_pattern="tools.secret.*",
            denied_principals={"agent1"},
            description="No agents on secrets",
        ))
        decision = ac.check_access("agent1", "tools.secret.vault")
        assert not decision.allowed

    def test_audit_log(self):
        ac = AccessController()
        ac.create_user("u1", "User")
        ac.check_access("u1", "files.test")
        ac.check_access("u1", "files.other")
        log = ac.get_audit_log("u1")
        assert len(log) == 2

    def test_stats(self):
        ac = AccessController()
        ac.create_user("u1", "User")
        ac.check_access("u1", "test")
        stats = ac.get_stats()
        assert stats["total_checks"] >= 1
        assert stats["principals"] == 1
