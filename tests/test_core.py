"""Tests for AgentSecurityFirewall."""
from src.core import AgentSecurityFirewall
def test_init(): assert AgentSecurityFirewall().get_stats()["ops"] == 0
def test_op(): c = AgentSecurityFirewall(); c.process(x=1); assert c.get_stats()["ops"] == 1
def test_multi(): c = AgentSecurityFirewall(); [c.process() for _ in range(5)]; assert c.get_stats()["ops"] == 5
def test_reset(): c = AgentSecurityFirewall(); c.process(); c.reset(); assert c.get_stats()["ops"] == 0
def test_service_name(): c = AgentSecurityFirewall(); r = c.process(); assert r["service"] == "agent-security-firewall"
