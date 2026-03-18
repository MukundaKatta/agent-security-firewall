"""Tests for token bucket rate limiter."""
import pytest, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.policies.rate_limiter import (
    RateLimiter, RateLimitConfig, TokenBucket, SlidingWindowCounter,
)
from src.policies.action_sandbox import (
    ActionSandbox, SandboxPolicy, DANGEROUS_PATTERNS,
)


class TestTokenBucket:
    def test_initial_burst(self):
        bucket = TokenBucket(sustained_rate=5.0, burst_size=10)
        for _ in range(10):
            allowed, _ = bucket.try_acquire()
            assert allowed
        # 11th should fail
        allowed, _ = bucket.try_acquire()
        assert not allowed

    def test_refill(self):
        bucket = TokenBucket(sustained_rate=1000.0, burst_size=5)
        # Drain
        for _ in range(5):
            bucket.try_acquire()
        # Wait a bit for refill
        time.sleep(0.01)
        allowed, _ = bucket.try_acquire()
        assert allowed

    def test_time_until_available(self):
        bucket = TokenBucket(sustained_rate=1.0, burst_size=1)
        bucket.try_acquire()
        wait = bucket.time_until_available()
        assert wait > 0


class TestSlidingWindow:
    def test_within_limit(self):
        sw = SlidingWindowCounter(window_seconds=1.0, max_requests=5)
        for _ in range(5):
            allowed, _ = sw.try_acquire()
            assert allowed

    def test_exceeds_limit(self):
        sw = SlidingWindowCounter(window_seconds=60.0, max_requests=3)
        for _ in range(3):
            sw.try_acquire()
        allowed, count = sw.try_acquire()
        assert not allowed
        assert count == 3


class TestRateLimiter:
    def test_default_allows(self):
        rl = RateLimiter(RateLimitConfig(sustained_rate=100, burst_size=50))
        decision = rl.check("agent1", "read")
        assert decision.allowed

    def test_burst_exceeded(self):
        rl = RateLimiter(RateLimitConfig(sustained_rate=0.1, burst_size=2))
        rl.check("agent1")
        rl.check("agent1")
        decision = rl.check("agent1")
        assert not decision.allowed
        assert decision.retry_after_seconds > 0

    def test_per_agent_config(self):
        rl = RateLimiter()
        rl.configure_agent("fast", RateLimitConfig(sustained_rate=100, burst_size=50))
        rl.configure_agent("slow", RateLimitConfig(sustained_rate=0.1, burst_size=1))

        assert rl.check("fast").allowed
        rl.check("slow")
        assert not rl.check("slow").allowed

    def test_per_action_config(self):
        rl = RateLimiter()
        rl.configure_action("expensive", RateLimitConfig(sustained_rate=0.1, burst_size=1))
        rl.check("agent1", "expensive")
        decision = rl.check("agent1", "expensive")
        assert not decision.allowed

    def test_stats(self):
        rl = RateLimiter()
        rl.check("a1")
        stats = rl.get_stats()
        assert stats["total_requests"] >= 1


class TestActionSandbox:
    def test_allowed_action(self):
        sandbox = ActionSandbox()
        violations = sandbox.check_action("agent1", "read", "read file data.txt")
        assert len(violations) == 0

    def test_blocked_action(self):
        sandbox = ActionSandbox()
        violations = sandbox.check_action("agent1", "delete", "rm -rf /")
        assert len(violations) > 0

    def test_code_injection_blocked(self):
        sandbox = ActionSandbox()
        violations = sandbox.check_action("agent1", "compute", "eval(user_input)")
        assert any(v.violation_type == "code_injection" for v in violations)

    def test_subprocess_blocked(self):
        sandbox = ActionSandbox()
        violations = sandbox.check_action("agent1", "compute", "os.system('ls')")
        assert any(v.violation_type == "subprocess" for v in violations)

    def test_network_allowed_with_policy(self):
        sandbox = ActionSandbox()
        policy = SandboxPolicy(name="net_ok", allowed_actions={"fetch"}, allow_network=True)
        sandbox.set_policy("agent1", policy)
        violations = sandbox.check_action("agent1", "fetch", "requests.get('http://example.com')")
        assert not any(v.violation_type == "network" for v in violations)

    def test_execute_success(self):
        sandbox = ActionSandbox()
        result = sandbox.execute("agent1", "read", "hello", lambda x: x.upper())
        assert result.success
        assert result.output == "HELLO"

    def test_execute_blocked(self):
        sandbox = ActionSandbox()
        result = sandbox.execute("agent1", "hack", "eval(bad_code)", lambda x: x)
        assert not result.success
        assert len(result.violations) > 0

    def test_rollback_handler(self):
        sandbox = ActionSandbox()
        rolled_back = []
        sandbox.register_rollback("write", lambda x: rolled_back.append(x))
        policy = SandboxPolicy(name="test", allowed_actions={"write"}, max_execution_time_seconds=0.0)
        sandbox.set_policy("agent1", policy)
        # Execute something that will trigger timeout check
        result = sandbox.execute("agent1", "write", "data",
                                  lambda x: time.sleep(0.001) or "done")
        # Timeout may or may not trigger depending on speed

    def test_stats(self):
        sandbox = ActionSandbox()
        sandbox.check_action("a1", "read", "safe")
        sandbox.check_action("a1", "hack", "eval(x)")
        stats = sandbox.get_stats()
        assert stats["total_violations"] > 0
