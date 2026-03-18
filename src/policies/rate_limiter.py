"""Token bucket rate limiter: per-agent, per-action. Configurable burst and sustained rates.
Sliding window tracking.
"""
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit."""
    sustained_rate: float = 10.0  # requests per second
    burst_size: int = 20  # max burst capacity
    window_seconds: float = 60.0  # sliding window for tracking


@dataclass
class RateLimitDecision:
    """Result of a rate limit check."""
    allowed: bool
    tokens_remaining: float
    retry_after_seconds: float = 0.0
    reason: str = ""
    agent_id: str = ""
    action: str = ""


class TokenBucket:
    """Token bucket rate limiter with configurable burst and sustained rates.

    Tokens are added at `sustained_rate` per second, up to `burst_size`.
    Each request consumes one token. Request is denied if no tokens available.
    """

    def __init__(self, sustained_rate: float = 10.0, burst_size: int = 20):
        self.sustained_rate = sustained_rate
        self.burst_size = burst_size
        self._tokens = float(burst_size)
        self._last_refill = time.time()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_refill
        new_tokens = elapsed * self.sustained_rate
        self._tokens = min(self.burst_size, self._tokens + new_tokens)
        self._last_refill = now

    def try_acquire(self, tokens: int = 1) -> Tuple[bool, float]:
        """Try to acquire tokens. Returns (allowed, tokens_remaining)."""
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True, self._tokens
        return False, self._tokens

    def time_until_available(self, tokens: int = 1) -> float:
        """Compute seconds until enough tokens are available."""
        self._refill()
        if self._tokens >= tokens:
            return 0.0
        deficit = tokens - self._tokens
        return deficit / self.sustained_rate if self.sustained_rate > 0 else float('inf')

    @property
    def current_tokens(self) -> float:
        self._refill()
        return self._tokens


class SlidingWindowCounter:
    """Sliding window rate counter for tracking request history."""

    def __init__(self, window_seconds: float = 60.0, max_requests: int = 100):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self._timestamps: List[float] = []

    def _clean(self) -> None:
        """Remove expired timestamps."""
        cutoff = time.time() - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]

    def try_acquire(self) -> Tuple[bool, int]:
        """Try to record a request. Returns (allowed, current_count)."""
        self._clean()
        if len(self._timestamps) >= self.max_requests:
            return False, len(self._timestamps)
        self._timestamps.append(time.time())
        return True, len(self._timestamps)

    @property
    def current_count(self) -> int:
        self._clean()
        return len(self._timestamps)

    def time_until_available(self) -> float:
        """Time until a slot frees up."""
        self._clean()
        if len(self._timestamps) < self.max_requests:
            return 0.0
        oldest = self._timestamps[0]
        return max(0, (oldest + self.window_seconds) - time.time())


class RateLimiter:
    """Multi-dimensional rate limiter: per-agent, per-action, combined.

    Each agent has its own token bucket and sliding window.
    Actions can have separate rate limits.
    """

    def __init__(self, default_config: Optional[RateLimitConfig] = None):
        self.default_config = default_config or RateLimitConfig()
        self._agent_buckets: Dict[str, TokenBucket] = {}
        self._action_buckets: Dict[str, TokenBucket] = {}
        self._agent_action_buckets: Dict[str, TokenBucket] = {}
        self._sliding_windows: Dict[str, SlidingWindowCounter] = {}
        self._agent_configs: Dict[str, RateLimitConfig] = {}
        self._action_configs: Dict[str, RateLimitConfig] = {}
        self._total_requests = 0
        self._total_denied = 0

    def configure_agent(self, agent_id: str, config: RateLimitConfig) -> None:
        """Set rate limit config for a specific agent."""
        self._agent_configs[agent_id] = config
        self._agent_buckets[agent_id] = TokenBucket(config.sustained_rate, config.burst_size)
        self._sliding_windows[agent_id] = SlidingWindowCounter(
            config.window_seconds, int(config.sustained_rate * config.window_seconds),
        )
        logger.info(f"Configured rate limit for agent {agent_id}: {config.sustained_rate}/s, burst={config.burst_size}")

    def configure_action(self, action: str, config: RateLimitConfig) -> None:
        """Set rate limit config for a specific action type."""
        self._action_configs[action] = config
        self._action_buckets[action] = TokenBucket(config.sustained_rate, config.burst_size)

    def check(self, agent_id: str, action: str = "default") -> RateLimitDecision:
        """Check if a request should be rate limited."""
        self._total_requests += 1

        # Get or create agent bucket
        if agent_id not in self._agent_buckets:
            cfg = self._agent_configs.get(agent_id, self.default_config)
            self._agent_buckets[agent_id] = TokenBucket(cfg.sustained_rate, cfg.burst_size)
            self._sliding_windows[agent_id] = SlidingWindowCounter(
                cfg.window_seconds, int(cfg.sustained_rate * cfg.window_seconds),
            )

        # Check agent-level token bucket
        agent_bucket = self._agent_buckets[agent_id]
        allowed, remaining = agent_bucket.try_acquire()
        if not allowed:
            self._total_denied += 1
            retry = agent_bucket.time_until_available()
            logger.warning(f"Rate limited agent {agent_id}: token bucket empty")
            return RateLimitDecision(
                allowed=False, tokens_remaining=remaining,
                retry_after_seconds=retry,
                reason=f"Agent rate limit exceeded (token bucket)",
                agent_id=agent_id, action=action,
            )

        # Check action-level bucket if configured
        if action in self._action_buckets:
            action_bucket = self._action_buckets[action]
            allowed, remaining = action_bucket.try_acquire()
            if not allowed:
                self._total_denied += 1
                retry = action_bucket.time_until_available()
                return RateLimitDecision(
                    allowed=False, tokens_remaining=remaining,
                    retry_after_seconds=retry,
                    reason=f"Action rate limit exceeded for '{action}'",
                    agent_id=agent_id, action=action,
                )

        # Check combined agent+action
        combo_key = f"{agent_id}:{action}"
        if combo_key not in self._agent_action_buckets:
            cfg = self._action_configs.get(action, self.default_config)
            self._agent_action_buckets[combo_key] = TokenBucket(
                cfg.sustained_rate * 0.5, max(1, cfg.burst_size // 2),
            )
        combo_bucket = self._agent_action_buckets[combo_key]
        allowed, remaining = combo_bucket.try_acquire()
        if not allowed:
            self._total_denied += 1
            return RateLimitDecision(
                allowed=False, tokens_remaining=remaining,
                retry_after_seconds=combo_bucket.time_until_available(),
                reason=f"Agent+action combo rate limit exceeded",
                agent_id=agent_id, action=action,
            )

        # Track in sliding window
        window = self._sliding_windows.get(agent_id)
        if window:
            sw_allowed, count = window.try_acquire()
            if not sw_allowed:
                self._total_denied += 1
                return RateLimitDecision(
                    allowed=False, tokens_remaining=remaining,
                    retry_after_seconds=window.time_until_available(),
                    reason="Sliding window limit exceeded",
                    agent_id=agent_id, action=action,
                )

        return RateLimitDecision(
            allowed=True, tokens_remaining=remaining,
            reason="Allowed", agent_id=agent_id, action=action,
        )

    def get_stats(self) -> Dict:
        return {
            "total_requests": self._total_requests,
            "total_denied": self._total_denied,
            "denial_rate": self._total_denied / max(self._total_requests, 1),
            "configured_agents": len(self._agent_configs),
            "configured_actions": len(self._action_configs),
        }
