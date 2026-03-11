"""
STRIDE Control: Denial of Service
Token bucket rate limiter per IP address.

Attack paths mitigated:
- ATK-007: API flooding / DDoS
- ATK-008: Brute force authentication
- ATK-009: Cost exhaustion via LLM API abuse
"""

import time
import threading
import logging
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TokenBucket:
    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(default=0)
    last_refill: float = field(default_factory=time.time)

    def __post_init__(self):
        self.tokens = float(self.capacity)

    def consume(self) -> bool:
        """Attempt to consume one token. Returns True if allowed."""
        now = time.time()
        elapsed = now - self.last_refill
        # Refill tokens based on elapsed time
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.refill_rate
        )
        self.last_refill = now

        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class RateLimiter:
    """
    Per-IP token bucket rate limiter.
    Thread-safe implementation for concurrent requests.
    
    Default: 20 requests per 60 seconds per IP.
    Automatically cleans up stale buckets to prevent memory exhaustion.
    """

    def __init__(self, max_requests: int = 20, window_seconds: int = 60):
        self.max_requests = max_requests
        self.refill_rate = max_requests / window_seconds
        self._buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(
                capacity=self.max_requests,
                refill_rate=self.refill_rate
            )
        )
        self._lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # Clean stale IPs every 5 minutes

    def is_allowed(self, client_ip: str) -> bool:
        """Check if client IP is within rate limit."""
        with self._lock:
            self._maybe_cleanup()
            allowed = self._buckets[client_ip].consume()
            if not allowed:
                logger.warning(f"Rate limit exceeded for IP: {self._mask_ip(client_ip)}")
            return allowed

    def _maybe_cleanup(self):
        """Remove buckets for IPs inactive for 10+ minutes to prevent memory leak."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        stale_cutoff = now - 600
        stale = [
            ip for ip, bucket in self._buckets.items()
            if bucket.last_refill < stale_cutoff
        ]
        for ip in stale:
            del self._buckets[ip]
        if stale:
            logger.info(f"Rate limiter cleanup: removed {len(stale)} stale IP buckets")
        self._last_cleanup = now

    @staticmethod
    def _mask_ip(ip: str) -> str:
        """Mask last octet for logging (privacy-preserving)."""
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        return "xxx.xxx.xxx.xxx"
