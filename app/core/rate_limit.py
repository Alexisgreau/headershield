from __future__ import annotations

import time
from collections import defaultdict, deque


class SimpleRateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self.limit = limit_per_minute
        self.buckets: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        window_start = now - 60
        dq = self.buckets[key]
        while dq and dq[0] < window_start:
            dq.popleft()
        if len(dq) < self.limit:
            dq.append(now)
            return True
        return False

