"""Cancellation-aware, serialized request admission shared by the whole scan."""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager


class ControlError(RuntimeError):
    pass


class ProbeClosed(ControlError):
    pass


class BudgetExceeded(ControlError):
    pass


class ProbeToken:
    def __init__(self):
        self.closed = asyncio.Event()

    def close(self):
        self.closed.set()


class RequestBudget:
    """Hold the gate through response headers so 429 stops all queued requests."""

    def __init__(self, max_requests: int, spacing_ms: float):
        self.maximum = max_requests
        self.spacing = spacing_ms / 1000
        self.requests = 0
        self.last_start = None
        self.reason = None
        self.stopped = asyncio.Event()
        self._lock = asyncio.Lock()

    def stop(self, reason: str):
        if self.reason is None:
            self.reason = reason
        self.stopped.set()

    def _check(self, token):
        if token.closed.is_set():
            raise ProbeClosed("Probe closed; queued request cancelled")
        if self.stopped.is_set():
            raise BudgetExceeded(self.reason)

    @asynccontextmanager
    async def permit(self, token: ProbeToken):
        self._check(token)
        acquire = asyncio.create_task(self._lock.acquire())
        closed = asyncio.create_task(token.closed.wait())
        stopped = asyncio.create_task(self.stopped.wait())
        acquired = False
        try:
            await asyncio.wait((acquire, closed, stopped), return_when=asyncio.FIRST_COMPLETED)
            if acquire.done() and not acquire.cancelled():
                acquired = acquire.result()
            self._check(token)
            if not acquired:
                raise ProbeClosed("Request cancelled")
            delay = 0 if self.last_start is None else self.spacing - (time.monotonic() - self.last_start)
            if delay > 0:
                await asyncio.wait((closed, stopped), timeout=delay, return_when=asyncio.FIRST_COMPLETED)
            self._check(token)
            if self.requests >= self.maximum:
                self.stop("Hard request budget exhausted")
                raise BudgetExceeded(self.reason)
            self.requests += 1
            self.last_start = time.monotonic()
            yield
        finally:
            for task in (acquire, closed, stopped):
                if not task.done():
                    task.cancel()
            await asyncio.gather(acquire, closed, stopped, return_exceptions=True)
            # An acquire may complete concurrently with cancellation.
            if acquired or (not acquire.cancelled() and acquire.done() and acquire.exception() is None and acquire.result()):
                self._lock.release()
