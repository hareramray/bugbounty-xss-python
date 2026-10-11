import asyncio
import time

import pytest

from xss_suite.control import BudgetExceeded, ProbeClosed, ProbeToken, RequestBudget
from xss_suite.engine import sanitize_error


@pytest.mark.asyncio
async def test_hard_budget_and_spacing():
    budget = RequestBudget(2, 35)
    token = ProbeToken()
    starts = []
    for _ in range(2):
        async with budget.permit(token):
            starts.append(time.monotonic())
    assert starts[1] - starts[0] >= 0.03
    with pytest.raises(BudgetExceeded):
        async with budget.permit(token):
            pytest.fail("Request beyond budget admitted")
    assert budget.requests == 2


@pytest.mark.asyncio
async def test_queued_request_is_cancelled_while_gate_is_held():
    budget = RequestBudget(10, 0)
    first, queued = ProbeToken(), ProbeToken()
    async def waiter():
        async with budget.permit(queued):
            pytest.fail("Closed probe reached network")
    async with budget.permit(first):
        task = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        queued.close()
        with pytest.raises(ProbeClosed):
            await asyncio.wait_for(task, 0.5)
    assert budget.requests == 1
    async with budget.permit(first):
        pass
    assert budget.requests == 2


@pytest.mark.asyncio
async def test_429_stop_cancels_all_queue_before_unlock():
    budget = RequestBudget(10, 0)
    async def waiter():
        async with budget.permit(ProbeToken()):
            pytest.fail("Stopped request reached network")
    async with budget.permit(ProbeToken()):
        task = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        budget.stop("HTTP 429 received; scan stopped")
        with pytest.raises(BudgetExceeded, match="429"):
            await asyncio.wait_for(task, 0.5)
    assert budget.requests == 1


@pytest.mark.asyncio
async def test_cancellation_during_spacing_does_not_spend_budget():
    budget = RequestBudget(10, 10000)
    token = ProbeToken()
    async with budget.permit(token):
        pass
    async def waiter():
        async with budget.permit(token):
            pytest.fail("Cancelled request admitted")
    task = asyncio.create_task(waiter())
    await asyncio.sleep(0.02)
    token.close()
    with pytest.raises(ProbeClosed):
        await asyncio.wait_for(task, 0.5)
    assert budget.requests == 1


@pytest.mark.asyncio
async def test_task_cancelled_during_lock_wait_does_not_leak_lock():
    budget = RequestBudget(10, 0)
    async def waiter():
        async with budget.permit(ProbeToken()):
            pass
    async with budget.permit(ProbeToken()):
        task = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    await asyncio.wait_for(waiter(), 0.5)


def test_error_sanitization_omits_credentials_urls_and_playwright_call_log():
    raw = RuntimeError("page.goto https://example.test/?token=TOPSECRET\nCall log:\nAuthorization: Bearer SECRET")
    sanitized = sanitize_error(raw)
    assert all(value not in sanitized for value in ("TOPSECRET", "SECRET", "example.test", "Call log"))
    assert "RuntimeError" in sanitized
