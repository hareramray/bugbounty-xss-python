"""Scoped HTTP probes and Chromium execution verification.

The transport fetches each intercepted request once, without redirects, and
fulfills that SAME request with its unmodified response. It never creates HTML
documents from API responses. CDP execution-context metadata, not page supplied
origin strings or reflection, is the authority for execution evidence.
"""
from __future__ import annotations

import asyncio
import json
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from .config import validate_config
from .control import BudgetExceeded, ControlError, ProbeClosed, ProbeToken, RequestBudget
from .payloads import new_marker, select_payloads
from .scope import Scope, origin


LIMITATIONS = [
    "Finite templates, selected fields, and observation windows do not provide exhaustive XSS coverage.",
    "All browser HTTP redirect responses are blocked: Playwright routing cannot reliably validate every native redirect hop. Client-side HTTP(S) navigations are separately scoped.",
    "Service workers and WebSockets are blocked; these and blocked resources can reduce application coverage.",
    "Only allowed HTTP(S) frames with trusted Chromium effective origin equal to the current test or verification origin can confirm. Opaque, sandboxed, inherited about:blank/srcdoc, and cross-origin frame execution is excluded.",
    "Browser requests use a serialized fetch/fulfill transport with TLS verification and preserved URL, content type, and CSP. Streaming, downloads, cache behavior and browser-native authentication can differ.",
    "HTTP-only mode observes responses and cannot confirm JavaScript execution. Browser forms and DOM fragments require Chromium.",
    "Storage state initializes each fresh probe context. Server-side writes persist; isolation does not undo stored data or provide automatic cleanup.",
    "Reported unique vulnerabilities are deduplicated candidate locations, not a claim of independently verified root causes.",
    "Scope enforcement covers toolkit-controlled HTTP(S) requests, not a network firewall or DNS/IP authorization boundary. Only test systems you are authorized to use.",
]


def sanitize_error(error: BaseException) -> str:
    """Never copy Playwright call logs, URLs, headers, or credentials into errors."""
    if isinstance(error, ControlError):
        return str(error)
    if isinstance(error, asyncio.TimeoutError) or type(error).__name__ == "TimeoutError":
        return "Operation timed out; sensitive call details omitted"
    return f"{type(error).__name__}: operation failed; sensitive call details omitted"


def _kind(case):
    return case.get("submission_type", "form_post") if case["type"] == "stored" else case["type"]


def _writes(case):
    return _kind(case) in {"form_post", "json_post", "browser_form"}


def _request(case, payload):
    kind = _kind(case)
    url, method, body, content_type = case["url"], "GET", None, None
    if kind == "query":
        parts = urlsplit(url)
        pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != case["parameter"]]
        pairs.append((case["parameter"], payload))
        url = urlunsplit(parts._replace(query=urlencode(pairs)))
    elif kind == "fragment":
        url = urlunsplit(urlsplit(url)._replace(fragment=quote(payload, safe="")))
    elif kind in {"form_post", "json_post"}:
        data = dict(case["data"])
        data[case["property"] if kind == "json_post" else case["parameter"]] = payload
        method = "POST"
        if kind == "json_post":
            body, content_type = json.dumps(data, ensure_ascii=False).encode(), "application/json"
        else:
            body, content_type = urlencode(data).encode(), "application/x-www-form-urlencoded"
    return url, method, body, content_type


def plan(config):
    config = validate_config(config)
    probes = []
    for case in config["cases"]:
        for template in select_payloads(case["payloads"]):
            probes.append({"case": case["name"], "type": case["type"], "url": case["url"],
                           "payload_id": template.id, "requires_allow_writes": _writes(case),
                           "verification_urls": case.get("verification_urls", [])})
    return {"dry_run": True, "network_requests": 0, "planned_probes": len(probes),
            "probe_budget": config["limits"]["max_probes"], "request_budget": config["limits"]["max_requests"],
            "probes": probes, "limitations": LIMITATIONS}


class Probe:
    def __init__(self, config, case, template, budget, allow_writes):
        self.config, self.case, self.budget = config, case, budget
        self.scope = Scope(config["scope"])
        self.allow_writes = allow_writes
        self.token = ProbeToken()
        self.page_tokens = {}
        self.marker = new_marker()
        self.payload = template.render(self.marker)
        self.headers = {**config["headers"], **case["headers"]}
        self.auth_origin = origin(case["url"])
        self.active_page = None
        self.pending_post = None
        self.routed_tasks = set()
        self.instrument_sessions = []
        self.result = {"case": case["name"], "type": case["type"], "url": case["url"],
                       "payload_id": template.id, "payload": self.payload, "marker": self.marker,
                       "status": "not_observed", "reflection": False, "execution": [],
                       "rejected_executions": [], "blocked_requests": [], "errors": [],
                       "response_excerpts": [], "reproduction": {"type": case["type"],
                       "url": case["url"], "parameter": case.get("parameter"),
                       "property": case.get("property"), "verification_urls": case.get("verification_urls", []),
                       "submission_type": case.get("submission_type"), "data": case["data"],
                       "field_selector": case.get("field_selector"), "submit_selector": case.get("submit_selector"),
                       "observation_ms": case["observation_ms"], "timeout_ms": case["timeout_ms"],
                       "marker_observer": "__xss_probe is a toolkit-installed evidence binding. Re-run this case with the CLI to reproduce, or use an approved harmless console marker for manual investigation.",
                       "authentication": "Configured storage state / headers are required (values omitted)" if config.get("storage_state") or self.headers else "None configured"}}

    def block(self, url, reason, method=None):
        self.result["blocked_requests"].append({"url": url, "method": method, "reason": reason})

    def error(self, error):
        message = sanitize_error(error)
        if message not in self.result["errors"]:
            self.result["errors"].append(message)

    def headers_for(self, url, existing=None):
        # Treat EVERY configured header as potentially secret, not just Authorization.
        headers = {k.lower(): v for k, v in (existing or {}).items()}
        for name in self.headers:
            headers.pop(name.lower(), None)
        if origin(url) == self.auth_origin:
            headers.update(self.headers)
        else:
            headers.pop("authorization", None)
            headers.pop("proxy-authorization", None)
        return headers

    async def observe(self, response, url):
        status, headers = response.status, response.headers
        content_type = headers.get("content-type", "")
        if status == 429:
            self.budget.stop("HTTP 429 received; scan stopped")
        if status >= 400:
            note = f"HTTP {status} response limits coverage"
            if note not in self.result["errors"]:
                self.result["errors"].append(note)
        if any(t in content_type.lower() for t in ("text/", "json", "javascript", "xml")):
            body = (await response.body()).decode("utf-8", errors="replace")
            pos = body.find(self.marker)
            if pos >= 0:
                self.result["reflection"] = True
            # Retain useful bounded evidence, not complete documents or cookies.
            if len(self.result["response_excerpts"]) < 8:
                start = max(0, pos - 250) if pos >= 0 else 0
                excerpt = body[start:start + 1200]
                for secret in self.headers.values():
                    if secret:
                        excerpt = excerpt.replace(secret, "[REDACTED]")
                self.result["response_excerpts"].append({"url": url, "status": status,
                    "content_type": content_type, "csp": headers.get("content-security-policy"),
                    "text": excerpt, "marker_present": pos >= 0})

    async def http_request(self, client, url, method="GET", body=None, content_type=None):
        seen = 0
        while True:
            if not self.scope.allows(url):
                self.block(url, "Outside explicit scope", method)
                return
            headers = self.headers_for(url)
            if content_type:
                headers["content-type"] = content_type
            async with self.budget.permit(self.token):
                response = await client.fetch(url, method=method, data=body, headers=headers,
                    timeout=self.case["timeout_ms"], max_redirects=0, fail_on_status_code=False)
                await self.observe(response, url)
                status = response.status
                location = response.headers.get("location")
                await response.dispose()
            if self.budget.stopped.is_set():
                raise BudgetExceeded(self.budget.reason)
            if status in {301, 302, 303, 307, 308} and location:
                target = urljoin(url, location)
                if not self.scope.allows(target):
                    self.block(target, "HTTP redirect destination outside scope", method)
                    return
                if seen >= self.config["limits"]["max_redirects"]:
                    self.block(target, "HTTP redirect hop limit reached", method)
                    return
                seen += 1
                if status == 303 or (status in {301, 302} and method == "POST"):
                    method, body, content_type = "GET", None, None
                url = target
                continue
            return

    async def http(self, playwright):
        if _kind(self.case) in {"fragment", "browser_form"}:
            self.result["status"] = "skipped"
            self.result["skip_reason"] = "This workflow requires browser verification"
            return
        client = await playwright.request.new_context(storage_state=self.config.get("storage_state"),
                    ignore_https_errors=False, timeout=self.case["timeout_ms"])
        try:
            request = _request(self.case, self.payload)
            self.result["reproduction"].update({"request_url": request[0], "method": request[1],
                "body": request[2].decode() if request[2] else None})
            await self.http_request(client, *request)
            if self.case["type"] == "stored":
                for url in self.case["verification_urls"]:
                    await self.http_request(client, url)
        finally:
            self.token.close()
            await client.dispose()

    async def route(self, route):
        task = asyncio.current_task()
        self.routed_tasks.add(task)
        request = route.request
        response = None
        try:
            url, method = request.url, request.method
            if not self.scope.allows(url):
                self.block(url, "Outside explicit scope", method)
                await route.abort("blockedbyclient")
                return
            if method not in {"GET", "HEAD", "OPTIONS"} and not self.allow_writes:
                self.block(url, "Write request requires --allow-writes", method)
                await route.abort("blockedbyclient")
                return
            try:
                page = request.frame.page
                token = self.page_tokens.get(page, self.token)
            except Exception:
                self.block(url, "Request has no attributable browser frame", method)
                await route.abort("blockedbyclient")
                return
            headers = self.headers_for(url, await request.all_headers())
            if _kind(self.case) == "browser_form" and request.post_data and self.marker in request.post_data:
                self.result["reproduction"]["submitted_request"] = {
                    "url": url, "method": method, "body": request.post_data,
                    "content_type": headers.get("content-type")}
            kwargs = {}
            if self.pending_post and request.is_navigation_request() and page is self.active_page and request.frame == page.main_frame:
                wanted_url, wanted_method, body, content_type = self.pending_post
                if urlsplit(url)._replace(fragment="") == urlsplit(wanted_url)._replace(fragment=""):
                    method = wanted_method
                    kwargs.update(method=method, post_data=body)
                    headers["content-type"] = content_type
                    headers.pop("content-length", None)
                    self.pending_post = None
            async with self.budget.permit(token):
                response = await route.fetch(headers=headers, max_redirects=0, max_retries=0,
                                             timeout=self.case["timeout_ms"], **kwargs)
                await self.observe(response, url)
                if self.budget.stopped.is_set():
                    self.block(url, self.budget.reason, method)
                    await route.abort("blockedbyclient")
                elif 300 <= response.status < 400:
                    location = response.headers.get("location")
                    target = urljoin(url, location) if location else url
                    scoped = self.scope.allows(target)
                    reason = "Browser redirect blocked; every native hop cannot be checked"
                    if not scoped:
                        reason += "; destination outside scope"
                    self.block(target, reason, method)
                    await route.abort("blockedbyclient")
                elif token.closed.is_set() or self.token.closed.is_set():
                    await route.abort("blockedbyclient")
                else:
                    # Preserve actual bytes, status, content type, URL and CSP.
                    await route.fulfill(response=response)
        except Exception as error:
            if isinstance(error, BudgetExceeded):
                self.block(request.url, str(error), request.method)
            if not self.token.closed.is_set() and not isinstance(error, ProbeClosed):
                self.error(error)
            try:
                await route.abort("blockedbyclient")
            except Exception:
                pass
        finally:
            if response:
                try:
                    await response.dispose()
                except Exception:
                    pass
            self.routed_tasks.discard(task)

    async def instrument(self, context, page, target_url, phase):
        """Use trusted DevTools metadata; never ask injected JS what its origin is."""
        session = await context.new_cdp_session(page)
        self.instrument_sessions.append(session)
        contexts, frames = {}, {}
        expected = origin(target_url)

        def frame_navigated(event):
            frame = event["frame"]
            frames[frame["id"]] = frame

        def context_created(event):
            c = event["context"]
            contexts[c["id"]] = c

        def within_document(event):
            # pushState/replaceState/hash changes do not emit frameNavigated.
            if event["frameId"] in frames:
                frames[event["frameId"]]["url"] = event["url"]

        def binding_called(event):
            if event.get("name") != "__xss_probe" or event.get("payload") != self.marker:
                return
            if self.token.closed.is_set() or page is not self.active_page:
                return
            c = contexts.get(event.get("executionContextId"), {})
            aux = c.get("auxData", {})
            frame = frames.get(aux.get("frameId"), {})
            frame_url = frame.get("url", "")
            context_origin, effective = c.get("origin", ""), frame.get("securityOrigin", "")
            accepted = False
            try:
                accepted = bool(aux.get("isDefault") and self.scope.allows(frame_url)
                                and origin(frame_url) == expected
                                and origin(context_origin) == expected
                                and origin(effective) == expected)
            except (ValueError, TypeError):
                pass
            evidence = {"marker": self.marker, "url": frame_url, "origin": context_origin,
                        "context_origin": context_origin, "frame_security_origin": effective,
                        "expected_origin": expected, "frame_id": aux.get("frameId"), "phase": phase}
            if phase == "verification":
                evidence["verification_url"] = target_url
            if accepted:
                if evidence not in self.result["execution"]:
                    self.result["execution"].append(evidence)
            else:
                evidence["reason"] = "Frame URL or trusted effective origin was not eligible"
                self.result["rejected_executions"].append(evidence)

        session.on("Page.frameNavigated", frame_navigated)
        session.on("Page.navigatedWithinDocument", within_document)
        session.on("Page.frameDetached", lambda e: frames.pop(e["frameId"], None))
        session.on("Runtime.executionContextCreated", context_created)
        session.on("Runtime.executionContextDestroyed", lambda e: contexts.pop(e["executionContextId"], None))
        session.on("Runtime.executionContextsCleared", lambda _: contexts.clear())
        session.on("Runtime.bindingCalled", binding_called)
        await session.send("Page.enable")
        await session.send("Runtime.enable")
        await session.send("Runtime.addBinding", {"name": "__xss_probe"})

    async def observe_window(self):
        try:
            await asyncio.wait_for(self.budget.stopped.wait(), self.case["observation_ms"] / 1000)
        except asyncio.TimeoutError:
            pass
        if self.budget.stopped.is_set():
            raise BudgetExceeded(self.budget.reason)

    async def close_page(self, page):
        self.page_tokens[page].close()
        if self.active_page is page:
            self.active_page = None
        await page.close()

    async def browser(self, browser):
        context = await browser.new_context(storage_state=self.config.get("storage_state"),
                    ignore_https_errors=False, service_workers="block", accept_downloads=False,
                    bypass_csp=False)
        context.set_default_timeout(self.case["timeout_ms"])

        async def websocket(ws):
            self.block(ws.url, "WebSockets are disabled")
            await ws.close()

        await context.route("**/*", self.route)
        await context.route_web_socket("**/*", websocket)
        try:
            page = await context.new_page()
            self.page_tokens[page] = ProbeToken()
            is_stored = self.case["type"] == "stored"
            # Submission pages never provide stored-XSS confirmation evidence.
            if not is_stored:
                self.active_page = page
                await self.instrument(context, page, self.case["url"], "test")
            url, method, body, content_type = _request(self.case, self.payload)
            self.result["reproduction"].update({"request_url": url, "method": method,
                "body": body.decode() if body else None})
            if _kind(self.case) == "browser_form":
                self.result["reproduction"]["method"] = "browser_form"
                self.result["reproduction"]["navigation_method"] = "GET"
                await page.goto(url, wait_until="domcontentloaded")
                for selector, value in self.case["data"].items():
                    await page.locator(selector).fill(str(value))
                await page.locator(self.case["field_selector"]).fill(self.payload)
                await page.locator(self.case["submit_selector"]).click()
            else:
                if method == "POST":
                    self.pending_post = (url, method, body, content_type)
                    # Needed only for transport identity; not eligible for evidence.
                    self.active_page = page
                await page.goto(url, wait_until="domcontentloaded")
            if is_stored:
                self.active_page = None
            await self.observe_window()
            if is_stored:
                # Close submission before opening verification. Cookies stay in context.
                await self.close_page(page)
                for target_url in self.case["verification_urls"]:
                    verification_page = await context.new_page()
                    self.page_tokens[verification_page] = ProbeToken()
                    self.active_page = verification_page
                    await self.instrument(context, verification_page, target_url, "verification")
                    await verification_page.goto(target_url, wait_until="domcontentloaded")
                    await self.observe_window()
                    await self.close_page(verification_page)
        finally:
            self.token.close()
            self.active_page = None
            for token in self.page_tokens.values():
                token.close()
            await context.close()
            if self.routed_tasks:
                await asyncio.gather(*list(self.routed_tasks), return_exceptions=True)

    def finish(self):
        if self.result["status"] == "skipped":
            return self.result
        if self.result["execution"]:
            self.result["status"] = "confirmed"
        elif self.result["errors"] or self.result["blocked_requests"] or self.result["rejected_executions"]:
            self.result["status"] = "inconclusive"
        elif self.result["reflection"]:
            self.result["status"] = "reflected"
        else:
            self.result["status"] = "not_observed"
        return self.result


async def scan(config, *, allow_writes=False, http_only=False, headed=False):
    """Run sequential probes; each gets an independent authenticated context."""
    from playwright.async_api import async_playwright

    config = validate_config(config)
    limits = config["limits"]
    budget = RequestBudget(limits["max_requests"], limits["request_spacing_ms"])
    results, probes = [], 0
    async with async_playwright() as playwright:
        browser = None
        try:
            for case in config["cases"]:
                for template in select_payloads(case["payloads"]):
                    probe = Probe(config, case, template, budget, allow_writes)
                    reason = None
                    if _writes(case) and not allow_writes:
                        reason = "Explicit POST/form workflow requires --allow-writes"
                    elif http_only and _kind(case) in {"fragment", "browser_form"}:
                        reason = "This workflow requires browser verification"
                    elif budget.stopped.is_set():
                        reason = budget.reason
                    elif probes >= limits["max_probes"]:
                        budget.stop("Hard probe budget exhausted")
                        reason = budget.reason
                    if reason:
                        probe.result.update(status="skipped", skip_reason=reason)
                        results.append(probe.finish())
                        continue
                    probes += 1
                    try:
                        if http_only:
                            await probe.http(playwright)
                        else:
                            if browser is None:
                                browser = await playwright.chromium.launch(headless=not headed)
                            await probe.browser(browser)
                    except Exception as error:
                        probe.error(error)
                    finally:
                        probe.token.close()
                    results.append(probe.finish())
        finally:
            if browser:
                await browser.close()
    counts = Counter(r["status"] for r in results)
    for status in ("confirmed", "reflected", "not_observed", "inconclusive", "skipped"):
        counts.setdefault(status, 0)
    locations = set()
    for r in results:
        if r["status"] == "confirmed":
            case = next(c for c in config["cases"] if c["name"] == r["case"])
            key = (case["type"], case["url"], case.get("parameter"), case.get("property"),
                   case.get("field_selector"), tuple(case.get("verification_urls", [])))
            locations.add(key)
    return {"tool": "bugbounty-xss-python", "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "http_only" if http_only else "browser", "scope": config["scope"],
            "results": results, "counts": {"probe_observations": len(results), **dict(counts),
                "unique_vulnerabilities": len(locations), "requests": budget.requests, "probes_started": probes},
            "stopped": budget.stopped.is_set(), "stop_reason": budget.reason,
            "incomplete": budget.stopped.is_set() or bool(counts["inconclusive"])
                or any(r["errors"] or r["blocked_requests"] for r in results),
            "limitations": LIMITATIONS}
