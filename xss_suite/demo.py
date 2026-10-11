"""Deliberately vulnerable, loopback-only practice application.

This fixture never binds a public interface and never contacts another service.
All saved values live in memory and are isolated by a random session cookie.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import ipaddress
import json
import secrets
import socket
import threading
import time
from typing import Iterator
from urllib.parse import parse_qs, quote, urlsplit


class PracticeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int]):
        self.events: list[dict] = []
        self.values: dict[str, str] = {}
        self.lock = threading.Lock()
        super().__init__(address, PracticeHandler)


class PracticeHandler(BaseHTTPRequestHandler):
    server: PracticeServer

    def log_message(self, format: str, *args: object) -> None:
        """Keep request contents (including potential credentials) out of stdout."""

    def _read(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_048_576:
            raise ValueError("Demo requests are limited to 1 MiB")
        raw = self.rfile.read(length) if length else b""
        self._body = raw.decode("utf-8", errors="replace")
        if self.headers.get("Content-Type", "").startswith("application/json"):
            value = json.loads(self._body or "{}")
            return value if isinstance(value, dict) else {}
        return {key: values[-1] for key, values in parse_qs(self._body, keep_blank_values=True).items()}

    def _session(self) -> tuple[str, bool]:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            pass
        session = cookie.get("xss_demo_session")
        value = session.value if session else ""
        if len(value) == 32 and all(c in "0123456789abcdef" for c in value):
            return value, False
        return secrets.token_hex(16), True

    def _reply(self, body: str | bytes, *, status: int = 200,
               content_type: str = "text/html; charset=utf-8", headers: dict | None = None) -> None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        self._handle({})

    def do_POST(self) -> None:
        try:
            self._handle(self._read())
        except (ValueError, json.JSONDecodeError):
            self._reply("Invalid request", status=400, content_type="text/plain")

    def _handle(self, data: dict) -> None:
        parsed = urlsplit(self.path)
        query = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}
        value = str(data.get("q", query.get("q", "")))
        route = parsed.path
        with self.server.lock:
            self.server.events.append({"method": self.command, "path": self.path,
                                       "headers": dict(self.headers), "body": getattr(self, "_body", "")})
        page = lambda body: "<!doctype html><html><head><meta charset='utf-8'><title>XSS practice</title></head><body>" + body + "</body></html>"
        if route == "/":
            self._reply(page("<h1>Local XSS practice</h1><p>Intentionally vulnerable; loopback only.</p>"
                             "<ul><li>/reflect?q=hello</li><li>/attribute?q=hello</li>"
                             "<li>/javascript?q=hello</li><li>/dom#hello</li><li>/form</li>"
                             "<li>/stored/view</li><li>/safe/escaped?q=hello</li>"
                             "<li>/safe/text#hello</li><li>/safe/json?q=hello</li>"
                             "<li>/safe/csp?q=hello</li></ul>"))
        elif route == "/reflect":
            self._reply(page("<main>" + value + "</main>"))
        elif route == "/attribute":
            self._reply(page('<input id="result" value="' + value + '">'))
        elif route == "/attribute-single":
            self._reply(page("<input id='result' value='" + value + "'>"))
        elif route == "/javascript":
            self._reply(page("<script>const value='" + value + "';</script>"))
        elif route == "/javascript-double":
            self._reply(page('<script>const value="' + value + '";</script>'))
        elif route == "/template":
            self._reply(page("<script>const value=`" + value + "`;</script>"))
        elif route == "/textarea":
            self._reply(page("<textarea>" + value + "</textarea>"))
        elif route == "/title":
            self._reply("<!doctype html><html><head><title>" + value + "</title></head><body>Title test</body></html>")
        elif route in ("/dom", "/safe/text"):
            sink = "innerHTML" if route == "/dom" else "textContent"
            self._reply(page("<main id='target'></main><script>document.getElementById('target')." + sink +
                             "=decodeURIComponent(location.hash.slice(1));</script>"))
        elif route == "/safe/escaped":
            self._reply(page("<main>" + html.escape(value, quote=True) + "</main>"))
        elif route == "/safe/json":
            self._reply(json.dumps({"q": value}), content_type="application/json; charset=utf-8")
        elif route == "/safe/csp":
            self._reply(page("<main>" + value + "</main>"), headers={
                "Content-Security-Policy": "default-src 'none'; script-src 'none'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'"})
        elif route == "/wrong-marker":
            self._reply(page("<script>globalThis.__xss_probe('xss_wrong_marker')</script><pre>" + html.escape(value) + "</pre>"))
        elif route == "/app/history":
            self._reply(page("<script>history.replaceState(null,'','/outside')</script>" + value))
        elif route in ("/form", "/json"):
            if self.command == "POST":
                self._reply(page("<main id='submitted'>" + value + "</main>"))
            else:
                self._reply(page("<form action='/form' method='post'><label>Value<input name='q' id='q'></label>"
                                 "<button id='send' type='submit'>Submit</button></form>"))
        elif route in ("/stored", "/stored/view", "/stored/clean", "/stored/delayed"):
            session, fresh = self._session()
            headers = {"Set-Cookie": "xss_demo_session=" + session + "; HttpOnly; SameSite=Strict; Path=/"} if fresh else {}
            if self.command == "POST":
                with self.server.lock:
                    self.server.values[session] = value
                if route == "/stored/delayed":
                    # Execution belongs to this submission document, never its later verification page.
                    self._reply(page("<script>setTimeout(()=>{document.body.innerHTML=" + json.dumps(value) + "},75)</script>"), headers=headers)
                else:
                    self._reply(page("<p>Saved in this browser session.</p>"), headers=headers)
            elif route == "/stored/clean":
                self._reply(page("<p>Clean verification page.</p>"), headers=headers)
            elif route == "/stored/view":
                with self.server.lock:
                    saved = self.server.values.get(session, "")
                self._reply(page("<main id='saved'>" + saved + "</main>"), headers=headers)
            else:
                self._reply(page("<form action='/stored' method='post'><input name='q' id='q'>"
                                 "<button id='send' type='submit'>Save</button></form>"), headers=headers)
        elif route == "/sandbox":
            self._reply(page('<iframe sandbox="allow-scripts" srcdoc="' + html.escape(value, quote=True) + '"></iframe>'))
        elif route == "/sandbox-url":
            target = "/reflect?q=" + quote(value, safe="")
            self._reply(page('<iframe sandbox="allow-scripts" src="' + html.escape(target, quote=True) + '"></iframe>'))
        elif route == "/sandbox-csp":
            self._reply(page(value), headers={"Content-Security-Policy": "sandbox allow-scripts"})
        elif route == "/frame":
            target = query.get("target", "/reflect?q=" + quote(value, safe=""))
            if query.get("inject") == "1":
                target += ("&" if "?" in target else "?") + "q=" + quote(value, safe="")
            self._reply(page('<iframe src="' + html.escape(target, quote=True) + '"></iframe>'))
        elif route == "/redirect":
            self._reply("Redirecting", status=302, headers={"Location": query.get("to", "/reflect?q=" + quote(value, safe=""))})
        elif route == "/rate-limit":
            self._reply("Slow down", status=429, content_type="text/plain", headers={"Retry-After": "1"})
        elif route == "/resources":
            self._reply(page(value + "".join(f"<img src='/pixel?n={n}'>" for n in range(20))))
        elif route == "/slow":
            time.sleep(min(max(float(query.get("delay", "0.1")), 0), 2))
            self._reply(page(value))
        elif route == "/pixel":
            self._reply(base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"), content_type="image/gif")
        elif route == "/cookie":
            session, fresh = self._session()
            headers = {"Set-Cookie": "xss_demo_session=" + session + "; HttpOnly; SameSite=Strict; Path=/"} if fresh else {}
            self._reply(page(value), headers=headers)
        elif route == "/websocket":
            self._reply(page("<script>new WebSocket('ws://'+location.host+'/ws')</script>" + value))
        elif route == "/worker":
            self._reply(page("<script>navigator.serviceWorker.register('/sw.js').catch(()=>{})</script>" + value))
        elif route == "/sw.js":
            self._reply("self.addEventListener('fetch',()=>{});", content_type="application/javascript")
        else:
            self._reply("Not found", status=404, content_type="text/plain")


def make_server(host: str = "127.0.0.1", port: int = 0) -> PracticeServer:
    """Build a server bound exclusively to a numeric loopback address."""
    if host == "localhost":
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("The practice server requires a loopback IP address") from exc
    if not address.is_loopback:
        raise ValueError("The practice server may only bind a loopback address")
    if address.version == 6:
        class IPv6PracticeServer(PracticeServer):
            address_family = socket.AF_INET6
        return IPv6PracticeServer((host, port))
    return PracticeServer((host, port))


create_server = make_server


@contextmanager
def serving(host: str = "127.0.0.1", port: int = 0) -> Iterator[tuple[PracticeServer, str]]:
    server = make_server(host, port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    bound_host, bound_port = server.server_address[:2]
    authority = f"[{bound_host}]" if ":" in bound_host else bound_host
    try:
        yield server, f"http://{authority}:{bound_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    with serving(host, port) as (_, base_url):
        print(f"Loopback XSS practice server: {base_url}", flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


def demo_config(base_url: str = "http://127.0.0.1:8765") -> dict:
    """Small deterministic coverage demonstration, including safe controls."""
    cases = [
        {"name": "Reflected HTML", "type": "query", "url": base_url + "/reflect", "parameter": "q", "payloads": ["html_svg"]},
        {"name": "Quoted attribute", "type": "query", "url": base_url + "/attribute", "parameter": "q", "payloads": ["attribute_double"]},
        {"name": "JavaScript string", "type": "query", "url": base_url + "/javascript", "parameter": "q", "payloads": ["js_single"]},
        {"name": "DOM fragment", "type": "fragment", "url": base_url + "/dom", "payloads": ["html_svg"]},
        {"name": "URL encoded POST", "type": "form_post", "url": base_url + "/form", "parameter": "q", "data": {}},
        {"name": "JSON POST", "type": "json_post", "url": base_url + "/json", "property": "q", "data": {"q": ""}},
        {"name": "Browser form", "type": "browser_form", "url": base_url + "/form", "field_selector": "#q", "submit_selector": "#send"},
        {"name": "Stored with shared cookies", "type": "stored", "submission_type": "form_post", "url": base_url + "/stored", "parameter": "q", "verification_urls": [base_url + "/stored/view"]},
        {"name": "Escaped HTML control", "type": "query", "url": base_url + "/safe/escaped", "parameter": "q"},
        {"name": "textContent control", "type": "fragment", "url": base_url + "/safe/text"},
        {"name": "JSON response control", "type": "query", "url": base_url + "/safe/json", "parameter": "q"},
        {"name": "CSP control", "type": "query", "url": base_url + "/safe/csp", "parameter": "q"},
    ]
    return {"scope": [base_url + "/"], "payloads": ["html_svg"], "headers": {},
            "limits": {"request_spacing_ms": 25, "timeout_ms": 5000, "observation_ms": 200,
                       "max_requests": 100, "max_probes": 30, "max_redirects": 5}, "cases": cases}
