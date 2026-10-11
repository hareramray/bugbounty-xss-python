# bugbounty-xss-python

A Python 3.11+ toolkit for scoped, authorized XSS testing. It injects harmless random markers and uses Playwright Chromium to distinguish execution from reflection. Use it only on targets and workflows for which you have permission. The included practice application and automated tests use loopback fixtures.

## Install

Windows PowerShell, from the project directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe -m pytest -q
```

Linux/macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m playwright install chromium
python -m pytest -q
```

On Linux systems missing browser libraries, use `python -m playwright install --with-deps chromium` (system package installation may require administrator privileges). The Python version used to create the environment must be 3.11 or newer. In PowerShell, use `.\.venv\Scripts\python.exe` in place of `python` in the following commands, or activate with `.\.venv\Scripts\Activate.ps1` if your execution policy permits it.

## Local demonstration

One command starts an ephemeral loopback server, tests it, writes reports, and stops it:

```bash
python -m xss_suite demo --scan --allow-writes --out reports/demo
```

The demo covers reflected HTML, quoted attributes, JavaScript strings, DOM fragments, URL-encoded and JSON POST, a real form, and stored data with shared session cookies. Escaped HTML, `textContent`, JSON responses, and an enforced CSP are safe controls. The server binds only loopback; stored data lives in memory. Every probe gets a new session unless a configured storage state deliberately seeds it.

To keep the server running and scan separately:

```bash
python -m xss_suite demo --port 8765
# In a second terminal:
python -m xss_suite scan --config examples/demo.json --allow-writes --out reports/demo
```

## Commands

```bash
python -m xss_suite validate --config examples/target.json
python -m xss_suite scan --config examples/target.json --dry-run
python -m xss_suite scan --config examples/target.json
python -m xss_suite scan --config examples/target.json --allow-writes
python -m xss_suite scan --config examples/target.json --http-only
python -m xss_suite scan --config examples/target.json --headed --out reports/target --fail-on-confirmed
python -m xss_suite payloads
```

`examples/target.json` uses nonfunctional `.example` placeholder URLs; copy it to an ignored `local-configs/` directory and set your authorized target before scanning. Use `examples/demo.json` for the running loopback practice server. Validation and dry runs send no requests. `--allow-writes` is required for explicit POST, browser-form, and stored workflows; otherwise those cases are reported as skipped. Even GET requests can have application-specific side effects, so select permitted endpoints. `--http-only` does not need Chromium to be installed but still needs the Python Playwright package. It reports HTTP evidence without confirming JavaScript execution; browser-only interactions cannot be exercised in that mode.

`--out` is a path prefix: `reports/target` writes `reports/target.json` and `reports/target.html`. A `.json` or `.html` suffix is accepted; an existing directory receives `xss-report.json` and `xss-report.html`. `--headed` shows the verification browser. The installed `xss-suite` command is equivalent to `python -m xss_suite`.

| Exit code | Meaning |
| --- | --- |
| `0` | Command completed; inspect results and skipped coverage. Confirmations also return 0 without `--fail-on-confirmed`. |
| `1` | At least one confirmed probe and `--fail-on-confirmed` was supplied. Takes precedence over an incomplete scan. |
| `2` | Invalid CLI/configuration, missing Python dependency, unrecoverable setup failure, or report I/O failure. |
| `3` | Scan stopped, incomplete, interrupted, or includes an inconclusive probe (including a failed Chromium launch). |

## Configuration

JSON configuration is strict: unsupported keys, unknown payload IDs, invalid limits, ambiguous URLs, and out-of-scope configured URLs are rejected. Relative storage-state paths resolve from the configuration file's directory.

```json
{
  "scope": ["https://app.example.test/authorized"],
  "headers": {"X-Researcher": "authorized-testing"},
  "payloads": ["html_svg", "attribute_double", "js_single"],
  "limits": {
    "request_spacing_ms": 250,
    "timeout_ms": 10000,
    "observation_ms": 750,
    "max_requests": 100,
    "max_probes": 30,
    "max_redirects": 5
  },
  "cases": [
    {
      "name": "Search text",
      "type": "query",
      "url": "https://app.example.test/authorized/search",
      "parameter": "q"
    },
    {
      "name": "Client fragment",
      "type": "fragment",
      "url": "https://app.example.test/authorized/preview",
      "payloads": ["html_svg"]
    },
    {
      "name": "Encoded form endpoint",
      "type": "form_post",
      "url": "https://app.example.test/authorized/preview",
      "parameter": "message",
      "data": {"category": "test"}
    },
    {
      "name": "JSON property",
      "type": "json_post",
      "url": "https://app.example.test/authorized/api/preview",
      "property": "message",
      "data": {"message": "", "kind": "test"}
    },
    {
      "name": "Live form",
      "type": "browser_form",
      "url": "https://app.example.test/authorized/form",
      "field_selector": "#message",
      "submit_selector": "button[type=submit]",
      "payloads": ["html_svg"]
    },
    {
      "name": "Stored note",
      "type": "stored",
      "submission_type": "form_post",
      "url": "https://app.example.test/authorized/notes",
      "parameter": "message",
      "data": {"category": "test"},
      "verification_urls": ["https://app.example.test/authorized/notes/view"],
      "observation_ms": 1000,
      "payloads": ["html_svg"]
    }
  ]
}
```

Replace the example URLs only with approved targets. Optional top-level `storage_state` accepts a path to a Playwright authentication-state JSON file, for example `"storage_state": "../auth/account.json"`. The state initializes each fresh context; cookies then follow browser domain/path rules. Seed only the intended account and domains. Save and rotate this file as a credential, and keep it out of version control.

Case names must be unique. Each case may override `headers`, `payloads`, `timeout_ms`, and `observation_ms`. Per-case headers override global headers. Header injection is bound to the case's original origin; configured headers are not forwarded to other origins, including an otherwise allowed verification origin. Cookie authentication should use storage state instead of a custom `Cookie` header. A JSON probe injects one selected top-level property, leaving the other configured properties intact. A browser-form probe fills the selected field and clicks the selected submit control; this preserves existing fields and browser form behavior. For browser forms, optional `data` maps additional field selectors to values; for raw POST types, it maps submitted field/property names to values. Stored `submission_type` supports `form_post`, `json_post`, and `browser_form`; browser-form submissions also require selectors. Every stored case must provide explicit `verification_urls`.

The ten payload templates cover HTML text, single/double quoted attributes, single/double quoted JavaScript strings, template literals, and textarea/title/script boundaries. Each actual probe receives a cryptographically random execution marker. Templates call the local browser evidence binding; they contain no external callback endpoint and do not read cookies or exfiltrate data. Choose templates appropriate to the input context instead of assuming every template applies everywhere.

## Evidence model

| Observation | Meaning |
| --- | --- |
| `confirmed` | The exact probe marker executed in an allowed frame at the expected effective origin. |
| `reflected` | Input or its marker was observed, without qualifying execution evidence. |
| `not_observed` | No qualifying execution or reflection was observed during this bounded probe. This does not establish safety. |
| `inconclusive` | A control, failure, budget, timeout, or blocked request prevented adequate observation. Review evidence and limitations. |
| `skipped` | A required permission or supported mode was missing, or the probe was not attempted. |

Every probe uses a fresh browser context. Within a stored probe, submission and verification share the session cookie jar. Confirmation is attributed to the actual verification document; the submission page is closed before verification, so delayed execution on that page cannot become stored evidence. Chromium DevTools execution-context and frame metadata establish the effective origin; the scanner does not trust a page-supplied origin string or execute its injected payload through `evaluate`. Opaque origins, sandboxed-origin frames, wrong markers, inherited `about:blank`/`srcdoc` documents, and unexpected-origin frames are rejected as first-party confirmation. Reflection in raw HTTP or JSON is never converted to execution evidence.

Chromium keeps CSP and TLS certificate validation enabled. The toolkit never uses `set_content` or a synthetic HTML wrapper to execute a response. Browser requests are fetched with redirects disabled and fulfilled using the original response content and headers at the original browser URL. JSON remains JSON. HTTP-only mode records response evidence and cannot produce a confirmed result.

Reports include payloads and markers, reproduction details, response excerpts, execution/frame origins, blocked requests, errors, and coverage limitations. JSON preserves evidence verbatim; HTML escapes every value and disables scripts with a restrictive CSP. Playwright call logs are removed from reported errors. Reports may still contain private application content in response excerpts and configured reproduction data, so store them privately and redact before sharing.

The `__xss_probe` evidence binding exists inside the scanner's browser. Reproduce with the same case configuration and CLI command; a copied payload alone does not install that binding in an ordinary browser. For an approved standalone manual proof, use a harmless console marker and independently inspect the frame's effective origin.

Observation counts describe individual case/payload result entries, including skipped probes that made no requests. Read `skipped`, `requests`, and `probes_started` alongside the total; a planned result entry does not imply a tested location. `unique_vulnerabilities` groups confirmed observations by type, configured URL, parameter/property, field selector, and verification URLs, rather than counting every executing payload or case name as a separate vulnerability. This is a reporting heuristic; review root causes and merge related cases manually before filing findings.

## Scope and traffic controls

Scope matches scheme, normalized hostname, effective port, and complete path segments. For example, `https://host.test/app` permits `/app` and `/app/search`, but not `/application`, HTTP, or a different port. Query strings do not widen the allowed path. Hostnames must use ASCII; enter internationalized hostnames explicitly in punycode so Python and Chromium cannot disagree about their identity. Unicode paths remain supported subject to path checks. Ambiguous path encodings and URL forms are rejected conservatively. All configured submission and verification URLs must be in scope; browser resources and frame requests must pass the same checks.

HTTP requests follow redirects only after checking each destination, origin/header policy, budget, and pacing. Browser HTTP redirects are blocked, including same-origin redirects: a browser route hook does not provide a reliable opportunity to approve every native redirect hop before it is sent. Fetching a redirect chain and fulfilling the final body under the first URL would change document URL/origin semantics, so the toolkit does not do that. Redirect-dependent login and POST/Redirect/GET applications require direct approved final URLs or manual follow-up. This behavior uses Playwright's [`route.fetch(max_redirects=0)`](https://playwright.dev/python/docs/api/class-route#route-fetch).

Service workers are disabled using [`service_workers="block"`](https://playwright.dev/python/docs/api/class-browser#browser-new-context-option-service-workers), and WebSockets are closed through [`BrowserContext.route_web_socket`](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route-web-socket). These controls reduce browser functionality and are included in coverage limitations. Each controlled network request consumes the global hard request budget; probes have a separate global hard budget. Pacing applies between request admissions across probes, including browser resources and redirect hops. HTTP 429 stops the scan. Closing a probe cancels its queued requests before they can be admitted. TLS verification remains enabled; no insecure certificate override is offered.

## Tests and follow-up

```bash
python -m pytest -q
python -m pytest -q tests/test_cli_reports.py
```

The tests use local HTTP fixtures and never target a public application. Browser integration tests need the Chromium binary installed. The suite covers positive execution, safe controls, frame/origin restrictions, storage-state and session behavior, scope, redirects, authentication handling, pacing/budgets/cancellation, report escaping, and CLI behavior.

This is bounded testing, not exhaustive XSS coverage. It does not crawl, discover inputs, brute force contexts, solve authentication challenges, generate dynamic CSRF tokens for raw POSTs, test every encoding/parser/browser, or exercise arbitrary user gestures and application state. Nested JSON fields, file uploads, rich editor interactions, second-user stored rendering, long delayed execution, browser extensions, and redirect-dependent workflows need manual investigation. A pre-authenticated state may expire. Blocking out-of-scope dependencies can make otherwise valid pages inconclusive. Fresh browser contexts isolate client state, but persistent server-side writes are not automatically rolled back. Use disposable test records and perform approved cleanup.

See the [manual testing checklist](docs/manual-checklist.md) and [finding template](docs/finding-template.md) for triage and reporting.
