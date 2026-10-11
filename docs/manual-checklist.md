# Manual XSS testing checklist

Use this checklist alongside the JSON evidence report. All manual steps must remain within the authorized program scope.

## Before a scan

- [ ] Confirm the exact approved scheme, hostname, ports, path segments, and account role.
- [ ] Check the program's automation, rate, and stored-content rules; configure spacing and small hard budgets accordingly.
- [ ] Copy an example into ignored `local-configs/`; select only intended cases and payload contexts.
- [ ] Check that every resource or verification origin needed by the workflow is explicitly approved before extending scope.
- [ ] Protect authentication storage state and use a disposable account/record where possible.
- [ ] Run `validate` and `scan --dry-run`; inspect the probe count and URLs.
- [ ] Supply `--allow-writes` only for approved writes, and identify how to remove test records afterward.

## Interpret results

- [ ] Read blocked requests, errors, and coverage limitations as well as result status.
- [ ] Treat `reflected` as an input-handling observation, not an XSS finding.
- [ ] For `confirmed`, verify the exact marker, effective execution origin, frame URL, and payload used.
- [ ] Reject sandboxed or opaque-origin execution as proof of first-party access.
- [ ] For stored cases, check that execution belongs to the explicit verification page and that the submitting page was closed.
- [ ] Confirm that CSP was enforced and the response was rendered in its real context with its original content type.
- [ ] Review `inconclusive` and `skipped` cases separately; absence of confirmation is not a safety guarantee.
- [ ] Distinguish payload-level observations from unique root causes before reporting counts.

## Reproduce a candidate

- [ ] Use the same authenticated role, browser, original endpoint, HTTP method, parameter/property or selector, and payload.
- [ ] Repeat with a fresh random marker and a clean browser session as appropriate.
- [ ] Preserve existing CSRF fields for browser forms; do not bypass permission or workflow checks.
- [ ] Keep the proof harmless: demonstrate marker execution without collecting another person's content, cookies, or tokens.
- [ ] For stored XSS, verify the intended audience and role only with approved test accounts.
- [ ] Inspect encoding, DOM sinks, headers, and CSP to identify the underlying cause.
- [ ] Manually test workflows excluded by redirect blocking only after independently checking every hop's authorization.
- [ ] Capture minimal reproduction steps and redacted evidence; do not attach credentials or unneeded private response data.
- [ ] Clean up approved test records; this toolkit does not undo server-side writes.

## Local regression checks

- [ ] Run `python -m pytest -q` with local Chromium installed.
- [ ] Run `python -m xss_suite demo --scan --allow-writes --out reports/demo`.
- [ ] Confirm positive demo routes execute and all safe controls lack confirmed execution.
- [ ] Open the HTML report locally and confirm payloads display as text without executing.
- [ ] Run the demo with `--http-only`; verify no confirmed results are produced.
