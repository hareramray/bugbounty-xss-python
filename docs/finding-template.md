# Finding: [Reflected / DOM / Stored XSS] in [location]

**Program / asset:** [authorized program and origin/path]

**Test date and account role:** [date, role; never include credentials]

**Affected input:** [method, parameter/property, fragment, or form field]

**Observed impact:** [what the harmless proof establishes; separate demonstrated behavior from potential consequences]

## Summary

[Describe how attacker-controlled input reaches an executable browser context. State who must view or interact with it and the required privileges. Do not claim impact solely from reflection.]

## Reproduction

1. Sign in using an approved test account with [role].
2. Visit or submit [exact authorized endpoint and method].
3. Inject the following harmless payload in [input location], using a fresh marker:

   ```text
   [payload from the report]
   ```

4. For a stored workflow, close the submission page and visit [explicit verification URL] in the intended approved session.
5. Observe [exact marker execution] in [frame URL] at effective origin [origin].

**Prerequisites:** [authentication state, relevant nonsecret fields, user interaction, timing]

Toolkit payloads call `__xss_probe`, a binding installed by the scanner. Attach a redacted case configuration and CLI command for an automated reproduction. For a standalone manual proof, replace only that call with an approved harmless console marker, and independently verify the executing frame's effective origin. An undefined binding outside the toolkit does not mean the original injection was safe.

**Expected behavior:** [input remains data through contextual escaping or a safe DOM sink]

**Actual behavior:** [marker executes with the documented effective origin]

## Evidence

- Case and payload ID: [identifiers]
- Exact marker: [marker]
- Observation status: [confirmed]
- Document URL and execution origin: [values]
- Stored verification URL, if applicable: [URL]
- Content type and relevant CSP: [redacted headers]
- Minimal redacted response excerpt or DOM sink: [excerpt]
- Browser/version and observation window: [details]
- Corroborating screenshot or recording: [optional; no private content]
- JSON report reference: [private path or approved attachment]

## Scope and limitations

[List blocked requests, redirects, incomplete coverage, and any manual steps. Explain related payload observations that represent the same root cause. Do not present sandboxed-origin execution, raw JSON reflection, or a synthetic HTML rendering as first-party XSS evidence.]

## Remediation suggestion

[Recommend contextual output encoding or a safe DOM API appropriate to the sink, avoid unsafe HTML parsing, and retain CSP as defense in depth. Tie the suggestion to the observed code path; do not assume one encoder is suitable for every context.]

## Cleanup and retest

[Identify approved test records removed or pending removal. Re-run the original harmless proof after a fix and include negative controls.]
