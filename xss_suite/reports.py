"""Portable JSON and escaped HTML reports without executable report content."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _pretty(value: Any) -> str:
    return _escape(json.dumps(value, ensure_ascii=False, indent=2))


def render_html(report: dict[str, Any]) -> str:
    """Render every report field as inert text; never link target-controlled URLs."""
    rows: list[str] = []
    details: list[str] = []
    for index, result in enumerate(report.get("results", []), start=1):
        cells = [index, result.get("case", ""), result.get("type", ""),
                 result.get("payload_id", ""), result.get("status", ""),
                 result.get("url", "")]
        rows.append("<tr>" + "".join(f"<td>{_escape(cell)}</td>" for cell in cells) + "</tr>")
        details.append(
            f"<details><summary>Probe {index}: {_escape(result.get('case', ''))} "
            f"({_escape(result.get('status', ''))})</summary>"
            f"<pre>{_pretty(result)}</pre></details>"
        )
    metadata = {key: value for key, value in report.items() if key != "results"}
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; img-src 'none'; connect-src 'none'">
<title>XSS test report</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#172033;background:#f8fafc}h1,h2{line-height:1.2}table{border-collapse:collapse;width:100%;font-size:.9rem}td,th{border:1px solid #cad3df;padding:.5rem;text-align:left;overflow-wrap:anywhere}th{background:#e5ebf3}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:1rem;border:1px solid #cad3df}details{margin:1rem 0}summary{cursor:pointer;font-weight:600}.table-wrap{overflow:auto}</style>
</head><body><h1>XSS test report</h1>
<p>Confirmed execution requires an exact probe marker in an allowed frame at the expected origin. Reflected input alone is not confirmation. Counts of observations and unique vulnerabilities are separate.</p>
<h2>Summary and coverage</h2><pre>""" + _pretty(metadata) + """</pre>
<h2>Probe observations</h2><div class="table-wrap"><table><thead><tr><th>#</th><th>Case</th><th>Type</th><th>Payload</th><th>Status</th><th>URL</th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table></div>
<h2>Evidence and reproduction</h2>""" + "".join(details) + """</body></html>
"""


def write_reports(report: dict[str, Any], out: str | Path) -> tuple[Path, Path]:
    """Write <out>.json and <out>.html, accepting either suffix as a prefix hint."""
    prefix = Path(out)
    if prefix.exists() and prefix.is_dir():
        prefix = prefix / "xss-report"
    if prefix.suffix.lower() in {".json", ".html"}:
        prefix = prefix.with_suffix("")
    json_path = Path(str(prefix) + ".json")
    html_path = Path(str(prefix) + ".html")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    return json_path, html_path
