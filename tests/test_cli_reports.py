"""CLI/report tests do not contact remote hosts or need a browser."""

import json
import subprocess
import sys
from html.parser import HTMLParser

import pytest

from xss_suite import cli
from xss_suite.reports import render_html, write_reports


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "target.json"
    path.write_text(json.dumps({
        "scope": ["http://127.0.0.1:8765/"],
        "payloads": ["html_svg"],
        "cases": [{"name": "local", "type": "query", "url": "http://127.0.0.1:8765/reflect", "parameter": "q"}],
    }), encoding="utf-8")
    return path


def report_with(status="confirmed"):
    attack = "</pre><script>alert('oops')</script><img src=x onerror=alert(1)>"
    return {
        "counts": {"observations": {status: 1}, "unique_vulnerabilities": int(status == "confirmed")},
        "limitations": [attack],
        "results": [{"case": attack, "type": "query", "url": 'javascript:alert("url")',
                     "payload_id": "html_svg", "payload": attack, "marker": "abc",
                     "status": status, "execution": [{"origin": attack}],
                     "response_excerpts": [attack], "errors": [attack],
                     "blocked_requests": [attack], "reproduction": {attack: attack}}],
    }


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_html_escapes_all_report_content():
    document = render_html(report_with())
    parsed = Tags()
    parsed.feed(document)
    assert not any(tag in {"script", "img", "a", "iframe", "form"} for tag, _ in parsed.tags)
    assert not any(key.startswith("on") for _, attrs in parsed.tags for key in attrs)
    assert "&lt;script&gt;" in document
    csp = [attrs["content"] for tag, attrs in parsed.tags if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"]
    assert len(csp) == 1
    assert "default-src 'none'" in csp[0]
    assert "script-src 'none'" in csp[0]


def test_report_json_preserves_evidence_and_counts(tmp_path):
    report = report_with()
    json_path, html_path = write_reports(report, tmp_path / "nested" / "audit.json")
    assert json_path.name == "audit.json"
    assert html_path.name == "audit.html"
    assert json.loads(json_path.read_text(encoding="utf-8")) == report
    assert "unique_vulnerabilities" in html_path.read_text(encoding="utf-8")


def test_existing_directory_report_destination(tmp_path):
    paths = write_reports(report_with(), tmp_path)
    assert all(path.parent == tmp_path and path.is_file() for path in paths)


def test_validate_and_payloads(config_file, capsys):
    assert cli.main(["validate", "--config", str(config_file)]) == 0
    assert "Valid configuration" in capsys.readouterr().out
    assert cli.main(["payloads"]) == 0
    output = capsys.readouterr().out
    assert "html_svg" in output and "script_boundary" in output


def test_invalid_config_is_exit_2(tmp_path, capsys):
    invalid = tmp_path / "bad.json"
    invalid.write_text('{"scope": [], "cases": []}', encoding="utf-8")
    assert cli.main(["validate", "--config", str(invalid)]) == 2
    assert "Error:" in capsys.readouterr().err


def test_dry_run_never_scans(config_file, monkeypatch, capsys):
    async def forbidden(*_):
        pytest.fail("dry run must never run a scan")

    monkeypatch.setattr(cli, "_scan", forbidden)
    assert cli.main(["scan", "--config", str(config_file), "--dry-run"]) == 0
    planned = json.loads(capsys.readouterr().out)
    assert planned["planned_probes"] == 1
    assert planned["network_requests"] == 0
    assert planned["probes"][0]["payload_id"] == "html_svg"


@pytest.mark.parametrize("status,flag,expected", [("confirmed", False, 0), ("confirmed", True, 1), ("reflected", True, 0), ("inconclusive", False, 3), ("skipped", False, 0)])
def test_scan_flags_reports_and_exit_codes(config_file, tmp_path, monkeypatch, status, flag, expected):
    seen = {}

    async def fake_scan(config, args):
        seen.update(vars(args))
        return report_with(status)

    monkeypatch.setattr(cli, "_scan", fake_scan)
    argv = ["scan", "--config", str(config_file), "--out", str(tmp_path / "scan"), "--allow-writes", "--http-only", "--headed"]
    if flag:
        argv.append("--fail-on-confirmed")
    assert cli.main(argv) == expected
    assert seen["allow_writes"] and seen["http_only"] and seen["headed"]
    assert (tmp_path / "scan.json").is_file()
    assert (tmp_path / "scan.html").is_file()


def test_stopped_report_is_nonzero(config_file, tmp_path, monkeypatch):
    async def fake_scan(*_):
        return {"stopped": True, "results": [], "counts": {}, "limitations": ["HTTP 429"]}

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["scan", "--config", str(config_file), "--out", str(tmp_path / "stopped")]) == 3


def test_confirmation_exit_precedes_incomplete(config_file, tmp_path, monkeypatch):
    async def fake_scan(*_):
        result = report_with()
        result["incomplete"] = True
        return result

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["scan", "--config", str(config_file), "--out", str(tmp_path / "confirmed"), "--fail-on-confirmed"]) == 1


@pytest.mark.parametrize("raw_error", [
    "Timeout waiting for browser.\nCall log:\nAuthorization: secret-value\n",
    "page.goto https://127.0.0.1/?token=secret-value failed\nCall log:\nrequest details",
])
def test_sensitive_playwright_call_log_not_reported(config_file, monkeypatch, capsys, raw_error):
    async def fake_scan(*_):
        raise RuntimeError(raw_error)

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["scan", "--config", str(config_file)]) == 2
    error = capsys.readouterr().err
    assert "RuntimeError" in error
    assert "secret-value" not in error and "Call log" not in error


def test_module_entrypoint():
    result = subprocess.run([sys.executable, "-m", "xss_suite", "--help"], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "validate" in result.stdout and "demo" in result.stdout


def test_missing_required_cli_argument_is_exit_2():
    with pytest.raises(SystemExit) as error:
        cli.main(["scan"])
    assert error.value.code == 2


@pytest.mark.browser
def test_report_is_inert_in_real_chromium(tmp_path):
    from playwright.sync_api import Error, sync_playwright

    report = report_with()
    report["results"][0]["payload"] = "</pre><script>window.__reportExecuted=1</script>"
    _, path = write_reports(report, tmp_path / "hostile-report")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            dialogs = []
            page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.dismiss()))
            page.goto(path.resolve().as_uri())
            assert not dialogs
            assert page.locator("script, img, iframe").count() == 0
            assert page.evaluate("window.__reportExecuted || 0") == 0
            # A second defense: even accidental inline script insertion is blocked by CSP.
            with pytest.raises(Error):
                page.add_script_tag(content="window.__reportExecuted=1")
            assert page.evaluate("window.__reportExecuted || 0") == 0
        finally:
            browser.close()
