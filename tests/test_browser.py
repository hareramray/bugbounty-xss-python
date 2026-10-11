"""Real Chromium verification against the local fixture only.

Install the pinned project requirements and run ``playwright install chromium``
before executing these tests. Missing browser binaries are a setup failure.
"""

import asyncio
import json
from urllib.parse import quote

import pytest

from xss_suite.config import validate_config
from xss_suite.engine import scan


pytestmark = pytest.mark.browser


def run_scan(config, **kwargs):
    return asyncio.run(scan(validate_config(config), **kwargs))


def case(base, path="/reflect", **kwargs):
    result = {"name": "test", "type": "query", "url": base + path, "parameter": "q"}
    result.update(kwargs)
    return result


def header(event, name):
    return {key.lower(): value for key, value in event["headers"].items()}.get(name.lower(), "")


@pytest.mark.parametrize("path,payload", [
    ("/reflect", "html_svg"),
    ("/reflect", "html_img"),
    ("/attribute", "attribute_double"),
    ("/attribute-single", "attribute_single"),
    ("/javascript", "js_single"),
    ("/javascript-double", "js_double"),
    ("/template", "template_literal"),
    ("/textarea", "textarea_boundary"),
    ("/title", "title_boundary"),
    ("/javascript", "script_boundary"),
])
def test_payload_executes_only_with_matching_marker(practice_server, local_config, path, payload):
    _, base = practice_server
    report = run_scan(local_config([case(base, path, payloads=[payload])]))
    result = report["results"][0]
    assert result["status"] == "confirmed", result
    assert result["execution"], result
    assert result["marker"].startswith("xss_")
    assert result["marker"] in result["payload"]


@pytest.mark.parametrize("path,type_", [
    ("/safe/escaped", "query"),
    ("/safe/text", "fragment"),
    ("/safe/json", "query"),
    ("/safe/csp", "query"),
])
def test_safe_controls_never_confirm(practice_server, local_config, path, type_):
    _, base = practice_server
    report = run_scan(local_config([case(base, path, type=type_)]))
    result = report["results"][0]
    assert result["status"] in {"reflected", "not_observed"}, result
    assert not result["execution"], result


def test_fragment_execution(practice_server, local_config):
    _, base = practice_server
    result = run_scan(local_config([case(base, "/dom", type="fragment")]))["results"][0]
    assert result["status"] == "confirmed", result


def test_nonmatching_execution_marker_does_not_confirm(practice_server, local_config):
    _, base = practice_server
    result = run_scan(local_config([case(base, "/wrong-marker")]))["results"][0]
    assert result["status"] != "confirmed", result
    assert not result["execution"]


def test_history_navigation_outside_path_scope_rejects_execution(practice_server, local_config):
    _, base = practice_server
    config = local_config([case(base, "/app/history")], scope=[base + "/app"])
    result = run_scan(config)["results"][0]
    assert result["status"] != "confirmed", result
    assert not result["execution"], result
    assert any(item["marker"] == result["marker"] and item["url"] == base + "/outside"
               for item in result["rejected_executions"]), result


@pytest.mark.parametrize("type_,path,extras", [
    ("form_post", "/form", {"data": {"other": "preserved"}}),
    ("json_post", "/json", {"property": "q", "data": {"q": "", "other": 7}}),
    ("browser_form", "/form", {"field_selector": "#q", "submit_selector": "#send"}),
])
def test_explicit_writes_require_opt_in_and_work(practice_server, local_config, type_, path, extras):
    server, base = practice_server
    config = local_config([case(base, path, type=type_, **extras)])
    skipped = run_scan(config)["results"][0]
    assert skipped["status"] == "skipped"
    assert not server.events
    result = run_scan(config, allow_writes=True)["results"][0]
    assert result["status"] == "confirmed", result
    submissions = [event for event in server.events if event["method"] == "POST"]
    assert submissions
    if type_ == "json_post":
        submitted = json.loads(submissions[-1]["body"])
        assert submitted["other"] == 7
        assert result["marker"] in submitted["q"]


@pytest.mark.parametrize("submission_type,extras", [
    ("form_post", {}),
    ("json_post", {"property": "q", "data": {"q": ""}}),
    ("browser_form", {"field_selector": "#q", "submit_selector": "#send"}),
])
def test_stored_confirmation_is_on_verification_page_with_shared_cookie(practice_server, local_config, submission_type, extras):
    server, base = practice_server
    config = local_config([case(base, "/stored", type="stored", submission_type=submission_type,
                                verification_urls=[base + "/stored/view"], **extras)])
    result = run_scan(config, allow_writes=True)["results"][0]
    assert result["status"] == "confirmed", result
    assert all("/stored/view" in item["url"] for item in result["execution"])
    requests = [event for event in server.events if event["path"].startswith("/stored/view")]
    assert requests and "xss_demo_session=" in header(requests[-1], "Cookie")


def test_delayed_submission_execution_is_not_stored_confirmation(practice_server, local_config):
    _, base = practice_server
    config = local_config([case(base, "/stored/delayed", type="stored", submission_type="form_post",
                                verification_urls=[base + "/stored/clean"], observation_ms=300)])
    result = run_scan(config, allow_writes=True)["results"][0]
    assert result["status"] != "confirmed", result
    assert not result["execution"], result


def test_fresh_context_per_probe_does_not_share_new_cookies(practice_server, local_config):
    server, base = practice_server
    cases = [case(base, "/cookie", name="first"), case(base, "/cookie", name="second")]
    report = run_scan(local_config(cases))
    assert len(report["results"]) == 2
    assert all(item["status"] == "confirmed" for item in report["results"]), report
    requests = [event for event in server.events if event["path"].startswith("/cookie?")]
    assert len(requests) == 2
    assert all("xss_demo_session=" not in header(event, "Cookie") for event in requests)
    assert len({item["marker"] for item in report["results"]}) == 2
    assert report["counts"]["confirmed"] == 2
    assert report["counts"]["unique_vulnerabilities"] == 1


def test_authentication_storage_state_cookie_is_loaded_per_context(practice_server, local_config, tmp_path):
    server, base = practice_server
    state = tmp_path / "auth.json"
    state.write_text(json.dumps({"cookies": [{"name": "auth_fixture", "value": "secret-fixture",
        "domain": "127.0.0.1", "path": "/", "expires": -1, "httpOnly": True,
        "secure": False, "sameSite": "Lax"}], "origins": []}), encoding="utf-8")
    run_scan(local_config([case(base)], storage_state=str(state)))
    assert "auth_fixture=secret-fixture" in header(server.events[0], "Cookie")


@pytest.mark.parametrize("path", ["/sandbox", "/sandbox-url", "/sandbox-csp"])
def test_opaque_sandbox_frame_is_not_first_party_confirmation(practice_server, local_config, path):
    _, base = practice_server
    result = run_scan(local_config([case(base, path)]))["results"][0]
    assert result["status"] != "confirmed", result
    assert not result["execution"], result
    assert any(item["marker"] == result["marker"] for item in result["rejected_executions"]), result


def test_allowed_same_origin_frame_can_confirm(practice_server, local_config):
    _, base = practice_server
    result = run_scan(local_config([case(base, "/frame")]))["results"][0]
    assert result["status"] == "confirmed", result
    assert all(item["origin"] == base for item in result["execution"])


def test_browser_redirect_is_blocked_even_in_scope(practice_server, local_config):
    server, base = practice_server
    result = run_scan(local_config([case(base, "/redirect")]))["results"][0]
    assert result["status"] == "inconclusive", result
    assert not any(event["path"].startswith("/reflect") for event in server.events)
    assert result["blocked_requests"], result


def test_out_of_scope_subframe_and_cross_origin_header_leak_are_blocked(practice_server, second_server, local_config):
    _, base = practice_server
    outside, external = second_server
    target = base + "/frame?target=" + quote(external + "/reflect", safe="")
    config = local_config([case(base, url=target)], headers={"Authorization": "Bearer fixture", "X-Fixture-Secret": "private"})
    result = run_scan(config)["results"][0]
    assert result["status"] != "confirmed", result
    assert result["blocked_requests"], result
    assert outside.events == []


def test_custom_auth_headers_do_not_cross_allowed_origins(practice_server, second_server, local_config):
    _, base = practice_server
    other, external = second_server
    target = base + "/frame?target=" + quote(external + "/safe/escaped", safe="")
    config = local_config([case(base, url=target)], scope=[base + "/", external + "/"],
                          headers={"Authorization": "Bearer fixture", "X-Fixture-Secret": "private"})
    run_scan(config)
    assert other.events
    assert all(not header(event, "Authorization") and not header(event, "X-Fixture-Secret")
               for event in other.events)


def test_allowed_but_different_effective_origin_does_not_confirm(practice_server, second_server, local_config):
    _, base = practice_server
    _, external = second_server
    target = base + "/frame?inject=1&target=" + quote(external + "/reflect", safe="")
    config = local_config([case(base, url=target)], scope=[base + "/", external + "/"])
    result = run_scan(config)["results"][0]
    assert result["status"] != "confirmed", result
    assert not result["execution"], result


def test_http_only_reflection_never_confirms(practice_server, local_config):
    _, base = practice_server
    result = run_scan(local_config([case(base)]), http_only=True)["results"][0]
    assert result["status"] == "reflected", result
    assert not result["execution"]


def test_probe_budget_is_hard(practice_server, local_config):
    server, base = practice_server
    config = local_config([case(base, name="first"), case(base, name="second")])
    config["limits"]["max_probes"] = 1
    report = run_scan(config, http_only=True)
    assert len(server.events) == 1
    assert report["counts"]["probes_started"] == 1
    assert report["results"][1]["status"] == "skipped"


def test_per_case_headers_override_globals(practice_server, local_config):
    server, base = practice_server
    config = local_config([case(base, headers={"X-Shared": "case", "X-Case": "yes"})],
                          headers={"X-Shared": "global", "X-Global": "yes"})
    run_scan(config, http_only=True)
    assert header(server.events[0], "X-Shared") == "case"
    assert header(server.events[0], "X-Global") == "yes"
    assert header(server.events[0], "X-Case") == "yes"


def test_http_only_redirects_validate_each_hop(practice_server, second_server, local_config):
    _, base = practice_server
    outside, external = second_server
    target = base + "/redirect?to=" + quote(external + "/reflect", safe="")
    result = run_scan(local_config([case(base, url=target)]), http_only=True)["results"][0]
    assert result["status"] == "inconclusive", result
    assert result["blocked_requests"]
    assert outside.events == []


def test_http_only_in_scope_redirect_preserves_original_header_policy(practice_server, second_server, local_config):
    _, base = practice_server
    other, external = second_server
    target = base + "/redirect?to=" + quote(external + "/safe/json", safe="")
    config = local_config([case(base, url=target)], scope=[base + "/", external + "/"],
                          headers={"Authorization": "Bearer fixture", "X-Fixture-Secret": "private"})
    run_scan(config, http_only=True)
    assert other.events
    assert all(not header(event, "Authorization") and not header(event, "X-Fixture-Secret")
               for event in other.events)


def test_429_stops_future_probes(practice_server, local_config):
    server, base = practice_server
    report = run_scan(local_config([case(base, "/rate-limit", name="rate"), case(base, name="after")]))
    assert all(item["status"] != "confirmed" for item in report["results"])
    assert not any(event["path"].startswith("/reflect") for event in server.events)


def test_request_budget_is_hard_even_for_browser_subresources(practice_server, local_config):
    server, base = practice_server
    config = local_config([case(base, "/resources")])
    config["limits"].update(max_requests=3, request_spacing_ms=20, observation_ms=1000)
    report = run_scan(config)
    assert len(server.events) <= 3
    assert report["results"][0]["blocked_requests"], report


def test_websockets_and_service_workers_cannot_issue_network_requests(practice_server, local_config):
    server, base = practice_server
    run_scan(local_config([case(base, "/websocket", name="ws"), case(base, "/worker", name="sw")]))
    assert not any(event["path"].startswith(("/ws", "/sw.js")) for event in server.events)


def test_closing_probe_cancels_queued_subresources(practice_server, local_config):
    server, base = practice_server
    config = local_config([case(base, "/resources", name="queued"), case(base, name="next")])
    config["limits"].update(request_spacing_ms=100, observation_ms=40)
    report = run_scan(config)
    assert len(report["results"]) == 2
    next_index = next(index for index, event in enumerate(server.events) if event["path"].startswith("/reflect?"))
    assert not any(event["path"].startswith("/pixel") for event in server.events[next_index:])
    assert sum(event["path"].startswith("/pixel") for event in server.events) < 20


def test_demo_refuses_public_bind_addresses():
    from xss_suite.demo import make_server
    for host in ("0.0.0.0", "::", "192.0.2.1", "example.com"):
        with pytest.raises(ValueError, match="loopback"):
            make_server(host=host)
