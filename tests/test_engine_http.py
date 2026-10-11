"""HTTP transport edge cases using only loopback fixtures and real responses."""

import asyncio
import json
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from xss_suite.engine import scan


def run_http(config, **kwargs):
    return asyncio.run(scan(config, http_only=True, **kwargs))


def case(base, name="test", path="/reflect", **updates):
    result = {"name": name, "type": "query", "url": base + path}
    result.update(updates)
    return result


def header(event, name):
    return {key.lower(): value for key, value in event["headers"].items()}.get(name.lower())


@pytest.mark.parametrize("maximum", [0, 1, 2])
def test_hard_probe_budget_including_zero(practice_server, local_config, maximum):
    server, base = practice_server
    config = local_config([case(base, name=f"probe-{index}") for index in range(3)])
    config["limits"]["max_probes"] = maximum
    report = run_http(config)
    assert len(server.events) == maximum
    assert report["counts"]["requests"] == maximum
    assert report["counts"]["probes_started"] == maximum
    assert report["counts"]["probe_observations"] == 3
    assert report["counts"]["skipped"] == 3 - maximum
    assert report["stopped"] and report["incomplete"]
    assert "probe budget" in report["stop_reason"]


def test_http_429_stops_all_remaining_payloads_and_cases(practice_server, local_config):
    server, base = practice_server
    config = local_config([
        case(base, name="rate-limited", path="/rate-limit", payloads=["html_svg", "html_img"]),
        case(base, name="must-not-run"),
    ])
    report = run_http(config)
    assert len(server.events) == report["counts"]["requests"] == 1
    assert urlsplit(server.events[0]["path"]).path == "/rate-limit"
    assert [result["status"] for result in report["results"]] == ["inconclusive", "skipped", "skipped"]
    assert "429" in report["stop_reason"]
    assert all("429" in result["skip_reason"] for result in report["results"][1:])


@pytest.mark.parametrize("maximum,expected_requests", [(0, 1), (1, 2), (2, 3)])
def test_http_redirect_hop_budget_and_exact_allowed_chain(practice_server, local_config, maximum, expected_requests):
    server, base = practice_server
    second = "/redirect?to=" + quote("/safe/json", safe="")
    first = "/redirect?to=" + quote(second, safe="")
    config = local_config([case(base, path=first)])
    config["limits"]["max_redirects"] = maximum
    report = run_http(config)
    result = report["results"][0]
    assert len(server.events) == report["counts"]["requests"] == expected_requests
    assert [urlsplit(event["path"]).path for event in server.events] == ["/redirect", "/redirect", "/safe/json"][:expected_requests]
    if maximum < 2:
        assert result["status"] == "inconclusive"
        assert any("hop limit" in blocked["reason"] for blocked in result["blocked_requests"])
    else:
        assert result["status"] == "not_observed"
        assert not result["blocked_requests"]


def test_request_budget_applies_to_each_http_redirect_hop(practice_server, local_config):
    server, base = practice_server
    config = local_config([case(base, path="/redirect"), case(base, name="later")])
    config["limits"]["max_requests"] = 1
    report = run_http(config)
    assert len(server.events) == report["counts"]["requests"] == 1
    assert [result["status"] for result in report["results"]] == ["inconclusive", "skipped"]
    assert "request budget" in report["stop_reason"]
    assert not any(urlsplit(event["path"]).path == "/reflect" for event in server.events)


def test_zero_request_budget_sends_nothing(practice_server, local_config):
    server, base = practice_server
    config = local_config([case(base)])
    config["limits"]["max_requests"] = 0
    report = run_http(config)
    assert not server.events
    assert report["counts"]["requests"] == 0
    assert report["results"][0]["status"] == "inconclusive"
    assert "request budget" in report["stop_reason"]


def test_case_auth_headers_override_global_values_without_duplicate_names(practice_server, local_config):
    server, base = practice_server
    config = local_config([case(base, headers={"authorization": "Bearer case-secret", "x-api-key": "case-key"})],
                          headers={"Authorization": "Bearer global-secret", "X-Api-Key": "global-key", "X-Account": "retained"})
    report = run_http(config)
    assert report["results"][0]["status"] == "reflected"
    assert len(server.events) == 1
    event = server.events[0]
    assert header(event, "Authorization") == "Bearer case-secret"
    assert header(event, "X-Api-Key") == "case-key"
    assert header(event, "X-Account") == "retained"
    serialized = json.dumps(report)
    assert "global-secret" not in serialized and "case-secret" not in serialized
    assert "global-key" not in serialized and "case-key" not in serialized


def test_auth_headers_are_removed_on_other_origin_and_restored_on_return(practice_server, second_server, local_config):
    server, base = practice_server
    other, secondary = second_server
    second_url = secondary + "/redirect?to=" + quote(base + "/safe/json", safe="")
    first = "/redirect?to=" + quote(second_url, safe="")
    config = local_config([case(base, path=first)], scope=[base + "/", secondary + "/"],
                          headers={"Authorization": "Bearer fixture-secret", "X-Custom-Auth": "custom-secret"})
    report = run_http(config)
    assert report["counts"]["requests"] == 3
    assert len(server.events) == 2 and len(other.events) == 1
    assert all(header(event, "Authorization") == "Bearer fixture-secret" for event in server.events)
    assert all(header(event, "X-Custom-Auth") == "custom-secret" for event in server.events)
    assert header(other.events[0], "Authorization") is None
    assert header(other.events[0], "X-Custom-Auth") is None


def test_http_probe_contexts_do_not_share_new_session_cookies(practice_server, local_config):
    server, base = practice_server
    report = run_http(local_config([case(base, name="first", path="/cookie"), case(base, name="second", path="/cookie")]))
    assert len(server.events) == 2
    assert all(not header(event, "Cookie") for event in server.events)
    assert all(result["status"] == "reflected" for result in report["results"])
    assert len({result["marker"] for result in report["results"]}) == 2


@pytest.mark.parametrize("type_,path", [("form_post", "/form"), ("json_post", "/json"), ("stored", "/stored")])
def test_explicit_http_writes_require_allow_writes(practice_server, local_config, type_, path):
    server, base = practice_server
    updates = {"verification_urls": [base + "/stored/view"]} if type_ == "stored" else {}
    config = local_config([case(base, type=type_, path=path, **updates)])
    report = run_http(config)
    assert report["results"][0]["status"] == "skipped"
    assert "allow-writes" in report["results"][0]["skip_reason"]
    assert report["counts"]["requests"] == 0
    assert not server.events


def test_http_stored_workflow_shares_cookie_only_with_its_verification(practice_server, local_config):
    server, base = practice_server
    report = run_http(local_config([case(base, type="stored", path="/stored", verification_urls=[base + "/stored/view"])]),
                      allow_writes=True)
    result = report["results"][0]
    assert result["status"] == "reflected" and not result["execution"]
    assert len(server.events) == 2
    assert [event["method"] for event in server.events] == ["POST", "GET"]
    assert not header(server.events[0], "Cookie")
    assert "xss_demo_session=" in header(server.events[1], "Cookie")
    assert any(item["url"].endswith("/stored/view") and item["marker_present"] for item in result["response_excerpts"])


@pytest.mark.parametrize("type_", ["query", "json_post"])
def test_json_responses_are_reflection_evidence_and_never_execution(practice_server, local_config, type_):
    server, base = practice_server
    config = local_config([case(base, type=type_, path="/safe/json")])
    report = run_http(config, allow_writes=True)
    result = report["results"][0]
    assert result["status"] == "reflected"
    assert not result["execution"]
    assert report["counts"]["unique_vulnerabilities"] == 0
    assert len(result["response_excerpts"]) == 1
    excerpt = result["response_excerpts"][0]
    assert excerpt["content_type"].startswith("application/json")
    assert result["marker"] in json.loads(excerpt["text"])["q"]
    assert len(server.events) == 1


def test_query_replacement_preserves_other_parameters_and_removes_duplicate_selected_keys(practice_server, local_config):
    server, base = practice_server
    report = run_http(local_config([case(base, path="/safe/json?q=old&q=duplicate&kept=one&kept=two&empty=")]))
    query = parse_qs(urlsplit(server.events[0]["path"]).query, keep_blank_values=True)
    assert query["q"] == [report["results"][0]["payload"]]
    assert query["kept"] == ["one", "two"]
    assert query["empty"] == [""]
