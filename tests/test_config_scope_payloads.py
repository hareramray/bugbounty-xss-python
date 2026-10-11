from __future__ import annotations

import json
import re

import pytest

from xss_suite.config import ConfigError, load_config, validate_config
from xss_suite.payloads import PAYLOADS, new_marker, select_payloads
from xss_suite.scope import Scope, ScopeError, origin


def minimal_config():
    return {
        "scope": ["http://127.0.0.1:8765/app"],
        "cases": [{"name": "reflected", "type": "query", "url": "http://127.0.0.1:8765/app/search"}],
    }


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8765/app",
    "http://127.0.0.1:8765/app/",
    "http://127.0.0.1:8765/app/child?q=anything#fragment",
    "http://127.0.0.1:8765/%61pp/child",
])
def test_scope_accepts_only_matching_complete_segments(url):
    assert Scope(["http://127.0.0.1:8765/app/"]).allows(url)


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:8765/app", "http://127.0.0.1:8766/app",
    "http://127.0.0.2:8765/app", "http://127.0.0.1:8765/application",
    "http://127.0.0.1:8765/APP", "http://127.0.0.1:8765/appish/child",
    "http://127.0.0.1:8765/app/../outside", "http://127.0.0.1:8765/app/./child",
    "http://127.0.0.1:8765/app/%2e%2e/outside", "http://127.0.0.1:8765/app/%2E./outside",
    "http://127.0.0.1:8765/app%2fchild", "http://127.0.0.1:8765/app/%5cchild",
    "http://127.0.0.1:8765/app/%252e%252e/outside", "http://127.0.0.1:8765/app//child",
    "http://127.0.0.1:8765/app/%00", "http://127.0.0.1:8765/app/%zz",
    "http://127.0.0.1:8765/app/%ff", "http://127.0.0.1:8765/app/\\evil",
    "http://user:password@127.0.0.1:8765/app", "http://127.0.0.1:8765.evil.test/app",
    "http://127.0.0.1.evil.test:8765/app", "http://127.0.0.1:8765@evil.test/app",
    "http://127.1:8765/app", "http://0177.0.0.1:8765/app", "http://0x7f000001:8765/app",
    "http://127.0.0.1.:8765/app", " http://127.0.0.1:8765/app",
    "http://127.0.0.1:8765/app\n", "http://127.0.0.1:8765/ap\tp",
    "http://127.0.0.1:/app", "http://127.0.0.1:0/app", "http://[invalid]/app",
    "http://127.0.0.1:99999/app", "//127.0.0.1:8765/app", "/app/child",
    "javascript:alert(1)", "data:text/html,anything", "file:///app", "about:blank",
    "http://127.0.0.1:8765/app #x", "http://127.0.0.1:8765\\@evil.test/app",
])
def test_scope_rejects_escape_and_browser_ambiguous_urls(url):
    scope = Scope(["http://127.0.0.1:8765/app"])
    assert not scope.allows(url)
    with pytest.raises(ScopeError):
        scope.require(url)


@pytest.mark.parametrize("prefixes", [
    [], None, "https://example.test", ["https://example.test/app?x=1"],
    ["https://example.test/app#x"], ["https://example.test/app?"],
    ["https://example.test/app#"], ["https://example.test/app/../outside"],
])
def test_invalid_scope_prefixes(prefixes):
    with pytest.raises(ScopeError):
        Scope(prefixes)


def test_canonical_origins_and_exact_origin_semantics():
    assert origin("HTTPS://EXAMPLE.test/path") == "https://example.test:443"
    assert origin("http://example.test") == "http://example.test:80"
    assert origin("https://[0:0:0:0:0:0:0:1]/") == "https://[::1]:443"
    assert origin("https://xn--bcher-kva.example/") == "https://xn--bcher-kva.example:443"
    scope = Scope(["https://example.test/"])
    assert scope.allows("https://EXAMPLE.test:443/any")
    assert not scope.allows("https://example.test.:443/any")
    assert not scope.allows("https://sub.example.test/any")
    assert not scope.allows("http://example.test:443/any")


@pytest.mark.parametrize("host", ["faß.example", "bücher.example", "ſcope.example", "ｅxample.test"])
def test_unicode_hosts_require_explicit_ascii_punycode(host):
    with pytest.raises(ScopeError, match="Unicode hosts"):
        Scope([f"https://{host}/"])
    with pytest.raises(ScopeError, match="Unicode hosts"):
        origin(f"https://{host}/")
    assert not Scope(["https://fass.example/"]).allows(f"https://{host}/")


def test_idna_mapping_cannot_widen_authorized_host():
    scope = Scope(["https://fass.example/"])
    assert scope.allows("https://fass.example/allowed")
    assert not scope.allows("https://faß.example/allowed")
    assert not scope.allows("https://xn--fa-hia.example/allowed")
    explicit = Scope(["https://xn--fa-hia.example/"])
    assert explicit.allows("https://xn--fa-hia.example/allowed")
    assert not explicit.allows("https://fass.example/allowed")
    assert not explicit.allows("https://faß.example/allowed")


def test_scope_error_never_echoes_auth_tokens():
    with pytest.raises(ScopeError) as caught:
        Scope(["https://example.test/"]).require("https://evil.test/?token=secret")
    assert "secret" not in str(caught.value)


def test_payloads_are_unique_harmless_and_render_markers():
    assert len(PAYLOADS) == 10
    assert len({p.id for p in PAYLOADS}) == 10
    markers = {new_marker() for _ in range(100)}
    assert len(markers) == 100
    assert all(re.fullmatch(r"xss_[0-9a-f]{32}", marker) for marker in markers)
    marker = new_marker()
    for payload in PAYLOADS:
        rendered = payload.render(marker)
        assert marker in rendered
        assert "globalThis.__xss_probe(" in rendered
        assert "{marker}" not in rendered
        assert "https://" not in rendered and "http://" not in rendered
        assert "document.cookie" not in rendered
    assert select_payloads(["html_svg", "html_svg", "js_single"]) == [PAYLOADS[0], PAYLOADS[4]]
    assert select_payloads() == list(PAYLOADS)


@pytest.mark.parametrize("selection", [[], ["nonexistent"], "html_svg", [1], {}])
def test_invalid_payload_selection(selection):
    with pytest.raises(ValueError):
        select_payloads(selection)


def test_marker_cannot_inject_its_own_javascript():
    with pytest.raises(ValueError):
        PAYLOADS[0].render("');alert(1);//")


def test_config_defaults_and_copy_independence():
    original = minimal_config()
    config = validate_config(original)
    assert config["limits"]["max_requests"] == 100
    assert config["limits"]["max_probes"] == 50
    assert config["limits"]["timeout_ms"] == 10000
    assert config["cases"][0]["parameter"] == "q"
    assert len(config["payloads"]) == 10
    config["cases"][0]["url"] = "changed"
    assert original["cases"][0]["url"].endswith("/app/search")
    assert "limits" not in original


def test_config_overrides_and_header_normalization():
    raw = minimal_config()
    raw.update(headers={"Authorization": "Bearer secret"}, payloads=["html_svg"], limits={"observation_ms": 20})
    raw["cases"][0].update(headers={"X-Api-Key": "another secret"}, payloads=["js_single"], timeout_ms=400)
    config = validate_config(raw)
    assert config["headers"] == {"authorization": "Bearer secret"}
    assert config["cases"][0]["headers"] == {"x-api-key": "another secret"}
    assert config["cases"][0]["payloads"] == ["js_single"]
    assert config["cases"][0]["timeout_ms"] == 400
    assert config["cases"][0]["observation_ms"] == 20


@pytest.mark.parametrize("field,value", [
    ("scope", []), ("scope", ["https://different.test/"]),
    ("cases", []), ("cases", {}), ("cases", [None]),
    ("headers", {"Host": "evil.test"}), ("headers", {"Cookie": "secret=1"}),
    ("headers", {"Origin": "https://evil.test"}), ("headers", {"Sec-Fetch-Site": "same-origin"}),
    ("headers", {"X-Test": "a\r\nInjected: true"}), ("headers", {"Bad Header": "x"}),
    ("headers", {"Authorization": "secret", "authorization": "another"}),
    ("headers", {"X-Test": 1}), ("payloads", ["unknown"]),
    ("limits", {"max_requests": -1}), ("limits", {"timeout_ms": 0}),
    ("limits", {"max_probes": True}), ("limits", {"typo": 1}), ("unknown", True),
])
def test_invalid_global_configuration(field, value):
    config = minimal_config()
    config[field] = value
    with pytest.raises(ConfigError):
        validate_config(config)


@pytest.mark.parametrize("field,value", [
    ("type", "unsupported"), ("type", []), ("name", ""), ("name", "bad\nname"),
    ("url", "http://127.0.0.1:8765/outside"), ("parameter", ""), ("property", 1),
    ("headers", []), ("data", []), ("data", {"q": float("nan")}),
    ("timeout_ms", -1), ("observation_ms", 1.5), ("payloads", []),
    ("submission_type", "form_post"), ("verification_urls", []), ("unknown", 1),
])
def test_invalid_case_configuration(field, value):
    config = minimal_config()
    config["cases"][0][field] = value
    with pytest.raises(ConfigError):
        validate_config(config)


def test_duplicate_case_names_rejected():
    config = minimal_config()
    config["cases"].append(dict(config["cases"][0]))
    with pytest.raises(ConfigError, match="unique"):
        validate_config(config)


def test_stored_requires_explicit_scoped_verification_pages():
    config = minimal_config()
    config["cases"][0]["type"] = "stored"
    with pytest.raises(ConfigError, match="verification_urls"):
        validate_config(config)
    config["cases"][0]["verification_urls"] = ["http://127.0.0.1:8765/outside"]
    with pytest.raises(ConfigError, match="Verification URL"):
        validate_config(config)
    config["cases"][0]["verification_urls"] = ["http://127.0.0.1:8765/app/view"]
    result = validate_config(config)["cases"][0]
    assert result["submission_type"] == "form_post"
    assert result["verification_urls"] == ["http://127.0.0.1:8765/app/view"]


def test_browser_forms_require_both_selectors():
    config = minimal_config()
    config["cases"][0]["type"] = "browser_form"
    with pytest.raises(ConfigError, match="field_selector"):
        validate_config(config)
    config["cases"][0]["field_selector"] = "[name=q]"
    with pytest.raises(ConfigError, match="submit_selector"):
        validate_config(config)
    config["cases"][0]["submit_selector"] = "button[type=submit]"
    assert validate_config(config)["cases"][0]["field_selector"] == "[name=q]"


def test_form_scalar_conversion_and_json_preservation():
    config = minimal_config()
    config["cases"][0].update(type="form_post", data={"count": 5, "flag": True})
    assert validate_config(config)["cases"][0]["data"] == {"count": "5", "flag": "True"}
    config["cases"][0]["data"] = {"nested": {"item": [1, None]}}
    with pytest.raises(ConfigError, match="scalar"):
        validate_config(config)
    config["cases"][0]["type"] = "json_post"
    assert validate_config(config)["cases"][0]["data"] == {"nested": {"item": [1, None]}}


def test_zero_budgets_are_deliberate_and_valid():
    config = minimal_config()
    config["limits"] = {"max_requests": 0, "max_probes": 0, "request_spacing_ms": 0, "max_redirects": 0}
    assert validate_config(config)["limits"]["max_requests"] == 0


def test_load_config_resolves_storage_state_relative_to_config(tmp_path):
    state = tmp_path / "auth.json"
    state.write_text('{"cookies": [], "origins": []}', encoding="utf-8")
    config = minimal_config()
    config["storage_state"] = "auth.json"
    config_path = tmp_path / "target.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    loaded = load_config(config_path)
    assert loaded["storage_state"] == str(state.resolve())


def test_config_missing_storage_state_rejected(tmp_path):
    config = minimal_config()
    config["storage_state"] = "missing.json"
    with pytest.raises(ConfigError, match="existing file"):
        validate_config(config, base_dir=tmp_path)


def test_load_config_rejects_invalid_json_and_duplicate_keys(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"scope": [], "scope": []}', encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(path)
    path.write_text('{"secret":"hidden",', encoding="utf-8")
    with pytest.raises(ConfigError, match="line") as caught:
        load_config(path)
    assert "hidden" not in str(caught.value)


def test_load_config_missing_file_is_readable_error(tmp_path):
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config(tmp_path / "missing.json")
