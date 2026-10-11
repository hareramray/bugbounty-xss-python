"""Strict JSON configuration loading, with safe defaults and early validation."""

from __future__ import annotations

import copy
import json
import math
import re
from pathlib import Path
from typing import Any

from .payloads import select_payloads
from .scope import Scope, ScopeError


class ConfigError(ValueError):
    """Configuration failed validation before any target request was made."""


DEFAULT_LIMITS = {
    "request_spacing_ms": 100,
    "timeout_ms": 10000,
    "observation_ms": 500,
    "max_requests": 100,
    "max_probes": 50,
    "max_redirects": 5,
}

_ROOT_KEYS = {"scope", "cases", "payloads", "headers", "storage_state", "limits"}
_CASE_KEYS = {
    "name", "type", "url", "parameter", "property", "data", "field_selector",
    "submit_selector", "verification_urls", "submission_type", "headers", "payloads",
    "timeout_ms", "observation_ms",
}
_TYPES = {"query", "fragment", "form_post", "json_post", "browser_form", "stored"}
_SUBMISSION_TYPES = {"form_post", "json_post", "browser_form"}
_FORBIDDEN_HEADERS = {
    "host", "cookie", "set-cookie", "origin", "referer", "connection", "content-length",
    "transfer-encoding", "proxy-authorization", "proxy-authenticate", "proxy-connection",
    "keep-alive", "te", "trailer", "upgrade", "accept-encoding",
}


def _keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    if any(key not in allowed for key in value):
        raise ConfigError(f"{label} contains unknown keys")


def _integer(value: Any, name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{name} must be an integer greater than or equal to {minimum}")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigError(f"{name} must be a nonempty string without control characters")
    return value


def _headers(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be an object of header strings")
    result: dict[str, str] = {}
    for name, header_value in value.items():
        if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ConfigError(f"{label} contains an invalid header name")
        lower = name.lower()
        if lower in _FORBIDDEN_HEADERS or lower.startswith("sec-"):
            raise ConfigError(f"{label} contains a transport-controlled header; use storage_state for cookies")
        if lower in result:
            raise ConfigError(f"{label} contains duplicate case-insensitive header names")
        if not isinstance(header_value, str) or any(ord(c) < 32 or ord(c) == 127 for c in header_value):
            raise ConfigError(f"{label} values must be strings without control characters")
        result[lower] = header_value
    return result


def _payload_ids(value: Any) -> list[str]:
    try:
        return [payload.id for payload in select_payloads(value)]
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc


def _json_data(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ConfigError("case.data must be an object with string keys")
    try:
        # Also reject NaN/Infinity and non-JSON objects supplied programmatically.
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ConfigError("case.data must contain JSON-compatible finite values") from exc
    return copy.deepcopy(value)


def validate_config(data: Any, base_dir: str | Path | None = None) -> dict[str, Any]:
    """Return a normalized independent configuration without sending requests."""
    if not isinstance(data, dict):
        raise ConfigError("Configuration must be a JSON object")
    _keys(data, _ROOT_KEYS, "Configuration")
    try:
        scope = Scope(data.get("scope"))
    except (ScopeError, TypeError) as exc:
        raise ConfigError(str(exc)) from exc
    limits_input = data.get("limits", {})
    if not isinstance(limits_input, dict):
        raise ConfigError("limits must be an object")
    _keys(limits_input, set(DEFAULT_LIMITS), "limits")
    limits = {
        key: _integer(limits_input.get(key, default), f"limits.{key}", 1 if key == "timeout_ms" else 0)
        for key, default in DEFAULT_LIMITS.items()
    }
    payload_ids = _payload_ids(data.get("payloads"))
    result: dict[str, Any] = {
        "scope": list(scope.prefixes),
        "headers": _headers(data.get("headers", {}), "headers"),
        "payloads": payload_ids,
        "limits": limits,
        "storage_state": None,
        "cases": [],
    }
    storage_state = data.get("storage_state")
    if storage_state is not None:
        storage_state = _text(storage_state, "storage_state")
        storage_path = Path(storage_state).expanduser()
        if not storage_path.is_absolute():
            storage_path = Path(base_dir or Path.cwd()) / storage_path
        storage_path = storage_path.resolve()
        if not storage_path.is_file():
            raise ConfigError("storage_state must reference an existing file")
        result["storage_state"] = str(storage_path)
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ConfigError("cases must be a nonempty list")
    names: set[str] = set()
    for item in cases:
        if not isinstance(item, dict):
            raise ConfigError("Each case must be an object")
        _keys(item, _CASE_KEYS, "Case")
        name = _text(item.get("name"), "case.name")
        if name in names:
            raise ConfigError("Case names must be unique")
        names.add(name)
        case_type = item.get("type")
        if not isinstance(case_type, str) or case_type not in _TYPES:
            raise ConfigError("case.type must be query, fragment, form_post, json_post, browser_form, or stored")
        url = _text(item.get("url"), "case.url")
        try:
            scope.require(url)
        except ScopeError as exc:
            raise ConfigError("Case URL is invalid or outside scope") from exc
        case: dict[str, Any] = {
            "name": name,
            "type": case_type,
            "url": url,
            "parameter": _text(item.get("parameter", "q"), "case.parameter"),
            "property": _text(item.get("property", "q"), "case.property"),
            "data": _json_data(item.get("data", {})),
            "headers": _headers(item.get("headers", {}), "case.headers"),
            "payloads": _payload_ids(item.get("payloads", payload_ids)),
            "timeout_ms": _integer(item.get("timeout_ms", limits["timeout_ms"]), "case.timeout_ms", 1),
            "observation_ms": _integer(item.get("observation_ms", limits["observation_ms"]), "case.observation_ms"),
        }
        effective_type = case_type
        if case_type == "stored":
            submission_type = item.get("submission_type", "form_post")
            if not isinstance(submission_type, str) or submission_type not in _SUBMISSION_TYPES:
                raise ConfigError("stored submission_type must be form_post, json_post, or browser_form")
            case["submission_type"] = effective_type = submission_type
            verification_urls = item.get("verification_urls")
            if not isinstance(verification_urls, list) or not verification_urls:
                raise ConfigError("Stored cases require a nonempty verification_urls list")
            case["verification_urls"] = []
            for verification_url in verification_urls:
                _text(verification_url, "verification URL")
                try:
                    scope.require(verification_url)
                except ScopeError as exc:
                    raise ConfigError("Verification URL is invalid or outside scope") from exc
                if verification_url not in case["verification_urls"]:
                    case["verification_urls"].append(verification_url)
        elif "submission_type" in item or "verification_urls" in item:
            raise ConfigError("submission_type and verification_urls apply only to stored cases")
        if effective_type == "browser_form":
            case["field_selector"] = _text(item.get("field_selector"), "case.field_selector")
            case["submit_selector"] = _text(item.get("submit_selector"), "case.submit_selector")
        elif "field_selector" in item or "submit_selector" in item:
            raise ConfigError("Form selectors apply only to browser_form submissions")
        if effective_type in {"form_post", "browser_form"}:
            for field, value in case["data"].items():
                if value is None or isinstance(value, (dict, list)):
                    raise ConfigError("Form data values must be scalar strings, numbers, or booleans")
                if isinstance(value, float) and not math.isfinite(value):
                    raise ConfigError("Form data values must be finite")
                case["data"][field] = str(value)
        result["cases"].append(case)
    return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ConfigError("JSON objects must not contain duplicate keys")
        obj[key] = value
    return obj


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError) as exc:
        raise ConfigError("Cannot read configuration file") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON configuration at line {exc.lineno}, column {exc.colno}") from exc
    return validate_config(raw, base_dir=config_path.parent)


parse_config = validate_config
