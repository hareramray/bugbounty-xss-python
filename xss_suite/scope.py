"""Conservative, segment-aware URL scope checks shared by HTTP and browser traffic."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


class ScopeError(ValueError):
    """A URL is invalid, ambiguous, or outside the configured authorization scope."""


@dataclass(frozen=True)
class _URL:
    origin: str
    path: str
    query: str
    fragment: str


def _parse(url: str) -> _URL:
    if not isinstance(url, str) or not url or url != url.strip():
        raise ScopeError("URL must be a nonempty string without surrounding whitespace")
    if any(ord(char) < 33 or ord(char) == 127 for char in url) or "\\" in url:
        raise ScopeError("URL contains whitespace, control characters, or backslashes")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ScopeError("Only absolute HTTP and HTTPS URLs are allowed")
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise ScopeError("URL credentials are not allowed; use storage state or headers")
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ScopeError("Malformed URL authority") from exc
    if not host or "%" in host:
        raise ScopeError("URL requires an unambiguous host")
    if not host.isascii():
        # Python's built-in IDNA2003 mapping differs from Chromium's UTS #46
        # mapping (notably faß.example versus fass.example). Require the caller
        # to select an explicit ASCII/punycode authority before authorization.
        raise ScopeError("Unicode hosts are not accepted; use an explicit ASCII punycode hostname")
    if parsed.netloc.endswith(":"):
        raise ScopeError("An explicit port must contain a number")
    try:
        if ":" in host:
            canonical_host = "[" + ipaddress.IPv6Address(host).compressed + "]"
        else:
            canonical_host = host.lower()
            # WHATWG browsers reinterpret legacy numeric IPv4 spellings (127.1,
            # 0177.0.0.1, 0x7f000001). Never accept a different browser authority.
            last_label = canonical_host.rstrip(".").split(".")[-1]
            if re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", last_label):
                if str(ipaddress.IPv4Address(canonical_host)) != canonical_host:
                    raise ValueError("Noncanonical numeric host")
            elif not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.?", canonical_host):
                raise ValueError("Invalid hostname")
            if ".." in canonical_host:
                raise ValueError("Empty hostname label")
    except (ValueError, UnicodeError) as exc:
        raise ScopeError("URL host is malformed or browser-ambiguous") from exc
    effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    if not 1 <= effective_port <= 65535:
        raise ScopeError("URL port must be between 1 and 65535")
    path = parsed.path or "/"
    if re.search(r"%(?![0-9a-fA-F]{2})", path):
        raise ScopeError("Malformed percent encoding in URL path")
    if re.search(r"%(?:2f|5c)", path, re.IGNORECASE):
        raise ScopeError("Encoded path separators are not allowed")
    try:
        decoded = unquote(path, encoding="utf-8", errors="strict")
    except UnicodeError as exc:
        raise ScopeError("URL path is not valid UTF-8") from exc
    if "%" in decoded or "\\" in decoded or "//" in decoded:
        raise ScopeError("Ambiguous or double-encoded URL path")
    if any(ord(char) < 32 or ord(char) == 127 for char in decoded):
        raise ScopeError("URL path contains encoded control characters")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ScopeError("URL path traversal or normalization segments are not allowed")
    return _URL(f"{parsed.scheme}://{canonical_host}:{effective_port}", decoded, parsed.query, parsed.fragment)


def origin(url: str) -> str:
    """Return the canonical HTTP(S) origin, including its effective port."""
    return _parse(url).origin


class Scope:
    """Match exact origins and complete path segments, never string lookalikes."""

    def __init__(self, prefixes: list[str] | tuple[str, ...]):
        if not isinstance(prefixes, (list, tuple)) or not prefixes:
            raise ScopeError("At least one explicit scope URL prefix is required")
        parsed_prefixes: list[_URL] = []
        for prefix in prefixes:
            parsed = _parse(prefix)
            if parsed.query or parsed.fragment or "?" in prefix or "#" in prefix:
                raise ScopeError("Scope prefixes must not contain a query or fragment")
            parsed_prefixes.append(parsed)
        self.prefixes = tuple(prefixes)
        self._prefixes = tuple(parsed_prefixes)

    def allows(self, url: str) -> bool:
        try:
            candidate = _parse(url)
        except ScopeError:
            return False
        for prefix in self._prefixes:
            base = prefix.path.rstrip("/")
            if candidate.origin == prefix.origin and (
                not base or candidate.path == base or candidate.path.startswith(base + "/")
            ):
                return True
        return False

    def require(self, url: str) -> None:
        if not self.allows(url):
            # Deliberately do not echo URLs: query parameters can contain secrets.
            raise ScopeError("Request URL is invalid or outside the explicit scope")
