"""All network fixtures bind loopback and are torn down after each test."""

import pytest

from xss_suite.demo import serving


@pytest.fixture
def practice_server():
    with serving() as instance:
        yield instance


@pytest.fixture
def second_server():
    with serving() as instance:
        yield instance


@pytest.fixture
def local_config(practice_server):
    _, base = practice_server

    def build(cases, **updates):
        value = {
            "scope": [base + "/"],
            "payloads": ["html_svg"],
            "limits": {
                "request_spacing_ms": 0,
                "timeout_ms": 3000,
                "observation_ms": 160,
                "max_requests": 100,
                "max_probes": 30,
                "max_redirects": 5,
            },
            "cases": cases,
        }
        value.update(updates)
        return value

    return build
