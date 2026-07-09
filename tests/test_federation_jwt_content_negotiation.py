"""Tests for profile-backed HTTP Accept negotiation helpers."""

import importlib
import inspect

import pytest

from fedservice.federation_jwt import content_negotiation
from fedservice.federation_jwt.content_negotiation import accepts_profile_response
from fedservice.federation_jwt.content_negotiation import require_acceptable_response
from fedservice.federation_jwt.errors import FederationJwtContentNegotiationError
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE


def accepts(accept_header, allow_application_wildcard=False):
    return accepts_profile_response(
        accept_header=accept_header,
        profile=RESOLVE_RESPONSE,
        allow_application_wildcard=allow_application_wildcard,
    )


@pytest.mark.parametrize("accept_header", [None, "", "   "])
def test_accepts_absent_or_blank_accept_header(accept_header):
    assert accepts(accept_header) is True


@pytest.mark.parametrize("accept_header", ["*/*", "text/plain;q=0.2, */*;q=0.5"])
def test_accepts_any_media_range(accept_header):
    assert accepts(accept_header) is True


@pytest.mark.parametrize(
    "accept_header",
    [
        "application/resolve-response+jwt",
        " Application/Resolve-Response+Jwt ",
        "application/resolve-response+jwt; charset=utf-8",
        "application/json;q=0.1, application/resolve-response+jwt;q=0.5",
    ],
)
def test_accepts_exact_profile_content_type(accept_header):
    assert accepts(accept_header) is True


def test_rejects_q_zero_unless_another_member_is_acceptable():
    assert accepts("application/resolve-response+jwt;q=0") is False
    assert accepts("application/resolve-response+jwt;q=0, */*;q=0.1") is True


@pytest.mark.parametrize(
    "accept_header",
    [
        "application/json",
        "application/entity-statement+jwt",
        "text/plain",
        "application/other+jwt",
    ],
)
def test_rejects_unacceptable_media_ranges(accept_header):
    assert accepts(accept_header) is False


@pytest.mark.parametrize(
    "accept_header",
    [
        "application/resolve-response+jwt;q=bogus",
        "application/resolve-response+jwt;q=2",
        "application/resolve-response+jwt;q=-0.1",
    ],
)
def test_rejects_invalid_q_values(accept_header):
    assert accepts(accept_header) is False


@pytest.mark.parametrize(
    "accept_header",
    [
        "not-a-media-range",
        "application/",
        "/resolve-response+jwt",
        "application / resolve-response+jwt",
    ],
)
def test_rejects_malformed_media_ranges(accept_header):
    assert accepts(accept_header) is False


def test_rejects_application_wildcard_by_default():
    assert accepts("application/*") is False


def test_accepts_application_wildcard_when_enabled():
    assert accepts("application/*", allow_application_wildcard=True) is True


def test_require_acceptable_response_returns_for_acceptable_request():
    assert require_acceptable_response(
        accept_header="application/resolve-response+jwt",
        profile=RESOLVE_RESPONSE,
    ) is None


def test_require_acceptable_response_raises_with_expected_content_type():
    with pytest.raises(
        FederationJwtContentNegotiationError,
        match="application/resolve-response\\+jwt",
    ):
        require_acceptable_response(
            accept_header="application/json",
            profile=RESOLVE_RESPONSE,
        )


def test_content_negotiation_module_does_not_use_jwt_or_endpoint_work():
    source = inspect.getsource(content_negotiation)

    assert "sign_federation_jwt" not in source
    assert "verify_federation_jwt" not in source
    assert "factory" not in source
    assert "JWS" not in source


def test_content_negotiation_import_performs_no_network_work(monkeypatch):
    import socket

    def fail_socket(*args, **kwargs):
        raise AssertionError("content negotiation import must not open sockets")

    monkeypatch.setattr(socket, "socket", fail_socket)

    reloaded = importlib.reload(content_negotiation)

    assert reloaded.accepts_profile_response(
        accept_header="*/*",
        profile=RESOLVE_RESPONSE,
    ) is True
