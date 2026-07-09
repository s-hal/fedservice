"""Tests for Federation JWT payload-only message schemas."""

import pytest

from idpyoidc.message.oidc import JsonWebToken

from fedservice.message import ResolveResponse
from fedservice.message import TrustMarkStatusResponse


def trust_mark_status_response_payload(status="active"):
    return {
        "iss": "https://issuer.example.org",
        "iat": 1700000000,
        "trust_mark": (
            "eyJhbGciOiJSUzI1NiJ9."
            "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLm9yZyJ9.signature"
        ),
        "status": status,
    }


def test_trust_mark_status_response_minimal_payload_verifies():
    message = TrustMarkStatusResponse(**trust_mark_status_response_payload())

    assert message.verify() is True


@pytest.mark.parametrize("status", ["active", "expired", "revoked", "invalid"])
def test_trust_mark_status_response_accepts_builtin_status_values(status):
    message = TrustMarkStatusResponse(**trust_mark_status_response_payload(status=status))

    assert message.verify() is True


def test_trust_mark_status_response_accepts_configured_extra_status_value():
    message = TrustMarkStatusResponse(**trust_mark_status_response_payload(status="pending"))

    assert message.verify(allowed_extra_status_values={"pending"}) is True


def test_trust_mark_status_response_rejects_unknown_status_value():
    message = TrustMarkStatusResponse(**trust_mark_status_response_payload(status="pending"))

    with pytest.raises(
        ValueError, match="Unknown Trust Mark Status Response status value"
    ):
        message.verify()


@pytest.mark.parametrize("claim", ["iss", "iat", "trust_mark", "status"])
def test_trust_mark_status_response_requires_core_claims(claim):
    payload = trust_mark_status_response_payload()
    payload.pop(claim)
    message = TrustMarkStatusResponse(**payload)

    with pytest.raises(Exception):
        message.verify()


def test_trust_mark_status_response_does_not_define_jwt_container_methods():
    assert "from_jwt" not in TrustMarkStatusResponse.__dict__
    assert "to_jwt" not in TrustMarkStatusResponse.__dict__


def resolve_response_payload(**overrides):
    payload = {
        "iss": "https://resolver.example.org",
        "sub": "https://subject.example.org",
        "iat": 1700000000,
        "exp": 1700000600,
        "metadata": {"federation_entity": {"contacts": ["ops@example.org"]}},
        "trust_chain": [
            "eyJhbGciOiJSUzI1NiJ9."
            "eyJpc3MiOiJodHRwczovL3N1YmplY3QuZXhhbXBsZS5vcmcifQ.signature"
        ],
    }
    payload.update(overrides)
    return payload


def test_resolve_response_minimal_payload_verifies():
    message = ResolveResponse(**resolve_response_payload())

    assert message.verify() is True


@pytest.mark.parametrize(
    "claim", ["iss", "sub", "iat", "exp", "metadata", "trust_chain"]
)
def test_resolve_response_requires_core_claims(claim):
    payload = resolve_response_payload()
    payload.pop(claim)
    message = ResolveResponse(**payload)

    with pytest.raises(Exception):
        message.verify()


def test_resolve_response_allows_absent_trust_marks():
    payload = resolve_response_payload()
    payload.pop("trust_marks", None)
    message = ResolveResponse(**payload)

    assert message.verify() is True


def test_resolve_response_allows_aud():
    message = ResolveResponse(**resolve_response_payload(aud="https://rp.example.org"))

    assert message.verify() is True


def test_resolve_response_does_not_define_jwt_container_methods():
    assert "from_jwt" not in ResolveResponse.__dict__
    assert "to_jwt" not in ResolveResponse.__dict__


def test_resolve_response_is_not_json_web_token_subclass():
    assert not issubclass(ResolveResponse, JsonWebToken)
