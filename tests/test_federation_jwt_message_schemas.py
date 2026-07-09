"""Tests for Federation JWT payload-only message schemas."""

import pytest

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
