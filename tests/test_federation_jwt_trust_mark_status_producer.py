"""Tests for Trust Mark Status Response producer signing."""

import inspect
import json

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key

from fedservice.federation_jwt.jose import decode_protected_header
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.key_resolver import KeyJarResolver
from fedservice.federation_jwt.registry import TRUST_MARK_STATUS_RESPONSE
from fedservice.trust_mark_entity.server import trust_mark_status
from fedservice.trust_mark_entity.server.trust_mark_status import TrustMarkStatus
from fedservice.trust_mark_entity.server.trust_mark_status import create_trust_mark_status_response


ISSUER = "https://trust-mark-issuer.example.org"
TRUST_MARK = "compact.trust.mark"


def keyjar_with_signing_key():
    key = new_rsa_key(kid="key-1")
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [key])
    return key_jar


class TrustMarkIssuer:
    def __init__(self, active=True):
        self.active = active
        self.entity_id = ISSUER
        self.keyjar = keyjar_with_signing_key()

    def unpack_trust_mark(self, trust_mark):
        return {
            "trust_mark_type": "https://example.org/trust-mark",
            "sub": "https://subject.example.org",
        }

    def find(self, trust_mark_type, sub):
        return self.active

    def upstream_get(self, item, name):
        assert (item, name) == ("attribute", "keyjar")
        return self.keyjar


def status_endpoint(active=True):
    issuer = TrustMarkIssuer(active=active)
    endpoint = object.__new__(TrustMarkStatus)
    endpoint.upstream_get = lambda item: issuer
    return endpoint, issuer


def test_create_trust_mark_status_response_returns_compact_jwt():
    token = create_trust_mark_status_response(
        keyjar=keyjar_with_signing_key(),
        entity_id=ISSUER,
        trust_mark=TRUST_MARK,
        status="active",
    )

    assert token.count(".") == 2


def test_create_trust_mark_status_response_uses_status_response_typ():
    token = create_trust_mark_status_response(
        keyjar=keyjar_with_signing_key(),
        entity_id=ISSUER,
        trust_mark=TRUST_MARK,
        status="active",
    )

    assert decode_protected_header(token)["typ"] == "trust-mark-status-response+jwt"


def test_create_trust_mark_status_response_verifies_with_status_profile():
    key_jar = keyjar_with_signing_key()
    token = create_trust_mark_status_response(
        keyjar=key_jar,
        entity_id=ISSUER,
        trust_mark=TRUST_MARK,
        status="active",
    )

    verified = verify_federation_jwt(
        profile=TRUST_MARK_STATUS_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["status"] == "active"
    assert verified.claims()["trust_mark"] == TRUST_MARK


def test_matching_compact_trust_mark_returns_signed_status_with_exact_token():
    endpoint, issuer = status_endpoint()

    result = endpoint.process_request({"trust_mark": TRUST_MARK})
    token = result["response_args"]
    verified = verify_federation_jwt(
        profile=TRUST_MARK_STATUS_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(issuer.keyjar),
    )

    assert verified.claims()["trust_mark"] == TRUST_MARK
    assert verified.claims()["status"] == "active"


def test_subject_and_type_request_requires_compact_trust_mark(monkeypatch):
    endpoint, _ = status_endpoint()

    def fail_if_signed(**kwargs):
        raise AssertionError("unsupported request form must not sign a JWT")

    monkeypatch.setattr(
        trust_mark_status,
        "create_trust_mark_status_response",
        fail_if_signed,
    )

    result = endpoint.process_request(
        {
            "sub": "https://subject.example.org",
            "trust_mark_type": "https://example.org/trust-mark",
        }
    )

    assert result["error"] == "invalid_request"
    assert "compact trust_mark is required" in result["error_description"]


def test_inactive_compact_trust_mark_returns_not_found():
    endpoint, _ = status_endpoint(active=False)

    result = endpoint.process_request({"trust_mark": TRUST_MARK})

    assert result["error"] == "not_found"


def test_trust_mark_status_error_response_boundary_uses_json():
    endpoint, _ = status_endpoint()
    error = endpoint.process_request(
        {
            "sub": "https://subject.example.org",
            "trust_mark_type": "https://example.org/trust-mark",
        }
    )

    response = endpoint.do_response(response_args=error)

    assert ("Content-type", "application/json") in response["http_headers"]
    assert json.loads(response["response"])["error"] == "invalid_request"


def test_trust_mark_status_success_response_boundary_uses_profile_content_type():
    endpoint, _ = status_endpoint()
    result = endpoint.process_request({"trust_mark": TRUST_MARK})

    response = endpoint.do_response(**result)

    assert (
        "Content-type",
        "application/trust-mark-status-response+jwt",
    ) in response["http_headers"]


def test_trust_mark_status_endpoint_success_content_type_is_profile_type():
    assert TrustMarkStatus.response_format == "jose"
    assert (
        TrustMarkStatus.response_content_type
        == "application/trust-mark-status-response+jwt"
    )


def test_trust_mark_status_module_no_longer_uses_legacy_jwt_pack():
    source = inspect.getsource(trust_mark_status)

    assert "JWT(" not in source
    assert ".pack(" not in source
    assert "create_trust_mark(" not in source
    assert "create_trust_mark_status_response" in source
