"""Tests for Trust Mark Status Response producer signing."""

import inspect

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
