"""Tests for Trust Mark Status Response producer signing."""

import base64
from dataclasses import replace
import inspect
import json
import time

from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.jwt import JWT
import pytest

from fedservice.federation_jwt import registry
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import TRUST_MARK_STATUS_RESPONSE
from fedservice.exception import WrongSubject
from fedservice.message import TrustMark as TrustMarkMessage
from fedservice.trust_mark_entity import entity as trust_mark_entity_module
from fedservice.trust_mark_entity.entity import TrustMarkEntity
from fedservice.trust_mark_entity.server import trust_mark_status
from fedservice.trust_mark_entity.server.trust_mark_status import TrustMarkStatus
from fedservice.trust_mark_entity.server.trust_mark_status import create_trust_mark_status_response


ISSUER = "https://trust-mark-issuer.example.org"
TRUST_MARK = "compact.trust.mark"
TRUST_MARK_TYPE = "https://example.org/trust-mark"
SUBJECT = "https://subject.example.org"


def keyjar_with_signing_key():
    key = new_rsa_key(kid="key-1")
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [key])
    return key_jar


def canonical_trust_mark_entity(key_jar):
    entity = object.__new__(TrustMarkEntity)
    entity.entity_id = ISSUER
    entity.upstream_get = lambda item, name: key_jar
    return entity


def signed_trust_mark(key_jar, alg="RS256", kid="key-1", **overrides):
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": SUBJECT,
        "iat": now - 10,
        "exp": now + 600,
        "trust_mark_type": TRUST_MARK_TYPE,
    }
    payload.update(overrides)
    return sign_federation_jwt(
        profile=registry.TRUST_MARK,
        payload=payload,
        key_jar=key_jar,
        issuer=ISSUER,
        alg=alg,
        kid=kid,
        iat=payload["iat"],
    )


def replace_protected_header(token, header):
    encoded = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    _protected, payload, signature = token.split(".")
    return ".".join([encoded, payload, signature])


def corrupt_signature(token):
    protected, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    return ".".join([protected, payload, replacement + signature[1:]])


def test_unpack_trust_mark_uses_derived_rs256_profile_and_shared_keyjar(
    monkeypatch,
):
    key_jar = keyjar_with_signing_key()
    token = signed_trust_mark(key_jar)
    entity = canonical_trust_mark_entity(key_jar)
    real_verify = trust_mark_entity_module.verify_federation_jwt
    calls = []

    def record_verification(**kwargs):
        calls.append(kwargs)
        return real_verify(**kwargs)

    monkeypatch.setattr(
        trust_mark_entity_module,
        "verify_federation_jwt",
        record_verification,
    )

    result = entity.unpack_trust_mark(token)

    expected_profile = replace(
        registry.TRUST_MARK,
        allowed_algs=frozenset({"RS256"}),
    )
    assert len(calls) == 1
    assert calls[0] == {
        "profile": expected_profile,
        "token": token,
        "key_jar": key_jar,
    }
    assert isinstance(result, TrustMarkMessage)
    assert result["trust_mark_type"] == TRUST_MARK_TYPE
    assert registry.TRUST_MARK.allowed_algs != frozenset({"RS256"})


def test_unpack_trust_mark_accepts_current_rs256_issuance_path():
    key_jar = keyjar_with_signing_key()
    token = trust_mark_entity_module.create_trust_mark(
        key_jar,
        ISSUER,
        trust_mark_type=TRUST_MARK_TYPE,
        sub=SUBJECT,
        lifetime=600,
    )
    entity = canonical_trust_mark_entity(key_jar)

    result = entity.unpack_trust_mark(token)

    assert isinstance(result, TrustMarkMessage)
    assert result["iss"] == ISSUER
    assert result["sub"] == SUBJECT


def test_unpack_trust_mark_rejects_es256_allowed_by_global_profile():
    key = new_ec_key("P-256", kid="es-key")
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [key])
    token = signed_trust_mark(key_jar, alg="ES256", kid=key.kid)
    entity = canonical_trust_mark_entity(key_jar)

    verified = verify_federation_jwt(
        profile=registry.TRUST_MARK,
        token=token,
        key_jar=key_jar,
    )
    assert isinstance(verified.message(), TrustMarkMessage)

    with pytest.raises(ValueError):
        entity.unpack_trust_mark(token)


@pytest.mark.parametrize(
    "variant",
    ["missing-typ", "wrong-typ", "missing-kid", "bad-signature"],
)
def test_unpack_trust_mark_rejects_invalid_jose(variant):
    key_jar = keyjar_with_signing_key()
    token = signed_trust_mark(key_jar)
    if variant == "bad-signature":
        token = corrupt_signature(token)
    else:
        header = dict(jws_factory(token).jwt.headers)
        if variant == "missing-typ":
            del header["typ"]
        elif variant == "wrong-typ":
            header["typ"] = "trust-mark-delegation+jwt"
        else:
            del header["kid"]
        token = replace_protected_header(token, header)
    entity = canonical_trust_mark_entity(key_jar)

    with pytest.raises(ValueError):
        entity.unpack_trust_mark(token)


@pytest.mark.parametrize(
    "claim,value_offset",
    [
        ("exp", lambda skew: -skew - 60),
        ("iat", lambda skew: skew + 60),
    ],
    ids=["expired", "future-iat"],
)
def test_unpack_trust_mark_rejects_invalid_time_claims(claim, value_offset):
    key_jar = keyjar_with_signing_key()
    value = int(time.time()) + value_offset(JWT().skew)
    token = signed_trust_mark(key_jar, **{claim: value})
    entity = canonical_trust_mark_entity(key_jar)

    with pytest.raises(ValueError):
        entity.unpack_trust_mark(token)


def test_unpack_trust_mark_preserves_entity_id_subject_check():
    key_jar = keyjar_with_signing_key()
    token = signed_trust_mark(key_jar)
    entity = canonical_trust_mark_entity(key_jar)

    with pytest.raises(WrongSubject):
        entity.unpack_trust_mark(
            token,
            entity_id="https://different-subject.example.org",
        )


def test_unpack_trust_mark_has_no_direct_cryptojwt_unpack():
    source = inspect.getsource(TrustMarkEntity.unpack_trust_mark)

    assert "JWT(" not in source
    assert ".unpack(" not in source
    assert "verify_federation_jwt(" in source


def test_status_endpoint_maps_real_verification_failure_without_lookup():
    key_jar = keyjar_with_signing_key()
    entity = canonical_trust_mark_entity(key_jar)
    find_calls = []
    entity.find = lambda *args: find_calls.append(args)
    endpoint = object.__new__(TrustMarkStatus)
    endpoint.upstream_get = lambda item: entity
    invalid_token = corrupt_signature(signed_trust_mark(key_jar))

    result = endpoint.process_request({"trust_mark": invalid_token})

    assert result["error"] == "invalid_request"
    assert find_calls == []


class TrustMarkIssuer:
    def __init__(self, active=True, parsed_mark=None, parser_error=None):
        self.active = active
        self.entity_id = ISSUER
        self.keyjar = keyjar_with_signing_key()
        self.parsed_mark = parsed_mark
        self.parser_error = parser_error
        self.find_calls = []

    def unpack_trust_mark(self, trust_mark):
        if self.parser_error:
            raise self.parser_error
        if self.parsed_mark is not None:
            return self.parsed_mark
        return {
            "trust_mark_type": "https://example.org/trust-mark",
            "sub": "https://subject.example.org",
        }

    def find(self, trust_mark_type, sub):
        self.find_calls.append((trust_mark_type, sub))
        return self.active

    def upstream_get(self, item, name):
        assert (item, name) == ("attribute", "keyjar")
        return self.keyjar


def status_endpoint(active=True, parsed_mark=None, parser_error=None):
    issuer = TrustMarkIssuer(
        active=active,
        parsed_mark=parsed_mark,
        parser_error=parser_error,
    )
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

    assert jws_factory(token).jwt.headers["typ"] == "trust-mark-status-response+jwt"


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
        key_jar=key_jar,
    )

    assert verified.claims()["status"] == "active"
    assert verified.claims()["trust_mark"] == TRUST_MARK
    assert verified.claims()["iss"] == ISSUER
    assert isinstance(verified.claims()["iat"], int)
    assert "exp" not in verified.claims()


def test_matching_compact_trust_mark_returns_signed_status_with_exact_token():
    endpoint, issuer = status_endpoint()

    result = endpoint.process_request({"trust_mark": TRUST_MARK})
    token = result["response_args"]
    verified = verify_federation_jwt(
        profile=TRUST_MARK_STATUS_RESPONSE,
        token=token,
        key_jar=issuer.keyjar,
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


def test_parser_exception_returns_invalid_request():
    endpoint, issuer = status_endpoint(parser_error=ValueError("bad token"))

    result = endpoint.process_request({"trust_mark": TRUST_MARK})

    assert result["error"] == "invalid_request"
    assert issuer.find_calls == []


def test_non_mapping_parsed_trust_mark_returns_invalid_request():
    endpoint, issuer = status_endpoint(parsed_mark=["not", "a", "mapping"])

    result = endpoint.process_request({"trust_mark": TRUST_MARK})

    assert result["error"] == "invalid_request"
    assert issuer.find_calls == []


def test_missing_trust_mark_type_returns_invalid_request():
    endpoint, issuer = status_endpoint(
        parsed_mark={"sub": "https://subject.example.org"}
    )

    result = endpoint.process_request({"trust_mark": TRUST_MARK})

    assert result["error"] == "invalid_request"
    assert issuer.find_calls == []


def test_missing_subject_returns_invalid_request():
    endpoint, issuer = status_endpoint(
        parsed_mark={"trust_mark_type": "https://example.org/trust-mark"}
    )

    result = endpoint.process_request({"trust_mark": TRUST_MARK})

    assert result["error"] == "invalid_request"
    assert issuer.find_calls == []


def test_empty_or_non_string_routing_claims_return_invalid_request():
    invalid_marks = [
        {"trust_mark_type": "", "sub": "https://subject.example.org"},
        {"trust_mark_type": "https://example.org/trust-mark", "sub": ""},
        {"trust_mark_type": 123, "sub": "https://subject.example.org"},
        {"trust_mark_type": "https://example.org/trust-mark", "sub": []},
    ]

    for parsed_mark in invalid_marks:
        endpoint, issuer = status_endpoint(parsed_mark=parsed_mark)

        result = endpoint.process_request({"trust_mark": TRUST_MARK})

        assert result["error"] == "invalid_request"
        assert issuer.find_calls == []


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


def test_trust_mark_status_error_response_preserves_response_metadata():
    endpoint, _ = status_endpoint()
    error = endpoint.process_request({"sub": "https://subject.example.org"})
    request = {"trust_mark": TRUST_MARK}
    cookie = [{"name": "session", "value": "cookie-value"}]

    response = endpoint.do_response(
        response_args=error,
        request=request,
        response_code=400,
        http_headers=[("X-Correlation-ID", "request-1"), ("Content-Type", "text/plain")],
        cookie=cookie,
    )

    assert response["response_code"] == 400
    assert response["cookie"] == cookie
    assert ("X-Correlation-ID", "request-1") in response["http_headers"]
    assert ("Content-type", "application/json") in response["http_headers"]
    assert ("Content-Type", "text/plain") not in response["http_headers"]


def test_trust_mark_status_success_response_boundary_uses_profile_content_type():
    endpoint, _ = status_endpoint()
    result = endpoint.process_request({"trust_mark": TRUST_MARK})

    response = endpoint.do_response(**result)

    assert (
        "Content-type",
        TRUST_MARK_STATUS_RESPONSE.content_type,
    ) in response["http_headers"]


def test_trust_mark_status_endpoint_success_content_type_is_profile_type():
    assert TrustMarkStatus.response_format == "jose"
    assert (
        TrustMarkStatus.response_content_type
        == TRUST_MARK_STATUS_RESPONSE.content_type
    )


def test_trust_mark_status_module_no_longer_uses_legacy_jwt_pack():
    source = inspect.getsource(trust_mark_status)

    assert "JWT(" not in source
    assert ".pack(" not in source
    assert "create_trust_mark(" not in source
    assert "create_trust_mark_status_response" in source
