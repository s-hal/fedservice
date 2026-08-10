"""Tests for Resolve Response producer signing."""

import inspect
from types import SimpleNamespace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.message import Message
import pytest

from fedservice.entity.server import resolve as resolve_endpoint
from fedservice.entity.server.resolve import Resolve
from fedservice.entity_statement.create import create_resolve_response
from fedservice.federation_jwt.jose import decode_protected_header
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.key_resolver import KeyJarResolver
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE


ISSUER = "https://resolver.example.org"
SUBJECT = "https://subject.example.org"
TRUST_ANCHOR = "https://trust-anchor.example.org"


def keyjar_with_signing_key():
    key = new_rsa_key(kid="key-1")
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [key])
    return key_jar


def resolve_metadata():
    return {"federation_entity": {"contacts": ["ops@example.org"]}}


def trust_chain():
    return ["leaf.jwt", "intermediate.jwt", "anchor.jwt"]


def future_exp():
    return utc_time_sans_frac() + 3600


def test_create_resolve_response_emits_resolve_response_typ():
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=keyjar_with_signing_key(),
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=future_exp(),
    )

    assert decode_protected_header(token)["typ"] == "resolve-response+jwt"


def test_create_resolve_response_verifies_with_resolve_profile():
    key_jar = keyjar_with_signing_key()
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=future_exp(),
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.profile is RESOLVE_RESPONSE
    assert isinstance(verified.message(), Message)


def test_create_resolve_response_payload_uses_requested_subject():
    key_jar = keyjar_with_signing_key()
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=future_exp(),
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["iss"] == ISSUER
    assert verified.claims()["sub"] == SUBJECT


def test_create_resolve_response_preserves_trust_marks():
    key_jar = keyjar_with_signing_key()
    trust_marks = [
        {
            "trust_mark_type": "https://trust.example.org/mark",
            "trust_mark": "compact.trust.mark",
        }
    ]
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=future_exp(),
        trust_marks=trust_marks,
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["trust_marks"] == tuple(
        {"trust_mark_type": item["trust_mark_type"], "trust_mark": item["trust_mark"]}
        for item in trust_marks
    )


def test_create_resolve_response_uses_absolute_expiration_exactly():
    key_jar = keyjar_with_signing_key()
    expires_at = future_exp()
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=expires_at,
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["exp"] == expires_at


def test_create_resolve_response_passes_explicit_iat_with_zero_lifetime(monkeypatch):
    issued_at = utc_time_sans_frac()
    expires_at = issued_at + 3600
    monkeypatch.setattr(
        "fedservice.entity_statement.create.utc_time_sans_frac",
        lambda: issued_at,
    )
    key_jar = keyjar_with_signing_key()

    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=expires_at,
    )
    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["iss"] == ISSUER
    assert verified.claims()["iat"] == issued_at
    assert verified.claims()["exp"] == expires_at


def test_resolve_response_helper_does_not_derive_fixed_lifetime():
    signature = inspect.signature(create_resolve_response)
    source = inspect.getsource(create_resolve_response)

    assert signature.parameters["expires_at"].default is inspect.Parameter.empty
    assert "lifetime" not in signature.parameters
    assert "now + lifetime" not in source


@pytest.mark.parametrize(
    "trust_mark_exp,expected_exp",
    [
        (None, 5000),
        (4000, 4000),
        (6000, 5000),
    ],
    ids=["missing", "earlier", "later"],
)
def test_resolve_endpoint_bounds_expiration_with_verified_material(
        monkeypatch, trust_mark_exp, expected_exp
):
    raw_trust_mark = "original.compact.mark"
    trust_mark_payload = {"trust_mark_type": "https://example.org/trust-mark"}
    trust_mark_entries = []
    if trust_mark_exp is not None:
        trust_mark_payload["exp"] = trust_mark_exp
    if trust_mark_exp is not None or expected_exp == 5000:
        trust_mark_entries.append(
            {
                "trust_mark_type": "https://example.org/trust-mark",
                "trust_mark": raw_trust_mark,
            }
        )

    chosen_chain = SimpleNamespace(
        anchor=TRUST_ANCHOR,
        exp=5000,
        iss_path=[SUBJECT, TRUST_ANCHOR],
        metadata=resolve_metadata(),
        verified_chain=[{"trust_marks": trust_mark_entries}],
    )
    collector = SimpleNamespace(get_chain=lambda *args: trust_chain())
    functions = SimpleNamespace(
        trust_mark_verifier=lambda **kwargs: trust_mark_payload,
        trust_chain_collector=collector,
    )
    federation_entity = SimpleNamespace(
        entity_id=ISSUER,
        function=functions,
        get_attribute=lambda name: keyjar_with_signing_key(),
    )
    captured = {}

    monkeypatch.setattr(resolve_endpoint, "get_federation_entity", lambda endpoint: federation_entity)
    monkeypatch.setattr(resolve_endpoint, "collect_trust_chains", lambda *args, **kwargs: ([], None))
    monkeypatch.setattr(resolve_endpoint, "verify_trust_chains", lambda *args, **kwargs: [chosen_chain])
    monkeypatch.setattr(resolve_endpoint, "apply_policies", lambda entity, chains: chains)

    def record_response(*args, **kwargs):
        captured.update(kwargs)
        return "signed"

    monkeypatch.setattr(resolve_endpoint, "create_resolve_response", record_response)
    endpoint = object.__new__(Resolve)

    result = endpoint.process_request(
        {"sub": SUBJECT, "trust_anchor": TRUST_ANCHOR}
    )

    assert result == {"response_args": "signed"}
    assert captured["expires_at"] == expected_exp
    if trust_mark_entries:
        assert captured["trust_marks"][0]["trust_mark"] == raw_trust_mark


def test_resolve_endpoint_excludes_rejected_trust_mark_without_reducing_expiration(
        monkeypatch
):
    raw_trust_mark = "expired.compact.mark"
    chosen_chain = SimpleNamespace(
        anchor=TRUST_ANCHOR,
        exp=5000,
        iss_path=[SUBJECT, TRUST_ANCHOR],
        metadata=resolve_metadata(),
        verified_chain=[
            {
                "trust_marks": [
                    {
                        "trust_mark_type": "https://example.org/trust-mark",
                        "trust_mark": raw_trust_mark,
                    }
                ]
            }
        ],
    )
    collector = SimpleNamespace(get_chain=lambda *args: trust_chain())
    functions = SimpleNamespace(
        trust_mark_verifier=lambda **kwargs: None,
        trust_chain_collector=collector,
    )
    federation_entity = SimpleNamespace(
        entity_id=ISSUER,
        function=functions,
        get_attribute=lambda name: keyjar_with_signing_key(),
    )
    captured = {}

    monkeypatch.setattr(resolve_endpoint, "get_federation_entity", lambda endpoint: federation_entity)
    monkeypatch.setattr(resolve_endpoint, "collect_trust_chains", lambda *args, **kwargs: ([], None))
    monkeypatch.setattr(resolve_endpoint, "verify_trust_chains", lambda *args, **kwargs: [chosen_chain])
    monkeypatch.setattr(resolve_endpoint, "apply_policies", lambda entity, chains: chains)

    def record_response(*args, **kwargs):
        captured.update(kwargs)
        return "signed"

    monkeypatch.setattr(resolve_endpoint, "create_resolve_response", record_response)
    endpoint = object.__new__(Resolve)

    result = endpoint.process_request(
        {"sub": SUBJECT, "trust_anchor": TRUST_ANCHOR}
    )

    assert result == {"response_args": "signed"}
    assert captured["expires_at"] == 5000
    assert "trust_marks" not in captured


def test_resolve_endpoint_no_longer_uses_entity_configuration_producer():
    source = inspect.getsource(resolve_endpoint)

    assert "create_entity_configuration" not in source
    assert "create_resolve_response" in source


def test_resolve_endpoint_content_type_remains_resolve_response_jwt():
    assert Resolve.response_content_type == RESOLVE_RESPONSE.content_type
