"""Tests for Entity Statement producer signing."""

import inspect

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
import pytest

from fedservice.entity.server.entity_configuration import EntityConfiguration
from fedservice.entity.server.fetch import Fetch
from fedservice.entity_statement import create as entity_statement_create
from fedservice.entity_statement.create import create_entity_configuration
from fedservice.entity_statement.create import create_entity_statement
from fedservice.entity_statement.create import create_subordinate_statement
from fedservice.federation_jwt.jose import decode_protected_header
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.key_resolver import KeyJarResolver
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT


ISSUER = "https://issuer.example.org"
SUBJECT = "https://subject.example.org"


def keyjar_with_signing_key(owner=ISSUER):
    key = new_rsa_key(kid="key-1")
    key_jar = KeyJar()
    key_jar.add_keys(owner, [key])
    return key_jar


def metadata():
    return {"federation_entity": {"contacts": ["ops@example.org"]}}


def test_entity_configuration_producer_emits_entity_statement_typ():
    token = create_entity_configuration(
        ISSUER,
        key_jar=keyjar_with_signing_key(),
        metadata=metadata(),
    )

    assert decode_protected_header(token)["typ"] == "entity-statement+jwt"


def test_entity_configuration_payload_verifies_with_profile():
    key_jar = keyjar_with_signing_key()
    token = create_entity_configuration(ISSUER, key_jar=key_jar, metadata=metadata())

    verified = verify_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["iss"] == ISSUER
    assert verified.claims()["sub"] == ISSUER
    assert (
        verified.claims()["metadata"]["federation_entity"]["contacts"]
        == ("ops@example.org",)
    )
    assert "jwks" in verified.claims()


def test_entity_configuration_emits_non_reserved_protected_header():
    token = create_entity_configuration(
        ISSUER,
        key_jar=keyjar_with_signing_key(),
        metadata=metadata(),
        extra_protected_headers={"cty": "application/json"},
    )

    assert decode_protected_header(token)["cty"] == "application/json"


@pytest.mark.parametrize("header", ["typ", "kid", "alg"])
def test_entity_configuration_rejects_profile_owned_header_override(header):
    with pytest.raises(FederationJwtHeaderError):
        create_entity_configuration(
            ISSUER,
            key_jar=keyjar_with_signing_key(),
            metadata=metadata(),
            extra_protected_headers={header: "override"},
        )


def test_subordinate_statement_producer_emits_entity_statement_typ():
    token = create_subordinate_statement(
        ISSUER,
        SUBJECT,
        key_jar=keyjar_with_signing_key(),
        metadata=metadata(),
    )

    assert decode_protected_header(token)["typ"] == "entity-statement+jwt"


def test_entity_statement_profiles_are_distinct_despite_shared_typ():
    assert ENTITY_CONFIGURATION is not SUBORDINATE_STATEMENT
    assert ENTITY_CONFIGURATION.typ == "entity-statement+jwt"
    assert SUBORDINATE_STATEMENT.typ == "entity-statement+jwt"


def test_generic_entity_statement_helper_requires_profile():
    profile_parameter = inspect.signature(create_entity_statement).parameters["profile"]

    assert profile_parameter.default is inspect.Parameter.empty


def test_entity_statement_helper_does_not_select_profile_from_issuer_and_subject():
    source = inspect.getsource(create_entity_statement)

    assert "iss == sub" not in source


def test_entity_statement_wrappers_pass_canonical_profiles(monkeypatch):
    profiles = []

    def record_profile(iss, sub, key_jar, profile, **kwargs):
        profiles.append(profile)
        return "signed"

    monkeypatch.setattr(entity_statement_create, "create_entity_statement", record_profile)

    assert create_entity_configuration(ISSUER, object(), metadata=metadata()) == "signed"
    assert create_subordinate_statement(ISSUER, SUBJECT, object()) == "signed"
    assert profiles == [ENTITY_CONFIGURATION, SUBORDINATE_STATEMENT]


def test_subordinate_statement_payload_verifies_with_profile():
    key_jar = keyjar_with_signing_key()
    token = create_subordinate_statement(
        ISSUER,
        SUBJECT,
        key_jar=key_jar,
        metadata=metadata(),
        constraints={"max_path_length": 2},
    )

    verified = verify_federation_jwt(
        profile=SUBORDINATE_STATEMENT,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["iss"] == ISSUER
    assert verified.claims()["sub"] == SUBJECT
    assert (
        verified.claims()["metadata"]["federation_entity"]["contacts"]
        == ("ops@example.org",)
    )
    assert verified.claims()["constraints"] == {"max_path_length": 2}


def test_entity_configuration_producer_supports_blank_owner_keyjar():
    key_jar = keyjar_with_signing_key(owner="")
    token = create_entity_configuration(ISSUER, key_jar=key_jar, metadata=metadata())

    assert decode_protected_header(token)["kid"] == "key-1"


def test_entity_configuration_endpoint_content_type_is_preserved():
    assert EntityConfiguration.response_content_type == ENTITY_CONFIGURATION.content_type


def test_fetch_endpoint_content_type_is_preserved():
    assert Fetch.response_content_type == SUBORDINATE_STATEMENT.content_type


def test_entity_statement_create_no_longer_uses_cryptojwt_jwt_pack():
    source = inspect.getsource(entity_statement_create)

    assert "cryptojwt.jwt import JWT" not in source
    assert "JWT(" not in source
    assert ".pack(" not in source


def test_entity_statement_create_uses_extra_protected_headers_name_only():
    source = inspect.getsource(entity_statement_create)

    assert "jws_headers" not in source
    assert "extra_protected_headers" in source
