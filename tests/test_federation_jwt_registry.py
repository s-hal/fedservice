"""Tests for canonical Federation JWT profile registry."""

import ast
import importlib
import inspect
from types import MappingProxyType

import pytest
from idpyoidc.message import Message

from fedservice.federation_jwt import registry
from fedservice.federation_jwt.errors import FederationJwtProfileError
from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.message import EntityConfiguration
from fedservice.message import HistoricalKeysResponse
from fedservice.message import JWKSet
from fedservice.message import ResolveResponse
from fedservice.message import SubordinateStatement
from fedservice.message import TrustMark
from fedservice.message import TrustMarkDelegation
from fedservice.message import TrustMarkStatusResponse


PROFILE_CONSTANTS = (
    registry.ENTITY_CONFIGURATION,
    registry.SUBORDINATE_STATEMENT,
    registry.RESOLVE_RESPONSE,
    registry.TRUST_MARK,
    registry.TRUST_MARK_DELEGATION,
    registry.TRUST_MARK_STATUS_RESPONSE,
    registry.SIGNED_JWK_SET,
    registry.HISTORICAL_KEYS_RESPONSE,
    registry.EXPLICIT_REGISTRATION_RESPONSE,
)

EXPECTED_ORDER = (
    "entity_configuration",
    "subordinate_statement",
    "resolve_response",
    "trust_mark",
    "trust_mark_delegation",
    "trust_mark_status_response",
    "signed_jwk_set",
    "historical_keys_response",
    "explicit_registration_response",
)

EXPECTED_TYP_AND_CONTENT_TYPE = {
    "entity_configuration": (
        "entity-statement+jwt",
        "application/entity-statement+jwt",
    ),
    "subordinate_statement": (
        "entity-statement+jwt",
        "application/entity-statement+jwt",
    ),
    "resolve_response": (
        "resolve-response+jwt",
        "application/resolve-response+jwt",
    ),
    "trust_mark": (
        "trust-mark+jwt",
        "application/trust-mark+jwt",
    ),
    "trust_mark_delegation": (
        "trust-mark-delegation+jwt",
        "application/trust-mark-delegation+jwt",
    ),
    "trust_mark_status_response": (
        "trust-mark-status-response+jwt",
        "application/trust-mark-status-response+jwt",
    ),
    "signed_jwk_set": (
        "jwk-set+jwt",
        "application/jwk-set+jwt",
    ),
    "historical_keys_response": (
        "jwk-set+jwt",
        "application/jwk-set+jwt",
    ),
    "explicit_registration_response": (
        "explicit-registration-response+jwt",
        "application/explicit-registration-response+jwt",
    ),
}


def test_profile_constants_are_federation_jwt_profiles():
    for profile in PROFILE_CONSTANTS:
        assert isinstance(profile, FederationJwtProfile)


def test_profile_names_are_unique():
    names = [profile.name for profile in registry.ALL_PROFILES]

    assert len(names) == len(set(names))


def test_all_profiles_order_is_deterministic():
    assert registry.ALL_PROFILES == PROFILE_CONSTANTS
    assert tuple(profile.name for profile in registry.ALL_PROFILES) == EXPECTED_ORDER


def test_expected_typ_and_content_type_values_are_present():
    for profile in registry.ALL_PROFILES:
        assert (profile.typ, profile.content_type) == EXPECTED_TYP_AND_CONTENT_TYPE[
            profile.name
        ]


def test_entity_statement_profiles_are_distinct_with_shared_typ():
    assert registry.ENTITY_CONFIGURATION is not registry.SUBORDINATE_STATEMENT
    assert registry.ENTITY_CONFIGURATION.typ == "entity-statement+jwt"
    assert registry.SUBORDINATE_STATEMENT.typ == "entity-statement+jwt"


def test_jwk_set_profiles_are_distinct_with_shared_typ():
    assert registry.SIGNED_JWK_SET is not registry.HISTORICAL_KEYS_RESPONSE
    assert registry.SIGNED_JWK_SET.typ == "jwk-set+jwt"
    assert registry.HISTORICAL_KEYS_RESPONSE.typ == "jwk-set+jwt"


def test_message_classes_are_payload_schema_references_only():
    assert registry.ENTITY_CONFIGURATION.message_cls is EntityConfiguration
    assert registry.SUBORDINATE_STATEMENT.message_cls is SubordinateStatement
    assert registry.RESOLVE_RESPONSE.message_cls is ResolveResponse
    assert registry.TRUST_MARK.message_cls is TrustMark
    assert registry.TRUST_MARK_DELEGATION.message_cls is TrustMarkDelegation
    assert registry.SIGNED_JWK_SET.message_cls is JWKSet
    assert registry.HISTORICAL_KEYS_RESPONSE.message_cls is HistoricalKeysResponse
    assert registry.TRUST_MARK_STATUS_RESPONSE.message_cls is TrustMarkStatusResponse
    assert registry.EXPLICIT_REGISTRATION_RESPONSE.message_cls is Message


def test_registry_values_are_not_derived_from_message_jwt_container_attributes():
    source = inspect.getsource(registry)

    assert "JWT_TYP" not in source
    assert "h_allowed_values" not in source
    assert "TypedJsonWebToken" not in source
    assert "JsonWebToken" not in source


def test_registry_annotations_are_python37_compatible():
    source = inspect.getsource(registry)

    assert "MappingProxyType[" not in source
    assert "dict[" not in source
    assert "list[" not in source
    assert "tuple[" not in source
    assert " | " not in source


def test_registry_staging_comments_are_preserved():
    source = inspect.getsource(registry)

    assert "future spec-alignment ticket" in source
    assert "dedicated Explicit Registration Response payload class" in source


def test_registry_code_does_not_call_jwt_container_or_crypto_helpers():
    forbidden_calls = {
        "from_jwt",
        "to_jwt",
        "pack",
        "unpack",
        "sign_federation_jwt",
        "verify_federation_jwt",
    }
    tree = ast.parse(inspect.getsource(registry))
    called_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                called_names.add(node.func.attr)
            elif isinstance(node.func, ast.Name):
                called_names.add(node.func.id)

    assert not forbidden_calls.intersection(called_names)


def test_name_lookup_returns_exact_profile_object():
    for profile in registry.ALL_PROFILES:
        assert registry.get_profile_by_name(profile.name) is profile


def test_missing_name_lookup_raises_profile_error():
    with pytest.raises(FederationJwtProfileError, match="missing"):
        registry.get_profile_by_name("missing")


def test_content_type_lookup_returns_tuple():
    profiles = registry.get_profiles_by_content_type(
        "application/resolve-response+jwt"
    )

    assert isinstance(profiles, tuple)
    assert profiles == (registry.RESOLVE_RESPONSE,)


def test_content_type_lookup_returns_registry_tuple():
    content_type = "application/jwk-set+jwt"

    profiles = registry.get_profiles_by_content_type(content_type)

    assert profiles is registry.PROFILES_BY_CONTENT_TYPE[content_type]


def test_shared_content_type_lookup_returns_all_profiles_in_order():
    assert registry.get_profiles_by_content_type(
        "application/entity-statement+jwt"
    ) == (registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT)
    assert registry.get_profiles_by_content_type("application/jwk-set+jwt") == (
        registry.SIGNED_JWK_SET,
        registry.HISTORICAL_KEYS_RESPONSE,
    )


def test_missing_content_type_lookup_raises_profile_error():
    with pytest.raises(FederationJwtProfileError, match=r"application/missing\+jwt"):
        registry.get_profiles_by_content_type("application/missing+jwt")


def test_registry_groupings_are_immutable():
    assert isinstance(registry.ALL_PROFILES, tuple)
    assert isinstance(registry.PROFILES_BY_NAME, MappingProxyType)
    assert isinstance(registry.PROFILES_BY_CONTENT_TYPE, MappingProxyType)

    with pytest.raises(TypeError):
        registry.PROFILES_BY_NAME["new"] = registry.RESOLVE_RESPONSE
    with pytest.raises(TypeError):
        registry.PROFILES_BY_CONTENT_TYPE["new"] = (registry.RESOLVE_RESPONSE,)


def test_registry_helpers_do_not_mutate_registry_state():
    names_before = dict(registry.PROFILES_BY_NAME)
    content_types_before = dict(registry.PROFILES_BY_CONTENT_TYPE)

    assert registry.get_profile_by_name("resolve_response") is registry.RESOLVE_RESPONSE
    assert registry.get_profiles_by_content_type(
        "application/entity-statement+jwt"
    ) == (registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT)

    assert dict(registry.PROFILES_BY_NAME) == names_before
    assert dict(registry.PROFILES_BY_CONTENT_TYPE) == content_types_before


def test_registry_import_performs_no_network_or_crypto_work(monkeypatch):
    import socket

    def fail_socket(*args, **kwargs):
        raise AssertionError("registry import must not open network sockets")

    def fail_sign(*args, **kwargs):
        raise AssertionError("registry import must not sign JWTs")

    def fail_verify(*args, **kwargs):
        raise AssertionError("registry import must not verify JWTs")

    monkeypatch.setattr(socket, "socket", fail_socket)
    monkeypatch.setattr("fedservice.federation_jwt.jose.sign_federation_jwt", fail_sign)
    monkeypatch.setattr("fedservice.federation_jwt.jose.verify_federation_jwt", fail_verify)

    reloaded = importlib.reload(registry)

    assert reloaded.RESOLVE_RESPONSE.name == "resolve_response"
