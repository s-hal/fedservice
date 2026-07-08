"""Tests for deterministic Federation JWT key resolvers."""

from dataclasses import dataclass

import pytest
from cryptojwt.jwk.rsa import new_rsa_key
from idpyoidc.message import Message

from fedservice.federation_jwt.key_resolver import KeyResolver
from fedservice.federation_jwt.key_resolver import StaticKeyResolver
from fedservice.federation_jwt.profile import FederationJwtProfile


@dataclass(frozen=True)
class LocalKey:
    kid: str


class SerializedKey:
    def __init__(self, kid):
        self._kid = kid

    def serialize(self):
        return {"kid": self._kid}


def make_profile():
    return FederationJwtProfile(
        name="entity_configuration",
        typ="entity-statement+jwt",
        content_type="application/entity-statement+jwt",
        message_cls=Message,
    )


def resolve(resolver, protected_header=None, untrusted_payload=None, context=None):
    if protected_header is None:
        protected_header = {"kid": "key-1"}
    if untrusted_payload is None:
        untrusted_payload = {"iss": "issuer"}

    return resolver.resolve(
        profile=make_profile(),
        protected_header=protected_header,
        untrusted_payload=untrusted_payload,
        context=context,
    )


def test_key_resolver_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        KeyResolver()


def test_static_key_resolver_returns_matching_keys_by_kid():
    key = LocalKey("key-1")
    resolver = StaticKeyResolver([key, LocalKey("other")])

    assert resolve(resolver) == (key,)


def test_static_key_resolver_excludes_non_matching_keys():
    resolver = StaticKeyResolver([LocalKey("other")])

    assert resolve(resolver) == ()


def test_static_key_resolver_preserves_multiple_matches_in_source_order():
    first = LocalKey("key-1")
    second = LocalKey("key-1")
    resolver = StaticKeyResolver([LocalKey("other"), first, second])

    assert resolve(resolver) == (first, second)


def test_static_key_resolver_snapshots_constructor_keys():
    key = LocalKey("key-1")
    keys = [key]
    resolver = StaticKeyResolver(keys)
    keys.append(LocalKey("key-1"))

    assert resolve(resolver) == (key,)


def test_static_key_resolver_output_is_tuple():
    resolver = StaticKeyResolver([LocalKey("key-1")])

    assert isinstance(resolve(resolver), tuple)


@pytest.mark.parametrize("kid", [None, "", 123])
def test_static_key_resolver_returns_empty_tuple_without_usable_header_kid(kid):
    resolver = StaticKeyResolver([LocalKey("key-1")])
    protected_header = {}
    if kid is not None:
        protected_header["kid"] = kid

    assert resolve(resolver, protected_header=protected_header) == ()


def test_static_key_resolver_does_not_mutate_inputs():
    resolver = StaticKeyResolver([LocalKey("key-1")])
    protected_header = {"kid": "key-1"}
    untrusted_payload = {"iss": "issuer", "jwks": {"keys": []}}

    resolve(
        resolver,
        protected_header=protected_header,
        untrusted_payload=untrusted_payload,
    )

    assert protected_header == {"kid": "key-1"}
    assert untrusted_payload == {"iss": "issuer", "jwks": {"keys": []}}


def test_static_key_resolver_supports_mapping_key_ids():
    key = {"kid": "key-1"}
    resolver = StaticKeyResolver([key])

    assert resolve(resolver) == (key,)


def test_static_key_resolver_supports_serialized_key_ids():
    key = SerializedKey("key-1")
    resolver = StaticKeyResolver([key])

    assert resolve(resolver) == (key,)


def test_static_key_resolver_supports_cryptojwt_key_kid_attribute():
    key = new_rsa_key(kid="key-1")
    resolver = StaticKeyResolver([key])

    assert resolve(resolver) == (key,)


def test_static_key_resolver_does_not_use_network_fetch_or_discovery():
    def fail(*args, **kwargs):
        raise AssertionError("network or discovery callback should not be used")

    resolver = StaticKeyResolver([LocalKey("key-1")])
    context = {
        "fetch": fail,
        "discover": fail,
        "refresh": fail,
    }

    assert resolve(resolver, context=context) == (LocalKey("key-1"),)
