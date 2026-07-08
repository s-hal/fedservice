"""Tests for deterministic Federation JWT key resolvers."""

import pytest
from idpyoidc.message import Message

from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.key_resolver import KeyJarResolver
from fedservice.federation_jwt.key_resolver import KeyResolver
from fedservice.federation_jwt.key_resolver import StaticKeyResolver
from fedservice.federation_jwt.profile import FederationJwtProfile


class FakeKeyJar:
    def __init__(self, keys=None, error=None):
        self.keys = keys
        self.error = error
        self.calls = []

    def get_jwt_verify_keys(self, parsed_jwt):
        self.calls.append(parsed_jwt)
        if self.error is not None:
            raise self.error
        return self.keys


def make_profile():
    return FederationJwtProfile(
        name="entity_configuration",
        typ="entity-statement+jwt",
        content_type="application/entity-statement+jwt",
        message_cls=Message,
    )


def resolve(
    resolver,
    protected_header=None,
    untrusted_payload=None,
    parsed_jwt=None,
    context=None,
):
    if protected_header is None:
        protected_header = {"kid": "key-1"}
    if untrusted_payload is None:
        untrusted_payload = {"iss": "issuer"}
    if parsed_jwt is None:
        parsed_jwt = object()

    return resolver.resolve(
        profile=make_profile(),
        protected_header=protected_header,
        untrusted_payload=untrusted_payload,
        parsed_jwt=parsed_jwt,
        context=context,
    )


def test_key_resolver_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        KeyResolver()


def test_keyjar_resolver_delegates_to_get_jwt_verify_keys():
    parsed_jwt = object()
    keyjar = FakeKeyJar(keys=["key-1"])
    resolver = KeyJarResolver(keyjar)

    assert resolve(resolver, parsed_jwt=parsed_jwt) == ("key-1",)
    assert keyjar.calls == [parsed_jwt]


def test_static_key_resolver_is_keyjar_backed():
    parsed_jwt = object()
    keyjar = FakeKeyJar(keys=["key-1"])
    resolver = StaticKeyResolver(keyjar)

    assert resolve(resolver, parsed_jwt=parsed_jwt) == ("key-1",)
    assert keyjar.calls == [parsed_jwt]


def test_keyjar_resolver_output_is_tuple():
    resolver = KeyJarResolver(FakeKeyJar(keys=["key-1"]))

    assert isinstance(resolve(resolver), tuple)


def test_keyjar_resolver_preserves_framework_key_order():
    keys = ["first", "second", "third"]
    resolver = KeyJarResolver(FakeKeyJar(keys=keys))

    assert resolve(resolver) == ("first", "second", "third")


@pytest.mark.parametrize("framework_result", [None, [], ()])
def test_keyjar_resolver_empty_framework_result_returns_empty_tuple(framework_result):
    resolver = KeyJarResolver(FakeKeyJar(keys=framework_result))

    assert resolve(resolver) == ()


def test_keyjar_resolver_translates_lookup_failures():
    resolver = KeyJarResolver(FakeKeyJar(error=RuntimeError("lookup failed")))

    with pytest.raises(FederationJwtKeyResolutionError):
        resolve(resolver)


def test_keyjar_resolver_does_not_mutate_inputs_or_keyjar():
    keyjar = FakeKeyJar(keys=["key-1"])
    resolver = KeyJarResolver(keyjar)
    protected_header = {"kid": "mismatched-local-kid"}
    untrusted_payload = {"iss": "issuer", "jwks": {"keys": []}}
    context = {"trust_anchor": "anchor"}
    profile = make_profile()
    parsed_jwt = object()

    result = resolver.resolve(
        profile=profile,
        protected_header=protected_header,
        untrusted_payload=untrusted_payload,
        parsed_jwt=parsed_jwt,
        context=context,
    )

    assert result == ("key-1",)
    assert protected_header == {"kid": "mismatched-local-kid"}
    assert untrusted_payload == {"iss": "issuer", "jwks": {"keys": []}}
    assert context == {"trust_anchor": "anchor"}
    assert profile == make_profile()
    assert keyjar.keys == ["key-1"]
    assert keyjar.calls == [parsed_jwt]


def test_keyjar_resolver_does_not_perform_network_fetch_or_discovery():
    def fail(*args, **kwargs):
        raise AssertionError("network or discovery callback should not be used")

    keyjar = FakeKeyJar(keys=["key-1"])
    resolver = KeyJarResolver(keyjar)
    context = {
        "fetch": fail,
        "discover": fail,
        "refresh": fail,
    }

    assert resolve(resolver, context=context) == ("key-1",)


def test_manual_protected_header_kid_mismatch_does_not_filter_framework_keys():
    keyjar = FakeKeyJar(keys=["framework-key"])
    resolver = KeyJarResolver(keyjar)

    result = resolve(
        resolver,
        protected_header={"kid": "local-kid-that-does-not-match"},
    )

    assert result == ("framework-key",)
