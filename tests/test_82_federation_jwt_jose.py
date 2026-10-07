"""Tests for the Federation JWT JOSE policy boundary."""

import base64
from copy import deepcopy
import json
from dataclasses import replace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import JWT
from idpyoidc.message import Message
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message.oidc import deserialize_from_one_of
from idpyoidc.message.oidc import SINGLE_OPTIONAL_STRING
import pytest

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import validate_protected_header
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.federation_jwt import registry
from fedservice.federation_jwt.verified import VerifiedFederationJwt
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.exception import ConstraintError
from fedservice.exception import MetadataPolicyCritError
from fedservice.exception import UnknownCriticalExtension
from fedservice.message import Metadata
from fedservice.message import MetadataPolicy
from fedservice.message import Constraints
from fedservice.message import NamingConstraints
from fedservice.message import Policy
from fedservice.message import SubordinateStatement


NOW = 1700000000
ISSUER = "https://issuer.example.org"
SUBJECT = "https://subject.example.org"
DEFAULT_CRYPTOJWT_SKEW = JWT().skew


@pytest.fixture()
def signing_key():
    return new_rsa_key(kid="key-1")


def keyjar_for(key):
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [key])
    return key_jar


def header(token):
    parsed = jws_factory(token)
    assert parsed is not None
    return dict(parsed.jwt.headers)


def compact_token(protected_header, payload=None, signature=b"signature"):
    if payload is None:
        payload = {"iss": ISSUER, "sub": SUBJECT, "iat": NOW}

    def encode(value):
        if not isinstance(value, bytes):
            value = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    return ".".join((encode(protected_header), encode(payload), encode(signature)))


def replace_protected_header(token, remove=None, **updates):
    parts = token.split(".")
    protected_header = header(token)
    if remove is not None:
        protected_header.pop(remove)
    protected_header.update(updates)
    encoded = base64.urlsafe_b64encode(
        json.dumps(protected_header, separators=(",", ":")).encode("utf-8")
    )
    parts[0] = encoded.decode("ascii").rstrip("=")
    return ".".join(parts)


def payload_for(profile, signing_key):
    common = {"iss": ISSUER, "iat": NOW - 10}
    payloads = {
        registry.ENTITY_CONFIGURATION.name: dict(
            common,
            sub=ISSUER,
            exp=NOW + 600,
            jwks={"keys": [signing_key.serialize(private=False)]},
            metadata={"federation_entity": {}},
        ),
        registry.SUBORDINATE_STATEMENT.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            jwks={"keys": []},
        ),
        registry.RESOLVE_RESPONSE.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            metadata={"federation_entity": {}},
            trust_chain=["header.payload.signature"],
        ),
        registry.TRUST_MARK.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            trust_mark_type="https://marks.example.org/assured",
        ),
        registry.TRUST_MARK_DELEGATION.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            trust_mark_type="https://marks.example.org/assured",
        ),
        registry.TRUST_MARK_STATUS_RESPONSE.name: dict(
            common,
            trust_mark="header.payload.signature",
            status="active",
        ),
        registry.SIGNED_JWK_SET.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            keys=[{"kty": "RSA", "kid": "historical-key"}],
        ),
        registry.HISTORICAL_KEYS_RESPONSE.name: dict(
            common,
            jwks={"keys": []},
        ),
        registry.EXPLICIT_REGISTRATION_RESPONSE.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            aud=SUBJECT,
            trust_anchor="https://ta.example.org",
            authority_hints=["https://superior.example.org"],
            metadata={
                "oauth_client": {
                    "client_id": "client-id",
                    "redirect_uris": ["https://client.example.org/cb"],
                }
            },
        ),
    }
    return payloads[profile.name]


def sign(profile, key, payload=None, **kwargs):
    if payload is None:
        payload = payload_for(profile, key)
    return sign_federation_jwt(
        profile=profile,
        payload=payload,
        key_jar=keyjar_for(key),
        issuer=ISSUER,
        alg="RS256",
        kid=key.kid,
        iat=payload.get("iat"),
        **kwargs
    )


@pytest.fixture(scope="module")
def container_signing_key():
    return new_rsa_key(kid="container-key")


@pytest.mark.parametrize("policy", [
    [], [None], None, {},
    '{"federation_entity": {"organization_name": {"value": "Name"}}}',
    {"federation_entity": []}, {"federation_entity": {}},
    {"federation_entity": '{"organization_name": {"value": "Name"}}'},
    {"federation_entity": [], "https://example.org/type": {"name": {"value": "Name"}}},
    {"federation_entity": {"name": "", "valid": {"value": "Name"}}},
    {"federation_entity": {"name": [""]}},
    {"federation_entity": {"name": {}}},
    {"federation_entity": {"name": '{"value": "Name"}'}},
    {"https://example.org/type": None}, {"https://example.org/type": [None]},
    {"https://example.org/type": {}}, {"https://example.org/type": {"name": None}},
    {"https://example.org/type": {"name": {}}},
])
def test_signed_subordinate_rejects_original_policy_containers(policy, container_signing_key):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    payload["metadata_policy"] = policy
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert type(error.value.__cause__) is ValueError
    assert "metadata_policy" in str(error.value.__cause__)
    assert "nonempty JSON object" in str(error.value.__cause__)


def test_signed_subordinate_preserves_policy_operands_and_extensions(container_signing_key):
    policy = {"federation_entity": {
        "organization_name#sv": {"value": ""}, "extra": {"custom": ""},
        "remove": {"value": None}, "empty": {"value": []},
    }, "https://example.org/type": {
        "flag": {"value": False}, "zero": {"value": 0},
        "nested": {"value": [None, {"nested": [], "items": [None, False, 0]}]},
    }}
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    payload["metadata_policy"] = policy
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    assert verified.claims() == deep_freeze(payload)
    assert verified.message()["metadata_policy"].to_dict() == policy


@pytest.mark.parametrize("malformed,error_type,error_text", [
    ({"metadata_policy": {"federation_entity": {
        "organization_name": {"add": "not-an-array", "essential": False},
    }}}, ValueError, "add"),
    ({"metadata_policy_crit": ""}, MetadataPolicyCritError, "metadata_policy_crit"),
    ({"metadata_policy_crit": [""]}, MetadataPolicyCritError, "metadata_policy_crit"),
])
def test_signed_subordinate_rejects_original_malformed_policy_values(
        malformed, error_type, error_text, container_signing_key):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    payload.update(deepcopy(malformed))
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, error_type)
    assert error_text in str(error.value.__cause__)


def test_signed_subordinate_accepts_valid_policy_domain_control(container_signing_key):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    payload["metadata_policy"] = {"federation_entity": {
        "organization_name": {"add": [], "essential": False},
        "remove": {"value": None},
        "nested": {"value": ["", 0, 1.5, ["array"], {"object": []}]},
        "extension": {"custom": ""},
    }}
    token = sign(profile, container_signing_key, payload)
    verified = verify_federation_jwt(
        profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.claims() == deep_freeze(payload)


def _local_policy_profile(list_deserializer):
    class LocalPolicy(Policy):
        c_param = Policy.c_param.copy()

    policy_spec = list(LocalPolicy.c_param["subset_of"])
    policy_spec[3] = list_deserializer
    LocalPolicy.c_param["subset_of"] = tuple(policy_spec)

    def local_policy_deserializer(value, *, sformat):
        return deserialize_from_one_of(value, LocalPolicy, sformat)

    class LocalParameters(Message):
        c_param = {
            "*": (Message, False, None, local_policy_deserializer, False),
        }

    def local_parameters_deserializer(value, *, sformat):
        return deserialize_from_one_of(value, LocalParameters, sformat)

    class LocalMetadataPolicy(MetadataPolicy):
        c_param = MetadataPolicy.c_param.copy()

    metadata_spec = list(LocalMetadataPolicy.c_param["federation_entity"])
    metadata_spec[3] = local_parameters_deserializer
    LocalMetadataPolicy.c_param["federation_entity"] = tuple(metadata_spec)

    def local_metadata_policy_deserializer(value, *, sformat):
        return deserialize_from_one_of(value, LocalMetadataPolicy, sformat)

    class LocalSubordinateStatement(SubordinateStatement):
        c_param = SubordinateStatement.c_param.copy()

    statement_spec = list(LocalSubordinateStatement.c_param["metadata_policy"])
    statement_spec[3] = local_metadata_policy_deserializer
    LocalSubordinateStatement.c_param["metadata_policy"] = tuple(statement_spec)
    return replace(registry.SUBORDINATE_STATEMENT, message_cls=LocalSubordinateStatement)


def test_signed_subordinate_uses_local_policy_list_deserializer_rejection(
        container_signing_key):
    def rejecting_deserializer(value, *, sformat):
        assert value == ["original"]
        assert sformat == "dict"
        raise ValueError("signed local list deserializer rejected input")

    profile = _local_policy_profile(rejecting_deserializer)
    payload = payload_for(registry.SUBORDINATE_STATEMENT, container_signing_key)
    payload["metadata_policy"] = {"federation_entity": {
        "contacts": {"subset_of": ["original"]},
    }}
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload

    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert "signed local list deserializer rejected input" in str(error.value.__cause__)


def test_signed_subordinate_preserves_local_policy_list_deserializer_result(
        container_signing_key):
    seen = []

    def accepting_deserializer(value, *, sformat):
        seen.append((deepcopy(value), sformat))
        return value + ["accepted"]

    profile = _local_policy_profile(accepting_deserializer)
    payload = payload_for(registry.SUBORDINATE_STATEMENT, container_signing_key)
    payload["metadata_policy"] = {"federation_entity": {
        "contacts": {"subset_of": ["original"]},
    }}
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload

    verified = verify_federation_jwt(
        profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    assert verified.claims() == deep_freeze(payload)
    assert verified.message()["metadata_policy"]["federation_entity"]["contacts"][
        "subset_of"] == ["original", "accepted"]
    assert seen == [(["original"], "dict")]


@pytest.mark.parametrize("constraints,error_text", [
    ([], "constraints"),
    ({"max_path_length": "1", "allowed_entity_types": []}, "max_path_length"),
    ({"allowed_entity_types": "oauth_client", "max_path_length": 0},
     "allowed_entity_types"),
    ({"naming_constraints": []}, "naming_constraints"),
    ({"naming_constraints": {"permitted": ".example.org"}}, "permitted"),
])
def test_signed_subordinate_rejects_original_malformed_constraints(
        constraints, error_text, container_signing_key):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    payload["constraints"] = deepcopy(constraints)
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ConstraintError)
    assert error_text in str(error.value.__cause__)


def test_signed_subordinate_accepts_valid_constraint_domain_control(container_signing_key):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    payload["constraints"] = {
        "max_path_length": 0,
        "allowed_entity_types": [],
        "naming_constraints": {"permitted": [], "excluded": []},
        "custom": {"nested": None},
    }
    token = sign(profile, container_signing_key, payload)
    verified = verify_federation_jwt(
        profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.claims() == deep_freeze(payload)


def _local_constraint_list_profile(field, list_deserializer):
    class LocalNamingConstraints(NamingConstraints):
        c_param = NamingConstraints.c_param.copy()

    class LocalConstraints(Constraints):
        c_param = Constraints.c_param.copy()

    if field == "allowed_entity_types":
        field_spec = list(LocalConstraints.c_param[field])
        field_spec[3] = list_deserializer
        LocalConstraints.c_param[field] = tuple(field_spec)
    else:
        field_spec = list(LocalNamingConstraints.c_param[field])
        field_spec[3] = list_deserializer
        LocalNamingConstraints.c_param[field] = tuple(field_spec)

    def local_naming_deserializer(value, *, sformat):
        return deserialize_from_one_of(value, LocalNamingConstraints, sformat)

    naming_spec = list(LocalConstraints.c_param["naming_constraints"])
    naming_spec[3] = local_naming_deserializer
    LocalConstraints.c_param["naming_constraints"] = tuple(naming_spec)

    def local_constraints_deserializer(value, *, sformat):
        return deserialize_from_one_of(value, LocalConstraints, sformat)

    class LocalSubordinateStatement(SubordinateStatement):
        c_param = SubordinateStatement.c_param.copy()

    constraint_spec = list(LocalSubordinateStatement.c_param["constraints"])
    constraint_spec[3] = local_constraints_deserializer
    LocalSubordinateStatement.c_param["constraints"] = tuple(constraint_spec)
    return replace(registry.SUBORDINATE_STATEMENT, message_cls=LocalSubordinateStatement)


def _constraint_payload(field, value, signing_key):
    payload = payload_for(registry.SUBORDINATE_STATEMENT, signing_key)
    if field == "allowed_entity_types":
        payload["constraints"] = {field: value}
    else:
        payload["constraints"] = {"naming_constraints": {field: value}}
    return payload


@pytest.mark.parametrize("field", ["permitted", "allowed_entity_types"])
def test_signed_subordinate_uses_local_constraint_list_deserializer_rejection(
        field, container_signing_key):
    def rejecting_deserializer(value, *, sformat):
        assert value == ["original.example.org"]
        assert sformat == "dict"
        raise ValueError("signed local constraint list deserializer rejected input")

    profile = _local_constraint_list_profile(field, rejecting_deserializer)
    payload = _constraint_payload(field, ["original.example.org"], container_signing_key)
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload

    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert "signed local constraint list deserializer rejected input" in str(error.value.__cause__)


@pytest.mark.parametrize("field", ["permitted", "allowed_entity_types"])
def test_signed_subordinate_preserves_local_constraint_list_deserializer_result(
        field, container_signing_key):
    seen = []
    appended = "oauth_client" if field == "allowed_entity_types" else "accepted.example.org"

    def accepting_deserializer(value, *, sformat):
        seen.append((deepcopy(value), sformat))
        return value + [appended]

    profile = _local_constraint_list_profile(field, accepting_deserializer)
    payload = _constraint_payload(field, ["original.example.org"], container_signing_key)
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload

    verified = verify_federation_jwt(
        profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    assert verified.claims() == deep_freeze(payload)
    constraints = verified.message()["constraints"]
    parsed = (constraints[field] if field == "allowed_entity_types"
              else constraints["naming_constraints"][field])
    assert parsed == ["original.example.org", appended]
    assert seen == [(["original.example.org"], "dict")]


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("metadata", [
    None, [], [None], '{"federation_entity": {}}',
    {"federation_entity": []}, {"federation_entity": None},
    {"federation_entity": '{"organization_name": "Name"}'},
    {"federation_entity": {"organization_name": None}},
    {"federation_entity": {"extension": None}},
    {"federation_entity": {"organization_name#sv": None}},
    {"federation_entity": {"contacts": None}},
    {"https://example.org/type": []}, {"https://example.org/type": [None]},
    {"https://example.org/type": "{}"}, {"https://example.org/type": None},
    {"https://example.org/type": {"extension": None}},
])
def test_signed_statement_metadata_rejects_original_representation(
        profile, metadata, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload["metadata"] = deepcopy(metadata)
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert "metadata" in str(error.value.__cause__)
    if isinstance(metadata, dict):
        for entity_type in metadata:
            assert entity_type in str(error.value.__cause__)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("mode", ["omitted", "empty", "typed"])
def test_signed_statement_metadata_preserves_valid_objects(profile, mode, container_signing_key):
    extensions = {"text": "Name", "empty_text": "", "number": 0, "flag": False,
                  "array": [1, "two"], "empty_array": [], "empty_item": [""],
                  "object": {"nested": None, "items": [None, False, 0]}}
    metadata = {"federation_entity": extensions, "https://example.org/type": extensions,
                "openid_provider": {"organization_name": "Partial OP"},
                "oauth_client": {}, "https://example.org/empty": {}}
    payload = payload_for(profile, container_signing_key)
    payload.pop("metadata", None)
    if mode != "omitted":
        payload["metadata"] = {} if mode == "empty" else metadata
    before = deepcopy(payload)
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    assert jws_factory(token).jwt.payload() == payload
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    assert verified.claims() == deep_freeze(payload)
    view = verified.message()
    if mode == "omitted":
        assert "metadata" not in view
    else:
        assert set(view["metadata"].keys()) == set(payload["metadata"])
        projected = view["metadata"].to_dict()
        for entity_type, parameters in payload["metadata"].items():
            for name, value in parameters.items():
                assert projected[entity_type][name] == value
        with pytest.raises(TypeError):
            verified.claims()["metadata"]["new_type"] = {}
    if mode == "typed":
        with pytest.raises(TypeError):
            verified.claims()["metadata"]["federation_entity"]["object"]["nested"] = "changed"
    assert payload == before


def _local_metadata_fallback_profile(base_profile, claim, fallback_deserializer):
    outer_base = Metadata if claim == "metadata" else MetadataPolicy

    class LocalOuter(outer_base):
        c_param = outer_base.c_param.copy()
        c_param["*"] = (Message, False, None, fallback_deserializer, False)

    def outer_deserializer(value, *, sformat):
        return deserialize_from_one_of(value, LocalOuter, sformat)

    statement_base = base_profile.message_cls

    class LocalStatement(statement_base):
        c_param = statement_base.c_param.copy()

    spec = list(LocalStatement.c_param[claim])
    spec[3] = outer_deserializer
    LocalStatement.c_param[claim] = tuple(spec)
    return replace(base_profile, message_cls=LocalStatement)


@pytest.mark.parametrize("base_profile,claim", [
    (registry.ENTITY_CONFIGURATION, "metadata"),
    (registry.SUBORDINATE_STATEMENT, "metadata"),
    (registry.SUBORDINATE_STATEMENT, "metadata_policy"),
])
def test_signed_metadata_fallback_deserializer_rejection_is_effective(
        base_profile, claim, container_signing_key):
    seen = []

    def rejecting_deserializer(value, *, sformat):
        seen.append((deepcopy(value), sformat))
        raise ValueError("signed metadata fallback rejected input")

    profile = _local_metadata_fallback_profile(
        base_profile, claim, rejecting_deserializer)
    payload = payload_for(base_profile, container_signing_key)
    value = ({"name": "original"} if claim == "metadata"
             else {"name": {"value": "original"}})
    payload[claim] = {"https://example.org/type": value}
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert "signed metadata fallback rejected input" in str(error.value.__cause__)
    assert seen == [(value, "dict")]


@pytest.mark.parametrize("base_profile,claim", [
    (registry.ENTITY_CONFIGURATION, "metadata"),
    (registry.SUBORDINATE_STATEMENT, "metadata"),
    (registry.SUBORDINATE_STATEMENT, "metadata_policy"),
])
def test_signed_metadata_fallback_deserializer_preserves_typed_result(
        base_profile, claim, container_signing_key):
    seen = []

    class LocalEntityType(Message):
        pass

    def accepting_deserializer(value, *, sformat):
        seen.append((deepcopy(value), sformat))
        parsed = deserialize_from_one_of(value, LocalEntityType, sformat)
        parsed["callback_marker"] = (
            {"value": "accepted"} if claim == "metadata_policy" else "accepted"
        )
        return parsed

    profile = _local_metadata_fallback_profile(
        base_profile, claim, accepting_deserializer)
    payload = payload_for(base_profile, container_signing_key)
    value = ({"name": "original", "items": [], "nested": {"flag": False}}
             if claim == "metadata" else {"name": {"value": "original"}})
    payload[claim] = {"https://example.org/type": value}
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    verified = verify_federation_jwt(
        profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    assert verified.claims() == deep_freeze(payload)
    nested = verified.message()[claim]["https://example.org/type"]
    assert isinstance(nested, LocalEntityType)
    marker = {"value": "accepted"} if claim == "metadata_policy" else "accepted"
    assert nested["callback_marker"] == marker
    assert seen == [(value, "dict")]


@pytest.mark.parametrize("profile,field", [
    (registry.ENTITY_CONFIGURATION, "iss"),
    (registry.SUBORDINATE_STATEMENT, "iss"),
    (registry.SUBORDINATE_STATEMENT, "sub"),
])
@pytest.mark.parametrize("identifier", [
    "not-an-entity-id", "http://issuer.example.org", "https://issuer.example.org?q=1",
    "https:///path", "https://issuer.example.org?", "https://issuer.example.org#",
    "https://issuer.example.org/#fragment", " https://issuer.example.org",
    "https://iss\nuer.example.org", "https://issuer.example.org/\x00",
    "https://user@@example.org", "https://example.org/path[part]",
    "https://example.org/path[part", "https://example.org/path]part",
])
def test_signed_entity_identifiers_reject_at_schema(profile, field, identifier, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload[field] = identifier
    if profile is registry.ENTITY_CONFIGURATION:
        payload["sub"] = identifier
    keys = KeyJar()
    keys.add_keys(payload["iss"], [container_signing_key])
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keys, now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert field in str(error.value.__cause__)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("identifier", [
    "https://example.org", "https://Example.org:8443/path", "https://example.org/a%2Fb%3Fc%23d",
    "https://Example.org:8443/a@b:c;d=1", "https://example.org/path%5Bpart%5D",
    "https://[2001:db8::1]:8443/a%2Fb%3Fc%23d", "https://user@example.org/a@b",
])
def test_signed_entity_identifiers_preserve_exact_strings(profile, identifier, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload["iss"] = identifier
    if profile is registry.ENTITY_CONFIGURATION:
        payload["sub"] = identifier
    keys = KeyJar()
    keys.add_keys(identifier, [container_signing_key])
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    verified = verify_federation_jwt(profile, token, keys, now=NOW)
    assert verified.claims()["iss"] == verified.message()["iss"] == identifier
    assert verified.claims()["sub"] == verified.message()["sub"] == payload["sub"]
    assert verified.raw_token() == token


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints"])
@pytest.mark.parametrize("identifier", [
    "https://user@@example.org", "https://example.org/path[part]",
    "https://example.org/path[part", "https://example.org/path]part",
])
def test_signed_ec_hint_rejects_malformed_authority_or_path(claim, identifier, container_signing_key):
    profile = registry.ENTITY_CONFIGURATION
    payload = payload_for(profile, container_signing_key)
    payload[claim] = [identifier]
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert claim in str(error.value.__cause__)


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints"])
@pytest.mark.parametrize("value", [
    [], ISSUER, None, {}, 12, False, "", [""], [None],
    [12, ISSUER], [ISSUER, 12], [ISSUER, ""], ["bad", ISSUER],
    [ISSUER, "http://invalid.example.org"], [ISSUER + "?"], [ISSUER + "#"],
])
def test_signed_ec_rejects_original_hint_representation(claim, value, container_signing_key):
    profile = registry.ENTITY_CONFIGURATION
    payload = payload_for(profile, container_signing_key)
    payload[claim] = value
    token = sign(profile, container_signing_key, payload)
    decoded = jws_factory(token).jwt.payload()
    assert claim in decoded and decoded[claim] == value
    assert type(decoded[claim]) is type(value)
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert claim in str(error.value.__cause__)


@pytest.mark.parametrize("claims", [(), ("authority_hints",), ("trust_anchor_hints",),
                                    ("authority_hints", "trust_anchor_hints")])
@pytest.mark.parametrize("hints", [["https://ta.example.org"],
                                    ["https://example.org", "https://Example.org:8443/a@b:c;d=1",
                                     "https://example.org/path%5Bpart%5D",
                                     "https://[2001:db8::1]:8443/a%2Fb%3Fc%23d"],
                                    ["https://Ta.example.org:8443/a%2Fb", ISSUER,
                                     "https://Ta.example.org:8443/a%2Fb"]])
def test_signed_ec_hint_presence_and_exact_order(claims, hints, container_signing_key):
    profile = registry.ENTITY_CONFIGURATION
    payload = payload_for(profile, container_signing_key)
    payload.update({claim: hints for claim in claims})
    token = sign(profile, container_signing_key, payload)
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    for claim in ("authority_hints", "trust_anchor_hints"):
        if claim in claims:
            assert verified.claims()[claim] == tuple(hints)
            assert verified.message()[claim] == hints
        else:
            assert claim not in verified.claims()
            assert claim not in verified.message()


def _local_statement_list_profile(base_profile, claim, list_deserializer,
                                  supported_crit=False):
    base = base_profile.message_cls

    class LocalStatement(base):
        c_param = base.c_param.copy()

        def verify(self, **kwargs):
            if supported_crit:
                known = list(kwargs.get("known_extensions") or ())
                known.extend(["extension", "accepted_extension"])
                kwargs["known_extensions"] = known
            result = super().verify(**kwargs)
            if supported_crit:
                if self["extension"] != "supported":
                    raise ValueError("Unsupported extension value")
                if self.get("accepted_extension") != "accepted":
                    raise ValueError("Unsupported accepted extension value")
            return result

    spec = list(LocalStatement.c_param[claim])
    spec[3] = list_deserializer
    LocalStatement.c_param[claim] = tuple(spec)
    return replace(base_profile, message_cls=LocalStatement)


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints"])
def test_signed_ec_hint_uses_local_list_deserializer_rejection(
        claim, container_signing_key):
    def rejecting_deserializer(value, *, sformat):
        assert value == ["https://superior.example.org"]
        assert sformat == "dict"
        raise ValueError("signed EC hint deserializer rejected input")

    profile = _local_statement_list_profile(
        registry.ENTITY_CONFIGURATION, claim, rejecting_deserializer)
    payload = payload_for(registry.ENTITY_CONFIGURATION, container_signing_key)
    payload[claim] = ["https://superior.example.org"]
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert "signed EC hint deserializer rejected input" in str(error.value.__cause__)


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints"])
def test_signed_ec_hint_preserves_local_list_deserializer_result(
        claim, container_signing_key):
    seen = []

    def accepting_deserializer(value, *, sformat):
        seen.append((deepcopy(value), sformat))
        return value + ["https://accepted.example.org"]

    profile = _local_statement_list_profile(
        registry.ENTITY_CONFIGURATION, claim, accepting_deserializer)
    payload = payload_for(registry.ENTITY_CONFIGURATION, container_signing_key)
    payload[claim] = ["https://superior.example.org"]
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    verified = verify_federation_jwt(
        profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    assert verified.claims() == deep_freeze(payload)
    assert verified.message()[claim] == [
        "https://superior.example.org", "https://accepted.example.org",
    ]
    assert seen == [(["https://superior.example.org"], "dict")]


@pytest.mark.parametrize(
    "base_profile",
    [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT],
)
def test_signed_statement_crit_uses_local_list_deserializer_rejection(
        base_profile, container_signing_key):
    def rejecting_deserializer(value, *, sformat):
        assert value == ["extension"]
        assert sformat == "dict"
        raise ValueError("signed statement crit deserializer rejected input")

    profile = _local_statement_list_profile(
        base_profile, "crit", rejecting_deserializer, supported_crit=True)
    payload = payload_for(base_profile, container_signing_key)
    payload.update(extension="supported", crit=["extension"])
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert "signed statement crit deserializer rejected input" in str(error.value.__cause__)


@pytest.mark.parametrize(
    "base_profile",
    [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT],
)
def test_signed_statement_crit_preserves_local_list_deserializer_result(
        base_profile, container_signing_key):
    seen = []

    def accepting_deserializer(value, *, sformat):
        seen.append((deepcopy(value), sformat))
        return value + ["accepted_extension"]

    profile = _local_statement_list_profile(
        base_profile, "crit", accepting_deserializer, supported_crit=True)
    payload = payload_for(base_profile, container_signing_key)
    payload.update(
        extension="supported",
        accepted_extension="accepted",
        crit=["extension"],
    )
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    verified = verify_federation_jwt(
        profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    assert verified.claims() == deep_freeze(payload)
    assert verified.message()["crit"] == ["extension", "accepted_extension"]
    assert seen == [(["extension"], "dict")]


@pytest.mark.parametrize("rejecting", [False, True])
def test_signed_unsupported_policy_crit_rejected_before_construction(
        rejecting, container_signing_key):
    seen = []

    def deserializer(value, *, sformat):
        seen.append("callback")
        if rejecting:
            raise ValueError("signed metadata policy crit deserializer rejected input")
        return value

    profile = _local_statement_list_profile(
        registry.SUBORDINATE_STATEMENT, "metadata_policy_crit", deserializer)

    class ObservedStatement(profile.message_cls):
        def __init__(self, **kwargs):
            seen.append("constructor")
            super().__init__(**kwargs)

        def from_dict(self, values, **kwargs):
            seen.append("deserialize")
            return super().from_dict(values, **kwargs)

        def verify(self, **kwargs):
            seen.append("verify")
            return super().verify(**kwargs)

    profile = replace(profile, message_cls=ObservedStatement)
    payload = payload_for(registry.SUBORDINATE_STATEMENT, container_signing_key)
    payload["metadata_policy_crit"] = ["regexp"]
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, MetadataPolicyCritError)
    assert str(error.value.__cause__) == "Unsupported critical metadata policy operator"
    assert seen == []


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("critical", [None, [], "extension", {}, [12], [""],
                                       ["extension", "extension"], ["missing"],
                                       ["extension", "missing"], ["iss"], ["jwks"],
                                       ["authority_hints"], ["trust_anchor_hints"], ["metadata_policy"]])
@pytest.mark.parametrize("with_extra", [False, True])
def test_signed_payload_crit_rejects_invalid_declarations(
        profile, critical, with_extra, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload["crit"] = critical
    if with_extra:
        payload["extension"] = ""
    token = sign(profile, container_signing_key, payload)
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert "crit" in str(error.value.__cause__)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("value", ["", [""], None, False, 0, [], {}, "present"])
def test_signed_unsupported_critical_extension_and_noncritical_control(
        profile, value, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload["extension"] = value
    token = sign(profile, container_signing_key, payload)
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    payload["crit"] = ["extension"]
    token = sign(profile, container_signing_key, payload)
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, UnknownCriticalExtension)


@pytest.mark.parametrize(
    "base_profile",
    [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT],
)
@pytest.mark.parametrize("value", ["supported", ""])
def test_signed_schema_subclass_accepts_supported_critical_extension(
        base_profile, value, container_signing_key):
    seen = []

    class LocalMessage(base_profile.message_cls):
        c_param = base_profile.message_cls.c_param.copy()
        c_param["local_claim"] = SINGLE_OPTIONAL_STRING

        def verify(self, **kwargs):
            known = list(kwargs.get("known_extensions") or ())
            known.append("local_claim")
            kwargs["known_extensions"] = known
            result = super().verify(**kwargs)
            seen.append(self["local_claim"])
            if self["local_claim"] not in ("supported", ""):
                raise ValueError("Unsupported local claim value")
            return result

    assert "local_claim" not in base_profile.message_cls.c_param
    profile = replace(base_profile, message_cls=LocalMessage)
    payload = payload_for(base_profile, container_signing_key)
    payload.update(local_claim=value, crit=["local_claim"])
    token = sign(profile, container_signing_key, payload)
    assert jws_factory(token).jwt.payload() == payload

    verified = verify_federation_jwt(
        profile,
        token,
        keyjar_for(container_signing_key),
        now=NOW,
    )

    assert seen == [value]
    assert verified.raw_token() == token
    assert verified.claims()["local_claim"] == value
    assert verified.message()["local_claim"] == value
    assert "local_claim" not in base_profile.message_cls.c_param


def _local_list_extension_profile(base_profile, deserializer=None, accept=True):
    base = base_profile.message_cls
    seen = []

    class LocalMessage(base):
        c_param = base.c_param.copy()
        spec = list(OPTIONAL_LIST_OF_STRINGS)
        if deserializer is not None:
            spec[3] = deserializer
        c_param["local_claim"] = tuple(spec)

        def verify(self, **kwargs):
            if accept:
                known = list(kwargs.get("known_extensions") or ())
                known.append("local_claim")
                kwargs["known_extensions"] = known
            result = super().verify(**kwargs)
            seen.append(deepcopy(self["local_claim"]))
            if not isinstance(self["local_claim"], list) or not all(
                    isinstance(item, str) for item in self["local_claim"]):
                raise ValueError("Unsupported local list value")
            return result

    return replace(base_profile, message_cls=LocalMessage), seen


@pytest.mark.parametrize(
    "base_profile",
    [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT],
)
@pytest.mark.parametrize("value", [[], ["original"]])
def test_signed_schema_subclass_accepts_supported_list_critical_extension(
        base_profile, value, container_signing_key):
    callbacks = []

    def local_deserializer(items, *, sformat):
        callbacks.append((deepcopy(items), sformat))
        return items

    profile, validated = _local_list_extension_profile(
        base_profile, deserializer=local_deserializer)
    payload = payload_for(base_profile, container_signing_key)
    payload.update(local_claim=deepcopy(value), crit=["local_claim"])
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload

    verified = verify_federation_jwt(
        profile, token, keyjar_for(container_signing_key), now=NOW)
    assert callbacks == [(value, "dict")]
    assert validated == [value]
    assert verified.raw_token() == token
    assert verified.claims() == deep_freeze(payload)
    assert verified.message()["local_claim"] == value
    assert "local_claim" not in base_profile.message_cls.c_param


@pytest.mark.parametrize(
    "base_profile",
    [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT],
)
def test_signed_empty_array_extension_honors_rejecting_deserializer(
        base_profile, container_signing_key):
    def rejecting_deserializer(items, *, sformat):
        assert items == []
        assert sformat == "dict"
        raise ValueError("signed empty array deserializer rejected input")

    profile, _ = _local_list_extension_profile(
        base_profile, deserializer=rejecting_deserializer)
    payload = payload_for(base_profile, container_signing_key)
    payload.update(local_claim=[], crit=["local_claim"])
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert "signed empty array deserializer rejected input" in str(error.value.__cause__)


@pytest.mark.parametrize(
    "base_profile",
    [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT],
)
def test_signed_empty_array_schema_field_does_not_imply_critical_support(
        base_profile, container_signing_key):
    profile, _ = _local_list_extension_profile(base_profile, accept=False)
    payload = payload_for(base_profile, container_signing_key)
    payload.update(local_claim=[], crit=["local_claim"])
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, UnknownCriticalExtension)


@pytest.mark.parametrize(
    "base_profile",
    [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT],
)
def test_signed_schema_subclass_rejects_critical_extension_value(
        base_profile, container_signing_key):
    class LocalMessage(base_profile.message_cls):
        c_param = base_profile.message_cls.c_param.copy()
        c_param["local_claim"] = SINGLE_OPTIONAL_STRING

        def verify(self, **kwargs):
            known = list(kwargs.get("known_extensions") or ())
            known.append("local_claim")
            kwargs["known_extensions"] = known
            super().verify(**kwargs)
            raise ValueError("Unsupported local claim value")

    profile = replace(base_profile, message_cls=LocalMessage)
    payload = payload_for(base_profile, container_signing_key)
    payload.update(local_claim="rejected", crit=["local_claim"])
    token = sign(profile, container_signing_key, payload)

    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(
            profile,
            token,
            keyjar_for(container_signing_key),
            now=NOW,
        )
    assert isinstance(error.value.__cause__, ValueError)
    assert "Unsupported local claim value" in str(error.value.__cause__)


@pytest.mark.parametrize(
    "base_profile",
    [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT],
)
def test_signed_schema_field_does_not_imply_critical_support(
        base_profile, container_signing_key):
    class LocalMessage(base_profile.message_cls):
        c_param = base_profile.message_cls.c_param.copy()
        c_param["local_claim"] = SINGLE_OPTIONAL_STRING

    profile = replace(base_profile, message_cls=LocalMessage)
    payload = payload_for(base_profile, container_signing_key)
    payload.update(local_claim="unsupported", crit=["local_claim"])
    token = sign(profile, container_signing_key, payload)

    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(
            profile,
            token,
            keyjar_for(container_signing_key),
            now=NOW,
        )
    assert isinstance(error.value.__cause__, UnknownCriticalExtension)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("claim", ["iat", "exp"])
@pytest.mark.parametrize("value", [str(NOW), "", True, False, None, [], {},
                                    float("nan"), float("inf"), float("-inf")])
def test_signed_numeric_dates_reject_original_invalid_types(profile, claim, value, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload[claim] = value
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    decoded = jws_factory(token).jwt.payload()[claim]
    assert type(decoded) is type(value)
    assert json.dumps(decoded) == json.dumps(value)
    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("iat,exp", [
    (0, NOW + 600), (0.0, NOW + 600.0), (NOW - 10, NOW + 600),
    (float(NOW - 10), float(NOW + 600)), (NOW - 10.25, NOW + 600.75),
])
def test_signed_numeric_dates_preserve_values_types_and_token(profile, iat, exp, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload.update(iat=iat, exp=exp)
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    decoded = jws_factory(token).jwt.payload()
    verified = verify_federation_jwt(profile, token.encode("ascii"), keyjar_for(container_signing_key), now=NOW)
    for claim, value in (("iat", iat), ("exp", exp)):
        assert decoded[claim] == verified.claims()[claim] == verified.message()[claim] == value
        assert type(decoded[claim]) is type(value)
        assert type(verified.claims()[claim]) is type(value)
        assert type(verified.message()[claim]) is type(value)
    assert verified.raw_token() == token
    assert verified.raw_token_bytes() == token.encode("ascii")


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("case,accepted", [
    ("expired-zero", False), ("expired", False), ("future-iat", False),
    ("fractional-expiry-rounding", False), ("fractional-expiry-valid", True),
    ("iat-at-skew", True), ("iat-past-skew", False),
])
def test_numeric_dates_retain_dependency_time_boundaries(profile, case, accepted, container_signing_key):
    skew = JWT().skew
    payload = payload_for(profile, container_signing_key)
    payload["iat"] = NOW - 100
    if case == "expired-zero":
        payload["exp"] = 0
    elif case == "expired":
        payload["exp"] = NOW - skew - 100
    elif case == "future-iat":
        payload["iat"] = NOW + skew + 100
    elif case == "fractional-expiry-rounding":
        # Cryptojwt truncates exp before comparison; this representation fix retains it.
        payload["exp"] = NOW - skew + 0.5
    elif case == "fractional-expiry-valid":
        payload["exp"] = NOW - skew + 1.25
    elif case == "iat-at-skew":
        payload["iat"] = float(NOW + skew)
    else:
        payload["iat"] = NOW + skew + 0.25
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    assert jws_factory(token).jwt.payload() == payload
    if accepted:
        verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
        assert verified.message()["iat"] == payload["iat"]
        assert verified.message()["exp"] == payload["exp"]
    else:
        with pytest.raises(FederationJwtPayloadError):
            verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("value", [
    None, {}, {"keys": {}}, {"keys": [12]}, [], [None], [""], "",
    '{"keys": []}', {"keys": None}, {"keys": 12}, {"keys": "[]"},
])
def test_signed_statement_rejects_malformed_jwks(profile, value, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload["jwks"] = value
    token = sign(profile, container_signing_key, payload)
    assert jws_factory(token).jwt.payload()["jwks"] == value
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert "jwks" in str(error.value.__cause__)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
def test_signed_statement_requires_jwks(profile, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    del payload["jwks"]
    token = sign(profile, container_signing_key, payload)
    assert "jwks" not in jws_factory(token).jwt.payload()
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert "jwks" in str(error.value.__cause__)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("kind", ["empty", "public", "extension", "unknown-key"])
def test_signed_statement_valid_jwks_containers(profile, kind, container_signing_key):
    jwks = {"keys": []}
    if kind != "empty":
        jwks["keys"].append(container_signing_key.serialize(private=False))
    if kind == "extension":
        jwks["custom"] = "extension"
    if kind == "unknown-key":
        jwks["keys"].append({"kty": "future-key-type"})
    payload = payload_for(profile, container_signing_key)
    payload["jwks"] = jwks
    token = sign(profile, container_signing_key, payload)
    assert jws_factory(token).jwt.payload()["jwks"] == jwks
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.message().to_dict()["jwks"] == jwks


@pytest.mark.parametrize("profile", registry.ALL_PROFILES, ids=lambda item: item.name)
def test_every_profile_signs_and_verifies_with_exact_protected_header(
    profile, signing_key
):
    token = sign(profile, signing_key)

    verified = verify_federation_jwt(
        profile=profile,
        token=token,
        key_jar=keyjar_for(signing_key),
        now=NOW,
    )

    assert header(token) == {"alg": "RS256", "kid": "key-1", "typ": profile.typ}
    assert isinstance(verified, VerifiedFederationJwt)
    assert verified.profile is profile
    assert verified.raw_token() == token


@pytest.mark.parametrize("claim", ["metadata_policy", "metadata_policy_crit", "constraints", "source_endpoint"])
@pytest.mark.parametrize("value", [{}, [], None, False, 0, "", [""], "present"])
def test_signed_entity_configuration_rejects_subordinate_only_claims(signing_key, claim, value):
    profile = registry.ENTITY_CONFIGURATION
    payload = payload_for(profile, signing_key)
    payload[claim] = value
    token = sign(profile, signing_key, payload)
    assert header(token)["typ"] == "entity-statement+jwt"
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile=profile, token=token,
                              key_jar=keyjar_for(signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert claim in str(error.value.__cause__)


@pytest.mark.parametrize("claims", [
    {"constraints": {"max_path_length": 0}},
    {"metadata_policy": {"federation_entity": {"organization_name": {"value": "Name"}}}},
    {"source_endpoint": "https://issuer.example.org/fetch"},
])
def test_signed_subordinate_only_claims_remain_valid(signing_key, claims):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, signing_key)
    payload.update(claims)
    token = sign(profile, signing_key, payload)
    verified = verify_federation_jwt(profile=profile, token=token,
                                     key_jar=keyjar_for(signing_key), now=NOW)
    assert verified.profile is profile
    assert verified.header()["typ"] == registry.ENTITY_CONFIGURATION.typ
    for claim, value in claims.items():
        assert verified.claims()[claim] == value


def test_signed_subordinate_critical_operator_retains_semantic_rejection(signing_key):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, signing_key)
    payload["metadata_policy_crit"] = ["regexp"]
    token = sign(profile, signing_key, payload)
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile=profile, token=token,
                              key_jar=keyjar_for(signing_key), now=NOW)
    assert isinstance(error.value.__cause__, MetadataPolicyCritError)


@pytest.fixture(scope="module")
def ec_only_claim_values(container_signing_key):
    mark_payload = payload_for(registry.TRUST_MARK, container_signing_key)
    mark_payload["sub"] = ISSUER
    mark = sign(registry.TRUST_MARK, container_signing_key, mark_payload)
    verified_mark = verify_federation_jwt(registry.TRUST_MARK, mark,
                                          keyjar_for(container_signing_key), now=NOW)
    mark_type = verified_mark.claims()["trust_mark_type"]
    return {
        "authority_hints": ["https://superior.example.org"],
        "trust_anchor_hints": ["https://anchor.example.org"],
        "trust_marks": [{"trust_mark_type": mark_type, "trust_mark": mark}],
        "trust_mark_issuers": {mark_type: [ISSUER]},
        "trust_mark_owners": {mark_type: {
            "sub": ISSUER, "jwks": {"keys": [container_signing_key.serialize(private=False)]},
        }},
    }


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints", "trust_marks",
                                   "trust_mark_issuers", "trust_mark_owners"])
@pytest.mark.parametrize("value", [[], {}, None, False, 0, "", [""], "normal-shape"])
def test_signed_subordinate_rejects_ec_only_claims(
        container_signing_key, ec_only_claim_values, claim, value):
    if value == "normal-shape":
        value = ec_only_claim_values[claim]
    payload = payload_for(registry.SUBORDINATE_STATEMENT, container_signing_key)
    payload[claim] = value
    token = sign(registry.SUBORDINATE_STATEMENT, container_signing_key, payload)
    decoded = jws_factory(token).jwt.payload()
    assert claim in decoded
    assert decoded[claim] == value
    assert decoded["jwks"] == {"keys": []}
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(registry.SUBORDINATE_STATEMENT, token,
                              keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert claim in str(error.value.__cause__)


def test_signed_ec_retains_ec_only_claims(container_signing_key, ec_only_claim_values):
    payload = payload_for(registry.ENTITY_CONFIGURATION, container_signing_key)
    payload.update(ec_only_claim_values)
    token = sign(registry.ENTITY_CONFIGURATION, container_signing_key, payload)
    verified = verify_federation_jwt(registry.ENTITY_CONFIGURATION, token,
                                     keyjar_for(container_signing_key), now=NOW)
    projected = verified.message().to_dict()
    for claim, value in ec_only_claim_values.items():
        actual = projected[claim]
        if isinstance(actual, str):
            actual = json.loads(actual)
        elif claim == "trust_marks":
            actual = [json.loads(entry) if isinstance(entry, str) else entry
                      for entry in actual]
        assert actual == value


@pytest.fixture(scope="module")
def signed_statement_chain(container_signing_key):
    key = container_signing_key
    leaf_payload = payload_for(registry.ENTITY_CONFIGURATION, key)
    leaf_payload.update(iss=SUBJECT, sub=SUBJECT, authority_hints=[ISSUER])
    leaf_keys = KeyJar()
    leaf_keys.add_keys(SUBJECT, [key])
    leaf = sign_federation_jwt(
        registry.ENTITY_CONFIGURATION, leaf_payload, leaf_keys, SUBJECT, "RS256",
        kid=key.kid, iat=leaf_payload["iat"],
    )
    verify_federation_jwt(registry.ENTITY_CONFIGURATION, leaf, leaf_keys, now=NOW)
    parent_payload = payload_for(registry.SUBORDINATE_STATEMENT, key)
    parent_payload["jwks"] = leaf_payload["jwks"]
    parent = sign(registry.SUBORDINATE_STATEMENT, key, parent_payload)
    verify_federation_jwt(registry.SUBORDINATE_STATEMENT, parent, keyjar_for(key), now=NOW)
    anchor = sign(registry.ENTITY_CONFIGURATION, key)
    verify_federation_jwt(registry.ENTITY_CONFIGURATION, anchor, keyjar_for(key), now=NOW)
    return [leaf, parent, anchor]


@pytest.mark.parametrize("names", [
    ("trust_chain",), ("peer_trust_chain",), ("trust_chain", "peer_trust_chain"),
])
@pytest.mark.parametrize("value", [None, [], "", {}, {"not": "a chain"}, "real-chain"])
def test_subordinate_chain_headers_rejected_on_sign_and_receive(
        container_signing_key, signed_statement_chain, names, value):
    if value == "real-chain":
        value = signed_statement_chain
    extra = {name: value for name in names}
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    with pytest.raises(FederationJwtHeaderError, match="forbidden"):
        sign(profile, container_signing_key, payload, extra_protected_headers=extra)

    # Sign independently so the producer's prohibition cannot mask receive-path coverage.
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected=dict(extra, typ=profile.typ),
    )
    for name in names:
        assert name in header(token)
        assert header(token)[name] == value
    assert jws_factory(token).verify_compact(token, [container_signing_key]) == payload
    for keys in (keyjar_for(container_signing_key), KeyJar(), object()):
        with pytest.raises(FederationJwtHeaderError, match="forbidden"):
            verify_federation_jwt(profile, token, keys, now=NOW)


@pytest.mark.parametrize("name", ["jku", "jwk", "x5u", "x5c"])
def test_subordinate_preserves_existing_header_bans(container_signing_key, name):
    profile = registry.SUBORDINATE_STATEMENT
    with pytest.raises(FederationJwtHeaderError, match="forbidden"):
        sign(profile, container_signing_key, extra_protected_headers={name: None})
    token = JWS(json.dumps(payload_for(profile, container_signing_key)), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ, name: None},
    )
    with pytest.raises(FederationJwtHeaderError, match="forbidden"):
        verify_federation_jwt(profile, token, object(), now=NOW)


def test_resolve_preserves_protected_and_payload_trust_chains(
        container_signing_key, signed_statement_chain):
    profile = registry.RESOLVE_RESPONSE
    payload = payload_for(profile, container_signing_key)
    payload["trust_chain"] = signed_statement_chain
    token = sign(profile, container_signing_key, payload,
                 extra_protected_headers={"trust_chain": signed_statement_chain})
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.header()["trust_chain"] == tuple(signed_statement_chain)
    assert verified.claims()["trust_chain"] == tuple(signed_statement_chain)
    assert verified.raw_token() == token


def test_subordinate_header_ban_does_not_ban_payload_names(
        container_signing_key, signed_statement_chain):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    payload.update(trust_chain=signed_statement_chain, peer_trust_chain=signed_statement_chain)
    token = sign(profile, container_signing_key, payload)
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    for name in ("trust_chain", "peer_trust_chain"):
        assert name not in verified.header()
        assert verified.claims()[name] == tuple(signed_statement_chain)


@pytest.mark.parametrize("required", ("alg", "kid", "typ"))
def test_header_validation_requires_profile_headers(required):
    protected = {
        "alg": "RS256",
        "kid": "key-1",
        "typ": registry.ENTITY_CONFIGURATION.typ,
    }
    del protected[required]

    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(registry.ENTITY_CONFIGURATION, protected)


@pytest.mark.parametrize(
    "change",
    (
        {"typ": "trust-mark+jwt"},
        {"kid": ""},
        {"alg": "none"},
        {"alg": "HS256"},
        {"crit": ["exp"], "exp": "required"},
        {"jku": "https://keys.example.org/jwks.json"},
        {"jwk": {"kty": "RSA"}},
        {"x5u": "https://keys.example.org/cert.pem"},
        {"x5c": ["certificate"]},
    ),
)
def test_header_validation_rejects_values_outside_profile_policy(change):
    protected = {
        "alg": "RS256",
        "kid": "key-1",
        "typ": registry.ENTITY_CONFIGURATION.typ,
    }
    protected.update(change)

    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(registry.ENTITY_CONFIGURATION, protected)


def test_header_validation_accepts_explicitly_allowed_critical_header():
    profile = replace(
        registry.ENTITY_CONFIGURATION,
        allowed_crit_headers=frozenset({"custom"}),
    )
    protected = {
        "alg": "RS256",
        "kid": "key-1",
        "typ": profile.typ,
        "crit": ["custom"],
        "custom": "required-value",
    }

    assert validate_protected_header(profile, protected) == protected


@pytest.mark.parametrize("profile", registry.ALL_PROFILES, ids=lambda item: item.name)
@pytest.mark.parametrize("reserved", ("alg", "kid", "typ"))
def test_signing_rejects_caller_override_of_profile_headers(
    profile, reserved, signing_key
):
    with pytest.raises(FederationJwtHeaderError):
        sign(
            profile,
            signing_key,
            extra_protected_headers={reserved: "caller-value"},
        )


@pytest.mark.parametrize(
    "alg,extra_headers",
    (
        ("none", None),
        ("HS256", None),
        ("RS256", {"crit": ["exp"], "exp": "required"}),
        ("RS256", {"jku": "https://keys.example.org/jwks.json"}),
        ("RS256", {"jwk": {"kty": "RSA"}}),
        ("RS256", {"x5u": "https://keys.example.org/cert.pem"}),
        ("RS256", {"x5c": ["certificate"]}),
    ),
)
def test_signing_rejects_headers_outside_profile_policy(
    alg, extra_headers, signing_key
):
    payload = payload_for(registry.ENTITY_CONFIGURATION, signing_key)
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=registry.ENTITY_CONFIGURATION,
            payload=payload,
            key_jar=keyjar_for(signing_key),
            issuer=ISSUER,
            alg=alg,
            kid="key-1",
            iat=payload["iat"],
            extra_protected_headers=extra_headers,
        )


def test_signing_does_not_mutate_caller_mappings(signing_key):
    payload = payload_for(registry.ENTITY_CONFIGURATION, signing_key)
    payload["custom"] = {"items": ["one"]}
    extra_headers = {"cty": "application/json", "custom": {"items": ["one"]}}
    payload_before = deepcopy(payload)
    headers_before = deepcopy(extra_headers)

    sign(
        registry.ENTITY_CONFIGURATION,
        signing_key,
        payload=payload,
        extra_protected_headers=extra_headers,
    )

    assert payload == payload_before
    assert extra_headers == headers_before


@pytest.mark.parametrize("profile", registry.ALL_PROFILES, ids=lambda item: item.name)
def test_verification_rejects_distinct_profile_typ_before_key_resolution(
    profile, signing_key
):
    token = sign(profile, signing_key)
    wrong_profile = next(
        candidate
        for candidate in registry.ALL_PROFILES
        if candidate.typ != profile.typ
    )

    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(wrong_profile, token, object(), now=NOW)


@pytest.mark.parametrize(
    "source_profile,target_profile",
    (
        (registry.SUBORDINATE_STATEMENT, registry.ENTITY_CONFIGURATION),
        (registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT),
        (registry.SIGNED_JWK_SET, registry.HISTORICAL_KEYS_RESPONSE),
        (registry.HISTORICAL_KEYS_RESPONSE, registry.SIGNED_JWK_SET),
    ),
    ids=(
        "statement-as-configuration",
        "configuration-as-statement",
        "jwks-as-history",
        "history-as-jwks",
    ),
)
def test_shared_typ_profiles_are_separated_by_payload_schema(
    source_profile, target_profile, signing_key
):
    token = sign(source_profile, signing_key)

    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(
            target_profile,
            token,
            keyjar_for(signing_key),
            now=NOW,
        )


def test_verification_rejects_missing_caller_supplied_local_key(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)

    with pytest.raises(FederationJwtKeyResolutionError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            KeyJar(),
            now=NOW,
        )


def test_verification_rejects_missing_kid_before_signature_check(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)
    token = replace_protected_header(token, remove="kid")

    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            object(),
            now=NOW,
        )


def test_verification_rejects_unknown_local_kid(signing_key):
    unknown_key = new_rsa_key(kid="unknown-key")
    token = sign(registry.ENTITY_CONFIGURATION, unknown_key)

    with pytest.raises(FederationJwtKeyResolutionError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            keyjar_for(signing_key),
            now=NOW,
        )


def test_verification_preserves_exact_ascii_bytes(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)
    token_bytes = token.encode("ascii")

    verified = verify_federation_jwt(
        registry.ENTITY_CONFIGURATION,
        token_bytes,
        keyjar_for(signing_key),
        now=NOW,
    )

    assert verified.raw_token_bytes() == token_bytes
    assert verified.raw_token() == token
    assert verified.profile is registry.ENTITY_CONFIGURATION
    assert verified.claims()["iss"] == ISSUER
    assert verified.claims()["sub"] == ISSUER


def test_verification_rejects_invalid_signature(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)
    untrusted_key = new_rsa_key(kid="key-1")

    with pytest.raises(FederationJwtSignatureError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            keyjar_for(untrusted_key),
            now=NOW,
        )


class FailingMessage(Message):
    def verify(self, **kwargs):
        raise ValueError("schema validation failed")


@pytest.mark.parametrize("profile", registry.ALL_PROFILES, ids=lambda item: item.name)
@pytest.mark.parametrize("as_bytes", [False, True])
def test_verified_input_precedes_construction_for_every_profile(
        profile, as_bytes, container_signing_key):
    calls = []
    payload = payload_for(profile, container_signing_key)
    payload["extension"] = {"items": ["original"]}
    source = json.dumps(payload, indent=2).encode("utf-8")

    class ObservedMessage(profile.message_cls):
        @classmethod
        def validate_input(cls, values, *, source_json=None):
            calls.append("input")
            assert values == payload
            assert source_json == source
            super().validate_input(values, source_json=source_json)
            values["extension"]["items"].append("hook")

        def __init__(self, **values):
            calls.append("construct")
            assert values == payload
            values["extension"]["items"].append("constructor")
            super().__init__(**values)

        def from_dict(self, values, **kwargs):
            calls.append("deserialize")
            return super().from_dict(values, **kwargs)

        def verify(self, **kwargs):
            calls.append("verify")
            assert kwargs == {"skew": DEFAULT_CRYPTOJWT_SKEW}
            assert getattr(self, "jws_header", None) is None
            assert getattr(self, "jwe_header", None) is None
            super().verify(**kwargs)
            # The established Message contract does not require a True return.

    def validator(values, now, skew):
        calls.append("profile")
        assert values == payload
        assert now == NOW
        assert skew == DEFAULT_CRYPTOJWT_SKEW

    selected = replace(profile, message_cls=ObservedMessage,
                       payload_validators=profile.payload_validators + (validator,))
    token = JWS(source, alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    supplied = token.encode("ascii") if as_bytes else token
    verified = verify_federation_jwt(
        selected, supplied, keyjar_for(container_signing_key), now=NOW)
    assert calls == ["input", "construct", "deserialize", "verify", "profile"]
    assert verified.claims() == deep_freeze(payload)
    assert verified.raw_token() == token
    assert verified.raw_token_bytes() == token.encode("ascii")
    assert verified.message().jws_header == header(token)
    assert verified.message().jwe_header is None
    assert payload["extension"] == {"items": ["original"]}


@pytest.mark.parametrize("profile,claim,value,cause,detail", [
    (registry.ENTITY_CONFIGURATION, "metadata", [], ValueError, "metadata"),
    (registry.ENTITY_CONFIGURATION, "iat", True, ValueError, "iat"),
    (registry.ENTITY_CONFIGURATION, "authority_hints", "https://ta.example.org",
     ValueError, "authority_hints"),
    (registry.SUBORDINATE_STATEMENT, "metadata", {"federation_entity": {"contacts": ""}},
     ValueError, "contacts"),
    (registry.SUBORDINATE_STATEMENT, "exp", str(NOW + 600), ValueError, "exp"),
    (registry.SUBORDINATE_STATEMENT, "metadata_policy", {}, ValueError, "metadata_policy"),
    (registry.SUBORDINATE_STATEMENT, "constraints", {"max_path_length": True},
     ConstraintError, "max_path_length"),
])
def test_signed_original_input_rejected_before_construction(
        profile, claim, value, cause, detail, container_signing_key):
    calls = []

    class ObservedMessage(profile.message_cls):
        def __init__(self, **values):
            calls.append("construct")
            super().__init__(**values)

    payload = payload_for(profile, container_signing_key)
    payload[claim] = value
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(replace(profile, message_cls=ObservedMessage), token,
                              keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, cause)
    assert detail in str(error.value.__cause__)
    assert calls == []


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("as_array", [False, True])
def test_signed_contacts_original_type_and_matching_control(
        profile, as_array, container_signing_key):
    calls = []

    class ObservedMessage(profile.message_cls):
        def __init__(self, **values):
            calls.append("construct")
            super().__init__(**values)

    contacts = ["ops@example.org"] if as_array else "ops@example.org"
    payload = payload_for(profile, container_signing_key)
    payload["metadata"] = {"federation_entity": {"contacts": contacts}}
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ})
    assert jws_factory(token).jwt.payload() == payload
    selected = replace(profile, message_cls=ObservedMessage)
    if as_array:
        verified = verify_federation_jwt(
            selected, token, keyjar_for(container_signing_key), now=NOW)
        assert verified.claims() == deep_freeze(payload)
        assert verified.message()["metadata"]["federation_entity"]["contacts"] == contacts
        assert calls == ["construct"]
    else:
        with pytest.raises(FederationJwtPayloadError) as error:
            verify_federation_jwt(selected, token, keyjar_for(container_signing_key), now=NOW)
        assert type(error.value.__cause__) is ValueError
        assert "contacts must be an array of strings" in str(error.value.__cause__)
        assert calls == []


@pytest.mark.parametrize("mode", ["raise", "false", "malformed", "verify"])
def test_input_hook_and_normal_verify_rejections(mode, container_signing_key):
    calls = []

    class CustomMessage(Message):
        @classmethod
        def validate_input(cls, values, *, source_json=None):
            calls.append("input")
            if mode == "raise":
                raise ValueError("input rejected")
            return mode != "false"

        def verify(self, **kwargs):
            calls.append("verify")
            raise ValueError("verify rejected")

    if mode == "malformed":
        CustomMessage.validate_input = None
    profile = replace(registry.ENTITY_CONFIGURATION, message_cls=CustomMessage)
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, sign(profile, container_signing_key),
                              keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, (TypeError, ValueError))
    assert calls == ({"raise": ["input"], "false": ["input"], "malformed": [],
                      "verify": ["input", "verify"]}[mode])


@pytest.mark.parametrize("failure", ["signature", "header", "keys"])
def test_untrusted_token_never_reaches_input_hook(failure, container_signing_key):
    calls = []

    class CustomMessage(Message):
        @classmethod
        def validate_input(cls, values, *, source_json=None):
            calls.append(values)

    profile = replace(registry.ENTITY_CONFIGURATION, message_cls=CustomMessage)
    token = sign(profile, container_signing_key)
    keys = keyjar_for(container_signing_key)
    error = FederationJwtSignatureError
    if failure == "signature":
        keys = keyjar_for(new_rsa_key(kid=container_signing_key.kid))
    elif failure == "header":
        token = replace_protected_header(token, typ="wrong+jwt")
        error = FederationJwtHeaderError
    else:
        keys = KeyJar()
        error = FederationJwtKeyResolutionError
    with pytest.raises(error):
        verify_federation_jwt(profile, token, keys, now=NOW)
    assert calls == []


@pytest.mark.parametrize("issuer", ["", SUBJECT])
def test_manual_schema_dispatch_preserves_conditional_audience(
        issuer, monkeypatch, container_signing_key):
    calls = []

    class ConfiguredJWT(JWT):
        def __init__(self, **kwargs):
            super().__init__(iss=issuer, **kwargs)

    class CustomMessage(Message):
        def verify(self, **kwargs):
            calls.append(kwargs)

    token = sign(registry.ENTITY_CONFIGURATION, container_signing_key)
    monkeypatch.setattr("fedservice.federation_jwt.jose.JWT", ConfiguredJWT)
    profile = replace(registry.ENTITY_CONFIGURATION, message_cls=CustomMessage)
    verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    expected = {"skew": DEFAULT_CRYPTOJWT_SKEW}
    if issuer:
        expected["aud"] = issuer
    assert calls == [expected]


def test_message_schema_failure_is_a_payload_error(signing_key):
    profile = replace(registry.ENTITY_CONFIGURATION, message_cls=FailingMessage)
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)

    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(profile, token, keyjar_for(signing_key), now=NOW)


def test_profile_semantic_validator_receives_effective_time_and_skew(signing_key):
    calls = []

    def validator(payload, now, skew):
        calls.append((payload["iss"], now, skew))

    profile = FederationJwtProfile(
        name="test",
        typ="test+jwt",
        content_type="application/test+jwt",
        message_cls=Message,
        payload_validators=(validator,),
    )
    payload = {"iss": ISSUER, "sub": SUBJECT, "iat": NOW - 10}
    token = sign(profile, signing_key, payload=payload)

    verify_federation_jwt(profile, token, keyjar_for(signing_key), now=NOW)

    assert calls == [(ISSUER, NOW, DEFAULT_CRYPTOJWT_SKEW)]


@pytest.mark.parametrize(
    "profile",
    tuple(item for item in registry.ALL_PROFILES if item.payload_validators),
    ids=lambda item: item.name,
)
def test_profiles_with_future_iat_policy_honor_cryptojwt_skew(profile, signing_key):
    neutral_profile = replace(profile, message_cls=Message)
    accepted_iat = NOW + DEFAULT_CRYPTOJWT_SKEW
    rejected_iat = accepted_iat + 1
    accepted = sign(
        profile,
        signing_key,
        payload={"iss": ISSUER, "sub": SUBJECT, "iat": accepted_iat},
    )
    rejected = sign(
        profile,
        signing_key,
        payload={"iss": ISSUER, "sub": SUBJECT, "iat": rejected_iat},
    )

    verify_federation_jwt(
        neutral_profile, accepted, keyjar_for(signing_key), now=NOW
    )
    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(
            neutral_profile, rejected, keyjar_for(signing_key), now=NOW
        )


def test_signing_and_verification_work_with_caller_supplied_local_keys(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)

    verified = verify_federation_jwt(
        registry.ENTITY_CONFIGURATION,
        token,
        keyjar_for(signing_key),
        now=NOW,
    )

    assert verified.raw_token() == token


def test_invalid_compact_token_is_a_header_error():
    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            "not-a-compact-jws",
            KeyJar(),
        )


def test_invalid_header_is_rejected_before_signature_verification():
    token = compact_token(
        {"alg": "none", "kid": "key-1", "typ": "entity-statement+jwt"}
    )

    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            object(),
            now=NOW,
        )
