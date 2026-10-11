"""Incoming Resolve Response validation through real schemas and clients."""

from copy import deepcopy
from dataclasses import replace
import json
from unittest.mock import Mock

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
import pytest
import responses

from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.message import Metadata
from fedservice.message import ResolveResponse
from tests.build_federation import make_entity


ISSUER = "https://resolver.example.org"
SUBJECT = "https://subject.example.org"
ANCHOR = "https://anchor.example.org"
ENDPOINT = ISSUER + "/resolve"


@pytest.fixture(scope="module")
def signing_key():
    return new_rsa_key(kid="resolve-validation")


@pytest.fixture
def keyjar(signing_key):
    jar = KeyJar()
    jar.add_keys(ISSUER, [signing_key])
    return jar


@pytest.fixture
def payload():
    now = utc_time_sans_frac()
    return {
        "iss": ISSUER, "sub": SUBJECT, "iat": now - 10, "exp": now + 3600,
        "metadata": {"federation_entity": {}},
        "trust_chain": ["opaque.statement.signature"],
    }


def client_chain(subject, signing_key):
    now = utc_time_sans_frac()
    result = []
    for issuer, subordinate in ((subject, subject), (ANCHOR, subject), (ANCHOR, ANCHOR)):
        claims = {"iss": issuer, "sub": subordinate, "iat": now - 10, "exp": now + 3600,
                  "jwks": {"keys": [signing_key.serialize(private=False)]}}
        result.append(JWS(json.dumps(claims), alg="RS256").sign_compact(
            [signing_key], protected={"typ": ENTITY_CONFIGURATION.typ, "kid": signing_key.kid}))
    return result


@pytest.fixture
def client_payload(payload, signing_key):
    value = deepcopy(payload)
    value["trust_chain"] = client_chain(value["sub"], signing_key)
    return value


@pytest.fixture
def client(signing_key):
    entity = make_entity(
        "https://client.example.org", "trust_anchor",
        services=["resolve"], endpoints=["entity_configuration"],
        key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]},
    )
    entity.keyjar.add_keys(ISSUER, [signing_key])
    return entity.client


def signed(payload, signing_key):
    source = json.dumps(payload)
    token = JWS(source, alg="RS256").sign_compact(
        [signing_key], protected={"typ": RESOLVE_RESPONSE.typ, "kid": signing_key.kid}
    )
    parsed = jws_factory(token)
    assert parsed.jwt.part[1].decode("utf-8") == source
    assert parsed.jwt.payload() == payload
    return token


def request(client, subject=SUBJECT):
    return client.do_request(
        "resolve", endpoint=ENDPOINT, entity_id=ISSUER,
        request_args={"sub": subject, "trust_anchor": [ANCHOR]},
    )


def callback_profile(callback):
    class LocalResponse(ResolveResponse):
        c_param = ResolveResponse.c_param.copy()
        spec = c_param["metadata"]
        c_param["metadata"] = spec[:3] + (callback,) + spec[4:]

    return replace(RESOLVE_RESPONSE, message_cls=LocalResponse)


@pytest.mark.parametrize("case", ["numeric_string", "scalar_chain", "metadata_null"])
def test_client_rejects_original_malformed_payload(case, client_payload, signing_key, client, monkeypatch):
    payload = client_payload
    if case == "numeric_string":
        payload["exp"] = str(payload["exp"])
    elif case == "scalar_chain":
        payload["trust_chain"] = payload["trust_chain"][0]
    else:
        payload["metadata"] = {"federation_entity": {"organization_name": None}}
    token = signed(payload, signing_key)
    service = client.get_service("resolve")
    update = Mock(wraps=service.update_service_context)
    monkeypatch.setattr(service, "update_service_context", update)
    with responses.RequestsMock() as http:
        http.add("GET", ENDPOINT, body=token, status=200,
                 content_type=RESOLVE_RESPONSE.content_type)
        with pytest.raises(FederationJwtPayloadError) as error:
            request(client)
        assert isinstance(error.value.__cause__, ValueError)
        assert len(http.calls) == 1
    update.assert_not_called()


def test_client_accepts_valid_signed_response(client_payload, signing_key, client):
    payload = client_payload
    token = signed(payload, signing_key)
    with responses.RequestsMock() as http:
        http.add("GET", ENDPOINT, body=token, status=200,
                 content_type=RESOLVE_RESPONSE.content_type)
        result = request(client)
    assert isinstance(result, ResolveResponse)
    assert result["iss"] == ISSUER
    assert result["sub"] == SUBJECT
    assert result["trust_chain"] == payload["trust_chain"]
    assert isinstance(result["metadata"], Metadata)
    assert result["metadata"]["federation_entity"].to_dict() == {}


def test_client_dispatches_normal_nested_verification(client_payload, signing_key, client, monkeypatch):
    payload = client_payload
    calls = []
    original = Metadata.verify

    def observe(self, **kwargs):
        calls.append((self, kwargs))
        return original(self, **kwargs)

    monkeypatch.setattr(Metadata, "verify", observe)
    with responses.RequestsMock() as http:
        http.add("GET", ENDPOINT, body=signed(payload, signing_key), status=200,
                 content_type=RESOLVE_RESPONSE.content_type)
        result = request(client)
    assert calls == [(result["metadata"], {"skew": JWT().skew})]


@pytest.mark.parametrize("claim", ["iss", "sub", "iat", "exp", "metadata", "trust_chain"])
def test_input_hook_requires_claim_presence(claim, payload):
    del payload[claim]
    with pytest.raises(MissingRequiredAttribute, match=claim):
        ResolveResponse.validate_input(payload)


@pytest.mark.parametrize("claim,value", [
    ("iss", None), ("iss", [ISSUER]), ("iss", ""), ("sub", 23),
    ("sub", "http://subject.example.org"), ("sub", SUBJECT + "?query=1"),
    ("iat", "2000000000"), ("exp", "2000003600"), ("iat", False),
    ("exp", None), ("exp", []), ("iat", {}), ("iat", float("nan")),
    ("exp", float("inf")), ("iat", float("-inf")),
    ("metadata", []), ("metadata", None), ("metadata", "{}"),
    ("metadata", {"extension": []}), ("metadata", {"extension": None}),
    ("metadata", {"extension": {"name": None}}),
    ("metadata", {"federation_entity": {"contacts": "ops@example.org"}}),
    ("trust_chain", "opaque.statement.signature"), ("trust_chain", []),
    ("trust_chain", None), ("trust_chain", {}), ("trust_chain", [""]),
    ("trust_chain", [False]), ("trust_chain", [12]), ("trust_chain", [None]),
])
def test_input_hook_checks_original_values(claim, value, payload):
    payload[claim] = value
    with pytest.raises(ValueError, match=claim):
        ResolveResponse.validate_input(payload)


@pytest.mark.parametrize("value", [[], None, "{}"])
def test_input_hook_retains_outer_object_check(value):
    with pytest.raises(ValueError, match="JSON object"):
        ResolveResponse.validate_input(value)


def test_input_hook_is_read_only_and_cooperative(payload):
    calls = []

    class ExtendedResponse(ResolveResponse):
        @classmethod
        def validate_input(cls, value, *, source_json=None):
            super().validate_input(value, source_json=source_json)
            calls.append(source_json)

        def __init__(self, **kwargs):
            raise AssertionError("preflight must not construct a Message")

    before = deepcopy(payload)
    ExtendedResponse.validate_input(payload, source_json=b"original source")
    assert calls == [b"original source"]
    assert payload == before


def test_zero_numeric_dates_are_present_without_mutating_shared_declarations(payload):
    payload.update(iat=0, exp=0)
    declarations = ResolveResponse.c_param.copy()
    ResolveResponse.validate_input(payload)
    assert ResolveResponse(**payload).verify() is True
    assert ResolveResponse.c_param == declarations
    assert ResolveResponse.c_param["iat"][1] is True
    assert ResolveResponse.c_param["exp"][1] is True


def test_original_rejection_precedes_constructor_and_normalizing_callback(payload, signing_key, keyjar):
    calls = []

    def normalize(value, sformat="dict"):
        calls.append("callback")
        return Metadata(federation_entity={})

    class ObservedResponse(callback_profile(normalize).message_cls):
        def __init__(self, **kwargs):
            calls.append("constructor")
            super().__init__(**kwargs)

    payload["metadata"] = {"federation_entity": {"organization_name": None}}
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(
            replace(RESOLVE_RESPONSE, message_cls=ObservedResponse),
            signed(payload, signing_key), keyjar,
        )
    assert isinstance(error.value.__cause__, ValueError)
    assert "must not be null" in str(error.value.__cause__)
    assert calls == []


def test_rejecting_metadata_subclass_keeps_verification_context(payload, signing_key, keyjar):
    calls = []

    class RejectedMetadata(ValueError):
        pass

    class RejectingMetadata(Metadata):
        def verify(self, **kwargs):
            calls.append((self, kwargs))
            super().verify(**kwargs)
            raise RejectedMetadata("nested rejection")

    metadata = RejectingMetadata(**payload["metadata"])
    callback = Mock(return_value=metadata)
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(callback_profile(callback), signed(payload, signing_key), keyjar)
    assert isinstance(error.value.__cause__, RejectedMetadata)
    assert calls == [(metadata, {"skew": JWT().skew})]
    callback.assert_called_once_with(payload["metadata"], sformat="dict")


@pytest.mark.parametrize("kind", [dict, Message])
def test_invalid_callback_result_is_not_repaired(kind, payload, signing_key, keyjar):
    result = kind(extension={"name": None})
    callback = Mock(return_value=result)
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(callback_profile(callback), signed(payload, signing_key), keyjar)
    assert "must not be null" in str(error.value.__cause__)
    callback.assert_called_once_with(payload["metadata"], sformat="dict")
    assert result["extension"]["name"] is None


@pytest.mark.parametrize("kind", [dict, Message, Metadata])
def test_transformed_callback_result_is_preserved_once(kind, payload, signing_key, keyjar):
    before = deepcopy(payload)
    chosen = kind(extension={"chosen": "transformed", "empty": []})
    callback = Mock(return_value=chosen)
    token = signed(payload, signing_key)
    verified = verify_federation_jwt(callback_profile(callback), token, keyjar)
    callback.assert_called_once_with(payload["metadata"], sformat="dict")
    assert verified.message()["metadata"] is chosen
    assert chosen["extension"] == {"chosen": "transformed", "empty": []}
    assert "federation_entity" not in chosen
    assert verified.claims()["metadata"] == payload["metadata"]
    assert verified.raw_token() == token
    chosen["extension"]["chosen"] = "local mutation"
    assert verified.claims()["metadata"] == before["metadata"]
    assert payload == before


def test_callback_rejection_is_not_replayed(payload, signing_key, keyjar):
    callback = Mock(side_effect=ValueError("callback rejection"))
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(callback_profile(callback), signed(payload, signing_key), keyjar)
    assert "callback rejection" in str(error.value.__cause__)
    callback.assert_called_once_with(payload["metadata"], sformat="dict")


@pytest.mark.parametrize("claim,value", [
    ("iss", 23), ("sub", "http://subject.example.org"),
    ("iat", "2000000000"), ("exp", True),
    ("trust_chain", "scalar"), ("trust_chain", [""]),
    ("metadata", {"extension": {"name": None}}),
])
def test_current_object_validation_and_local_repair(claim, value, payload):
    message = ResolveResponse()
    message.update(deepcopy(payload))
    assert message.verify() is True
    message.update({claim: value})
    with pytest.raises(ValueError, match=claim):
        message.verify()
    message.update({claim: deepcopy(payload[claim])})
    assert message.verify() is True


def test_live_nested_metadata_mutation_is_rechecked(payload):
    message = ResolveResponse(**payload)
    metadata = message["metadata"]
    metadata["federation_entity"]["organization_name"] = None
    with pytest.raises(ValueError, match="must not be null"):
        message.verify()
    metadata["federation_entity"]["organization_name"] = "repaired"
    assert message.verify() is True
    assert message["metadata"] is metadata


def test_valid_fractional_dates_partial_metadata_and_authoritative_preservation(
        payload, signing_key, keyjar):
    payload["iat"] += 0.25
    payload["exp"] += 0.75
    payload["metadata"] = {
        "openid_provider": {},
        "extension": {"empty": [], "object": {"nested": None}, "flag": False},
    }
    payload["extension"] = {"data": ["original"]}
    before = deepcopy(payload)
    token = signed(payload, signing_key)
    verified = verify_federation_jwt(RESOLVE_RESPONSE, token, keyjar)
    assert verified.raw_token() == token
    assert verified.raw_token_bytes() == token.encode("utf-8")
    assert verified.claims()["iat"] == before["iat"]
    assert verified.claims()["exp"] == before["exp"]
    assert verified.claims()["metadata"]["extension"]["empty"] == ()
    assert verified.claims()["metadata"]["extension"]["object"]["nested"] is None
    assert verified.message()["metadata"]["extension"] == before["metadata"]["extension"]
    verified.message()["metadata"]["extension"]["empty"].append("local")
    assert verified.claims()["metadata"]["extension"]["empty"] == ()
    with pytest.raises(TypeError):
        verified.claims()["metadata"]["extension"]["flag"] = True
    assert payload == before


def test_repeated_client_use_does_not_accept_or_retain_invalid_response(
        client_payload, signing_key, client, monkeypatch):
    payload = client_payload
    valid_first = deepcopy(payload)
    valid_first["metadata"] = {"extension": {"name": "first"}}
    invalid = deepcopy(payload)
    invalid["metadata"] = {"extension": {"name": None}}
    valid_last = deepcopy(payload)
    valid_last["sub"] = "https://independent.example.org"
    valid_last["trust_chain"] = client_chain(valid_last["sub"], signing_key)
    valid_last["metadata"] = {"extension": {"name": "last"}}
    service = client.get_service("resolve")
    update = Mock(wraps=service.update_service_context)
    monkeypatch.setattr(service, "update_service_context", update)
    with responses.RequestsMock() as http:
        for value in (valid_first, invalid, valid_last):
            http.add("GET", ENDPOINT, body=signed(value, signing_key), status=200,
                     content_type=RESOLVE_RESPONSE.content_type)
        first = request(client)
        assert update.call_count == 1
        with pytest.raises(FederationJwtPayloadError):
            request(client)
        assert update.call_count == 1
        assert first["metadata"]["extension"] == {"name": "first"}
        last = request(client, subject=valid_last["sub"])
        assert len(http.calls) == 3
    assert last["sub"] == valid_last["sub"]
    assert last["metadata"]["extension"] == {"name": "last"}
    assert [call[0][0] for call in update.call_args_list] == [first, last]
