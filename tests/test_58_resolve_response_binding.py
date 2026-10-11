"""Resolve GET response bindings through real signing and client dispatch."""

from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import factory
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.jwt import JWT
from idpyoidc.client.exception import WrongContentType
import pytest
import responses

from fedservice.exception import WrongSubject
from fedservice.entity.client import resolve as resolve_module
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.message import Metadata
from fedservice.message import ResolveResponse
from tests.build_federation import make_entity


CLIENT = "https://client.example.org"
RESOLVER = "https://resolver.example.org"
OTHER_RESOLVER = "https://other-resolver.example.org"
SUBJECT = "https://subject.example.org"
OTHER_SUBJECT = "https://other-subject.example.org"
ANCHOR = "https://anchor.example.org"
OTHER_ANCHOR = "https://other-anchor.example.org"
UNREQUESTED = "https://unrequested.example.org"
INTERMEDIATE = "https://intermediate.example.org"


@pytest.fixture(scope="module")
def keys():
    return {owner: new_ec_key(crv="P-256", kid="binding-{}".format(index), use="sig")
            for index, owner in enumerate((RESOLVER, OTHER_RESOLVER, SUBJECT, OTHER_SUBJECT,
                                           ANCHOR, OTHER_ANCHOR, UNREQUESTED, INTERMEDIATE))}


def compact(payload, key, profile=RESOLVE_RESPONSE, **headers):
    source = json.dumps(payload)
    token = JWS(source, alg="ES256").sign_compact(
        [key], protected=dict(typ=profile.typ, kid=key.kid, **headers))
    decoded = factory(token)
    assert decoded.jwt.part[1].decode("utf-8") == source
    assert decoded.jwt.payload() == payload
    return token


@pytest.fixture
def peer(keys):
    now = utc_time_sans_frac()

    def statement(issuer, subject):
        payload = {"iss": issuer, "sub": subject, "iat": now - 60, "exp": now + 3600,
                   "jwks": {"keys": [keys[subject].serialize(private=False)]}}
        profile = ENTITY_CONFIGURATION if issuer == subject else SUBORDINATE_STATEMENT
        return compact(payload, keys[issuer], profile)

    def chain(subject=SUBJECT, anchor=ANCHOR, intermediate=False, include_anchor_ec=True):
        result = [statement(subject, subject)]
        if subject != anchor:
            if intermediate:
                result.extend([statement(INTERMEDIATE, subject), statement(anchor, INTERMEDIATE)])
            else:
                result.append(statement(anchor, subject))
            if include_anchor_ec:
                result.append(statement(anchor, anchor))
        return result

    def payload(issuer=RESOLVER, subject=SUBJECT, anchor=ANCHOR):
        return {"iss": issuer, "sub": subject, "iat": now - 60, "exp": now + 3600,
                "metadata": {"federation_entity": {"organization_name": subject}},
                "trust_chain": chain(subject, anchor)}

    return SimpleNamespace(statement=statement, chain=chain, payload=payload)


@pytest.fixture
def client(keys):
    entity = make_entity(
        CLIENT, "trust_anchor", services=["resolve"], endpoints=["entity_configuration"],
        key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]},
    )
    for issuer in (RESOLVER, OTHER_RESOLVER):
        entity.keyjar.import_jwks({"keys": [keys[issuer].serialize(private=False)]}, issuer)
    return entity.client


def request(client, resolver=RESOLVER, subject=SUBJECT, anchors=None):
    return client.do_request(
        "resolve", entity_id=resolver, endpoint=resolver + "/resolve",
        request_args={"sub": subject, "trust_anchor": anchors or [ANCHOR, OTHER_ANCHOR]},
    )


def respond(http, token, resolver=RESOLVER):
    http.add("GET", resolver + "/resolve", body=token, status=200,
             content_type=RESOLVE_RESPONSE.content_type)


@pytest.mark.parametrize("case", [
    "known_resolver", "outer_subject", "payload_subject", "payload_anchor",
    "header_resolver", "header_anchor", "foreign_audience",
])
def test_rejects_independent_binding_mismatch(case, peer, keys, client, monkeypatch):
    payload = peer.payload()
    headers = {}
    if case == "known_resolver":
        payload["iss"] = OTHER_RESOLVER
    elif case == "outer_subject":
        payload = peer.payload(subject=OTHER_SUBJECT)
    elif case == "payload_subject":
        payload["trust_chain"] = peer.chain(OTHER_SUBJECT)
    elif case == "payload_anchor":
        payload["trust_chain"] = peer.chain(anchor=UNREQUESTED)
    elif case == "header_resolver":
        headers["trust_chain"] = peer.chain(OTHER_RESOLVER)
    elif case == "header_anchor":
        headers["trust_chain"] = peer.chain(RESOLVER, UNREQUESTED)
    else:
        payload["aud"] = OTHER_SUBJECT
    token = compact(payload, keys[payload["iss"]], **headers)
    before = deepcopy(payload)
    verified = verify_federation_jwt(RESOLVE_RESPONSE, token, client.get_attribute("keyjar"))
    assert verified.claims() == deep_freeze(payload)
    assert verified.raw_token() == token
    update = Mock(wraps=client.get_service("resolve").update_service_context)
    monkeypatch.setattr(client.get_service("resolve"), "update_service_context", update)
    error = WrongSubject if case in ("outer_subject", "payload_subject") else FederationJwtPayloadError
    with responses.RequestsMock() as http:
        respond(http, token)
        with pytest.raises(error):
            request(client)
        assert len(http.calls) == 1
    update.assert_not_called()
    assert payload == before


@pytest.mark.parametrize("case", [
    "absent_audience", "string_audience", "other_resolver_subject", "second_anchor",
    "header_chain", "intermediate_chain", "singleton_self_anchor",
])
def test_matching_binding_control(case, peer, keys, client):
    resolver = OTHER_RESOLVER if case == "other_resolver_subject" else RESOLVER
    subject = OTHER_SUBJECT if case == "other_resolver_subject" else SUBJECT
    subject = ANCHOR if case == "singleton_self_anchor" else subject
    anchor = OTHER_ANCHOR if case == "second_anchor" else ANCHOR
    payload = peer.payload(resolver, subject, anchor)
    headers = {}
    if case == "string_audience":
        payload["aud"] = CLIENT
    if case == "header_chain":
        headers["trust_chain"] = peer.chain(resolver, OTHER_ANCHOR)
    if case == "intermediate_chain":
        payload["trust_chain"] = peer.chain(subject, anchor, intermediate=True)
    token = compact(payload, keys[resolver], **headers)
    with responses.RequestsMock() as http:
        respond(http, token, resolver)
        result = request(client, resolver, subject)
    assert result["iss"] == resolver
    assert result["sub"] == subject
    assert result["trust_chain"] == payload["trust_chain"]
    if "aud" in payload:
        assert result["aud"] == payload["aud"]


@pytest.mark.parametrize("audience", [[CLIENT], [OTHER_SUBJECT, CLIENT]])
def test_matching_audience_array_is_accepted(peer, keys, client, audience):
    payload = peer.payload()
    payload["aud"] = audience
    token = compact(payload, keys[RESOLVER])
    with responses.RequestsMock() as http:
        respond(http, token)
        result = request(client)
    assert result["aud"] == audience
    assert result.to_dict()["aud"] == audience


@pytest.mark.parametrize("subject", [SUBJECT, OTHER_SUBJECT])
@pytest.mark.parametrize("anchor", [ANCHOR, OTHER_ANCHOR])
@pytest.mark.parametrize("include_anchor_ec", [False, True])
def test_fixture_chains_have_independently_valid_statements(
        peer, keys, subject, anchor, include_anchor_ec):
    jar = KeyJar()
    for owner, key in keys.items():
        jar.import_jwks({"keys": [key.serialize(private=False)]}, owner)
    chain = peer.chain(subject, anchor, intermediate=True, include_anchor_ec=include_anchor_ec)
    for index, token in enumerate(chain):
        is_ec = index == 0 or (include_anchor_ec and index == len(chain) - 1)
        profile = ENTITY_CONFIGURATION if is_ec else SUBORDINATE_STATEMENT
        verified = verify_federation_jwt(profile, token, jar)
        assert verified.raw_token() == token
    assert factory(chain[0]).jwt.payload()["sub"] == subject
    terminal = factory(chain[-1]).jwt.payload()
    assert terminal["iss"] == anchor
    assert terminal["sub"] == (anchor if include_anchor_ec else INTERMEDIATE)


@pytest.mark.parametrize("location", ["payload", "header"])
@pytest.mark.parametrize("anchor", [ANCHOR, OTHER_ANCHOR])
@pytest.mark.parametrize("intermediate", [False, True])
@pytest.mark.parametrize("include_anchor_ec", [False, True])
def test_requested_terminal_issuer_accepts_both_chain_forms(
        location, anchor, intermediate, include_anchor_ec, peer, keys, client):
    start = SUBJECT if location == "payload" else RESOLVER
    chain = peer.chain(start, anchor, intermediate, include_anchor_ec)
    first, last = (factory(token).jwt.payload() for token in (chain[0], chain[-1]))
    assert first["iss"] == first["sub"] == start
    assert last["iss"] == anchor
    assert last["sub"] == (anchor if include_anchor_ec else INTERMEDIATE if intermediate else start)
    assert len(chain) == 2 + int(intermediate) + int(include_anchor_ec)
    payload = peer.payload()
    headers = {"trust_chain": chain} if location == "header" else {}
    if location == "payload":
        payload["trust_chain"] = chain
    token = compact(payload, keys[RESOLVER], **headers)
    verified = verify_federation_jwt(RESOLVE_RESPONSE, token, client.get_attribute("keyjar"))
    with responses.RequestsMock() as http:
        respond(http, token)
        result = request(client)
    assert result["trust_chain"] == payload["trust_chain"]
    assert verified.claims() == deep_freeze(payload)
    assert verified.header() == deep_freeze(factory(token).jwt.headers)
    assert verified.raw_token() == token


@pytest.mark.parametrize("location", ["payload", "header"])
@pytest.mark.parametrize("requested", [False, True])
def test_singleton_chain_must_also_be_a_requested_anchor(location, requested, peer, keys, client):
    start = SUBJECT if location == "payload" else RESOLVER
    chain = peer.chain(start, start)
    assert len(chain) == 1
    boundary = factory(chain[0]).jwt.payload()
    assert boundary["iss"] == boundary["sub"] == start
    payload = peer.payload()
    headers = {"trust_chain": chain} if location == "header" else {}
    if location == "payload":
        payload["trust_chain"] = chain
    anchors = [ANCHOR, start] if requested else [ANCHOR]
    with responses.RequestsMock() as http:
        respond(http, compact(payload, keys[RESOLVER], **headers))
        if requested:
            assert request(client, anchors=anchors)["trust_chain"] == payload["trust_chain"]
        else:
            with pytest.raises(FederationJwtPayloadError, match="anchor was not requested"):
                request(client, anchors=anchors)


@pytest.mark.parametrize("location", ["payload", "header"])
@pytest.mark.parametrize("include_anchor_ec", [False, True])
def test_unrequested_terminal_issuer_is_rejected_in_both_forms(
        location, include_anchor_ec, peer, keys, client):
    start = SUBJECT if location == "payload" else RESOLVER
    chain = peer.chain(start, UNREQUESTED, include_anchor_ec=include_anchor_ec)
    terminal = factory(chain[-1]).jwt.payload()
    assert terminal["iss"] == UNREQUESTED
    assert terminal["sub"] == (UNREQUESTED if include_anchor_ec else start)
    payload = peer.payload()
    headers = {"trust_chain": chain} if location == "header" else {}
    if location == "payload":
        payload["trust_chain"] = chain
    with responses.RequestsMock() as http:
        respond(http, compact(payload, keys[RESOLVER], **headers))
        with pytest.raises(FederationJwtPayloadError, match="anchor was not requested"):
            request(client)


@pytest.mark.parametrize("location", ["payload", "header"])
def test_terminal_ss_subject_cannot_substitute_for_requested_issuer(location, peer, keys, client):
    start = SUBJECT if location == "payload" else RESOLVER
    chain = peer.chain(start, ANCHOR, include_anchor_ec=False)
    chain.append(peer.statement(UNREQUESTED, ANCHOR))
    terminal = factory(chain[-1]).jwt.payload()
    assert terminal["iss"] == UNREQUESTED
    assert terminal["sub"] == ANCHOR
    payload = peer.payload()
    headers = {"trust_chain": chain} if location == "header" else {}
    if location == "payload":
        payload["trust_chain"] = chain
    with responses.RequestsMock() as http:
        respond(http, compact(payload, keys[RESOLVER], **headers))
        with pytest.raises(FederationJwtPayloadError, match="anchor was not requested"):
            request(client)


@pytest.mark.parametrize("location", ["payload", "header"])
@pytest.mark.parametrize("singleton", [False, True])
def test_start_must_remain_self_issued(location, singleton, peer, keys, client):
    start = SUBJECT if location == "payload" else RESOLVER
    chain = peer.chain(start)
    chain[0] = peer.statement(ANCHOR, start)
    if singleton:
        chain = chain[:1]
    payload = peer.payload()
    headers = {"trust_chain": chain} if location == "header" else {}
    if location == "payload":
        payload["trust_chain"] = chain
    with responses.RequestsMock() as http:
        respond(http, compact(payload, keys[RESOLVER], **headers))
        with pytest.raises(FederationJwtPayloadError, match="start must be self-issued"):
            request(client)


@pytest.mark.parametrize("location", ["payload", "header"])
@pytest.mark.parametrize("position", [0, -1])
@pytest.mark.parametrize("kind", ["unreadable", "json_serialization", "non_object", "missing_issuer",
                                  "missing_subject", "non_string_issuer", "non_string_subject",
                                  "empty_issuer", "empty_subject", "wrong_typ"])
def test_malformed_chain_boundary_is_rejected(location, position, kind, peer, keys, client):
    payload = peer.payload()
    chain = peer.chain(SUBJECT if location == "payload" else RESOLVER)
    boundary = factory(chain[position]).jwt.payload()
    if kind == "unreadable":
        replacement = "not-a-compact-statement"
    elif kind == "json_serialization":
        replacement = json.dumps({"payload": "", "signatures": []})
    else:
        if kind == "non_object":
            boundary = []
        elif kind == "missing_issuer":
            del boundary["iss"]
        elif kind == "missing_subject":
            del boundary["sub"]
        elif kind == "non_string_issuer":
            boundary["iss"] = 17
        elif kind == "non_string_subject":
            boundary["sub"] = 17
        elif kind == "empty_issuer":
            boundary["iss"] = ""
        elif kind == "empty_subject":
            boundary["sub"] = ""
        profile = RESOLVE_RESPONSE if kind == "wrong_typ" else ENTITY_CONFIGURATION
        replacement = compact(boundary, keys[ANCHOR], profile)
    chain[position] = replacement
    headers = {"trust_chain": chain} if location == "header" else {}
    if location == "payload":
        payload["trust_chain"] = chain
    token = compact(payload, keys[RESOLVER], **headers)
    with responses.RequestsMock() as http:
        respond(http, token)
        with pytest.raises(FederationJwtPayloadError):
            request(client)


@pytest.mark.parametrize("chain", [None, [], "scalar", {}, [None], [""]])
def test_malformed_header_chain_container_is_rejected(chain, peer, keys, client):
    token = compact(peer.payload(), keys[RESOLVER], trust_chain=chain)
    with responses.RequestsMock() as http:
        respond(http, token)
        with pytest.raises(FederationJwtPayloadError):
            request(client)


@pytest.mark.parametrize("audience", [None, "", [], {}, False, 17, [CLIENT, None], [CLIENT, 17],
                                      [None, CLIENT], [""], [OTHER_SUBJECT], CLIENT.upper()])
def test_invalid_audience_is_rejected_without_normalization(audience, peer, keys, client):
    payload = peer.payload()
    payload["aud"] = audience
    before = deepcopy(payload)
    with responses.RequestsMock() as http:
        respond(http, compact(payload, keys[RESOLVER]))
        with pytest.raises(FederationJwtPayloadError):
            request(client)
    assert payload == before


@pytest.mark.parametrize("missing", ["all", "expected_resolver", "expected_subject",
                                    "expected_trust_anchors", "expected_audience"])
def test_direct_parser_requires_explicit_context(missing, peer, keys, client):
    context = dict(expected_resolver=RESOLVER, expected_subject=SUBJECT,
                   expected_trust_anchors=[ANCHOR], expected_audience=CLIENT)
    if missing == "all":
        context.clear()
    else:
        del context[missing]
    client.context.issuer = RESOLVER
    with pytest.raises(ValueError, match="expected_"):
        client.get_service("resolve").parse_response(compact(peer.payload(), keys[RESOLVER]), **context)


@pytest.mark.parametrize("context", [{}, {"entity_id": None}, {"entity_id": ""},
                                   {"entity_id": "", "issuer": RESOLVER}])
def test_missing_resolver_is_rejected_before_http(context, client, monkeypatch):
    client.context.issuer = RESOLVER
    http = Mock(side_effect=AssertionError("request must not reach HTTP"))
    monkeypatch.setattr(client, "httpc", http)
    with pytest.raises(ValueError, match="resolver"):
        client.do_request("resolve", endpoint=RESOLVER + "/resolve",
                          request_args={"sub": SUBJECT, "trust_anchor": [ANCHOR]}, **context)
    http.assert_not_called()


def test_json_errors_remain_usable_but_unsigned_success_cannot_bypass_binding(peer, client):
    client.context.issuer = RESOLVER
    service = client.get_service("resolve")
    error = service.parse_response('{"error":"invalid_request"}', sformat="json")
    assert error["error"] == "invalid_request"
    with pytest.raises(ValueError):
        service.parse_response(json.dumps(peer.payload()), sformat="json")


@pytest.mark.parametrize("identity_args", [{"issuer": RESOLVER},
                                         {"entity_id": RESOLVER, "issuer": OTHER_RESOLVER}])
def test_explicit_resolver_alias_and_precedence(identity_args, peer, keys, client):
    with responses.RequestsMock() as http:
        respond(http, compact(peer.payload(), keys[RESOLVER]))
        result = client.do_request("resolve", endpoint=RESOLVER + "/resolve",
                                   request_args={"sub": SUBJECT, "trust_anchor": ANCHOR},
                                   **identity_args)
    assert result["iss"] == RESOLVER


def test_interleaved_calls_keep_copied_private_expectations(peer, keys, client):
    service = client.get_service("resolve")
    anchors = [ANCHOR]
    args = {"sub": SUBJECT, "trust_anchor": anchors}
    first = service.get_request_parameters(request_args=args, entity_id=RESOLVER,
                                           endpoint=RESOLVER + "/resolve")
    second = service.get_request_parameters(
        request_args={"sub": OTHER_SUBJECT, "trust_anchor": [OTHER_ANCHOR]},
        entity_id=OTHER_RESOLVER, endpoint=OTHER_RESOLVER + "/resolve")
    anchors[:] = [UNREQUESTED]
    args["sub"] = OTHER_SUBJECT
    client.context.issuer = UNREQUESTED
    assert first["expected_trust_anchors"] == (ANCHOR,)
    assert first["expected_subject"] == SUBJECT
    assert first["expected_audience"] == CLIENT
    with responses.RequestsMock() as http:
        respond(http, compact(peer.payload(), keys[RESOLVER]))
        respond(http, compact(peer.payload(OTHER_RESOLVER, OTHER_SUBJECT, OTHER_ANCHOR),
                              keys[OTHER_RESOLVER]), OTHER_RESOLVER)
        last_result = client.service_request(service, response_body_type="jose", **second)
        first_result = client.service_request(service, response_body_type="jose", **first)
        assert len(http.calls) == 2
        for call, subject, anchor in zip(http.calls, (OTHER_SUBJECT, SUBJECT), (OTHER_ANCHOR, ANCHOR)):
            assert parse_qs(urlsplit(call.request.url).query) == {"sub": [subject], "trust_anchor": [anchor]}
            assert not any(name.startswith("expected_") for name in call.request.headers)
    assert first_result["sub"] == SUBJECT
    assert last_result["sub"] == OTHER_SUBJECT


def test_rejected_response_has_no_success_update_and_next_call_succeeds(peer, keys, client, monkeypatch):
    service = client.get_service("resolve")
    update = Mock(wraps=service.update_service_context)
    monkeypatch.setattr(service, "update_service_context", update)
    with responses.RequestsMock() as http:
        respond(http, compact(peer.payload(), keys[RESOLVER]))
        first = request(client)
        assert update.call_count == 1
        respond(http, compact(peer.payload(OTHER_RESOLVER), keys[OTHER_RESOLVER]))
        with pytest.raises(FederationJwtPayloadError):
            request(client)
        assert update.call_count == 1
        respond(http, compact(peer.payload(OTHER_RESOLVER, OTHER_SUBJECT, OTHER_ANCHOR),
                              keys[OTHER_RESOLVER]), OTHER_RESOLVER)
        last = request(client, OTHER_RESOLVER, OTHER_SUBJECT, [OTHER_ANCHOR])
    assert [call[0][0] for call in update.call_args_list] == [first, last]
    assert first["sub"] == SUBJECT
    assert last["sub"] == OTHER_SUBJECT


@pytest.mark.parametrize("mismatch", [False, True])
def test_bindings_read_immutable_claims_without_replaying_callbacks(mismatch, peer, keys, client, monkeypatch):
    chosen = Metadata(extension={"chosen": "callback result"})
    callback = Mock(return_value=chosen)
    calls = []

    class TransformedResponse(ResolveResponse):
        c_param = ResolveResponse.c_param.copy()
        spec = c_param["metadata"]
        c_param["metadata"] = spec[:3] + (callback,) + spec[4:]

        def verify(self, **kwargs):
            calls.append(kwargs)
            super().verify(**kwargs)
            self.update({"iss": RESOLVER if mismatch else OTHER_RESOLVER})
            return True

    monkeypatch.setattr(resolve_module, "RESOLVE_RESPONSE", replace(RESOLVE_RESPONSE, message_cls=TransformedResponse))
    captured = []
    original = resolve_module.verify_federation_jwt

    def observe(*args, **kwargs):
        verified = original(*args, **kwargs)
        captured.append((verified, verified.header(), verified.claims()))
        return verified

    monkeypatch.setattr(resolve_module, "verify_federation_jwt", observe)
    payload = peer.payload(OTHER_RESOLVER if mismatch else RESOLVER)
    token = compact(payload, keys[payload["iss"]], trust_chain=peer.chain(RESOLVER))
    with responses.RequestsMock() as http:
        respond(http, token)
        if mismatch:
            with pytest.raises(FederationJwtPayloadError, match="issuer"):
                request(client)
        else:
            result = request(client)
            assert result["iss"] == OTHER_RESOLVER
            assert result["metadata"] is chosen
    callback.assert_called_once_with(payload["metadata"], sformat="dict")
    assert calls == [{"skew": JWT().skew}]
    assert len(captured) == 1
    verified, header, claims = captured[0]
    assert verified.header() is header
    assert verified.claims() is claims
    assert header == deep_freeze(factory(token).jwt.headers)
    assert claims == deep_freeze(payload)
    assert verified.raw_token() == token
    assert verified.raw_token_bytes() == token.encode("ascii")
    with pytest.raises(TypeError):
        claims["iss"] = "changed"
    assert chosen.to_dict() == {"extension": {"chosen": "callback result"}}


@pytest.mark.parametrize("case,error", [("signature", FederationJwtSignatureError),
                                       ("profile", FederationJwtHeaderError),
                                       ("key", FederationJwtKeyResolutionError),
                                       ("media", WrongContentType)])
def test_canonical_and_transport_failures_keep_their_public_errors(case, error, peer, keys, client):
    profile = ENTITY_CONFIGURATION if case == "profile" else RESOLVE_RESPONSE
    key = new_ec_key(crv="P-256", kid="unknown") if case == "key" else keys[RESOLVER]
    token = compact(peer.payload(), key, profile)
    if case == "signature":
        prefix, signature = token.rsplit(".", 1)
        token = prefix + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
    content_type = "application/json" if case == "media" else RESOLVE_RESPONSE.content_type
    with responses.RequestsMock() as http:
        http.add("GET", RESOLVER + "/resolve", body=token, content_type=content_type)
        with pytest.raises(error):
            request(client)
