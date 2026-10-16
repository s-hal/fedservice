"""Required algorithms through the canonical boundary and real consumers."""

from copy import deepcopy
import json

from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.hmac import new_sym_key
from cryptojwt.jwk.okp import new_okp_key
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import utc_time_sans_frac
import pytest
from requests import Response
import responses

from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.exception import WrongSubject
from fedservice.federation_jwt import registry
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.message import TrustMark
from fedservice.message import TrustMarkStatusResponse
from fedservice.utils import make_federation_entity
from tests.build_federation import build_federation
from tests.test_08_trust_mark import FEDERATION_CONFIG
from tests.test_08_trust_mark import TA_ID
from tests.test_08_trust_mark import TRUST_MARK_ISSUER_ID
from tests.test_55_entity_statement_subject_binding import add_response
from tests.test_55_entity_statement_subject_binding import corrupt_signature
from tests.test_58_resolve_response_binding import client
from tests.test_58_resolve_response_binding import keys
from tests.test_58_resolve_response_binding import peer
from tests.test_58_resolve_response_binding import request as resolve_request
from tests.test_58_resolve_response_binding import respond
from tests.test_58_resolve_response_binding import RESOLVER
from tests.test_58_resolve_response_binding import SUBJECT
from tests.test_82_federation_jwt_jose import ISSUER
from tests.test_82_federation_jwt_jose import payload_for


REQUIRED_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")


@pytest.fixture(scope="module")
def algorithm_keys():
    rsa = new_rsa_key(kid="algorithm-rsa", use="sig")
    result = {alg: rsa for alg in REQUIRED_ALGORITHMS if alg.startswith("RS")}
    for alg, curve in (("ES256", "P-256"), ("ES384", "P-384"), ("ES512", "P-521")):
        result[alg] = new_ec_key(crv=curve, kid=alg, use="sig")
    result["EdDSA"] = new_okp_key(crv="Ed25519", kid="algorithm-ed", use="sig")
    return result


def compact(profile, payload, key, alg):
    """Sign independently of Fedservice's supported-algorithm policy."""
    return JWS(json.dumps(payload), alg=alg).sign_compact(
        [key] if key is not None else [],
        protected={"typ": profile.typ, "kid": key.kid if key is not None else "unsigned"},
    )


def public_jar(issuer, key):
    jar = KeyJar()
    jar.import_jwks({"keys": [key.serialize(private=False)]}, issuer)
    return jar


def current_payload(profile, key):
    payload = payload_for(profile, key)
    now = utc_time_sans_frac()
    payload["iat"] = now - 10
    if "exp" in payload:
        payload["exp"] = now + 600
    if profile is registry.SIGNED_JWK_SET:
        payload["keys"] = [key.serialize(private=False)]
    return payload


@pytest.mark.parametrize("alg", REQUIRED_ALGORITHMS + ("EdDSA",))
@pytest.mark.parametrize("profile", registry.ALL_PROFILES, ids=lambda profile: profile.name)
def test_builtin_profiles_verify_real_signatures(profile, alg, algorithm_keys):
    key = algorithm_keys[alg]
    payload = current_payload(profile, key)
    token = compact(profile, payload, key, alg)
    verified = verify_federation_jwt(profile, token, public_jar(ISSUER, key))
    assert verified.profile is profile
    assert verified.header() == deep_freeze(factory(token).jwt.headers)
    assert verified.header()["alg"] == alg
    assert verified.claims() == deep_freeze(payload)
    assert verified.message()["iss"] == ISSUER
    assert verified.raw_token() == token
    assert verified.raw_token_bytes() == token.encode("ascii")


@pytest.mark.parametrize("alg", REQUIRED_ALGORITHMS)
def test_bootstrap_and_mixed_chain_consume_required_algorithms(alg, algorithm_keys):
    anchor = "https://algorithm-anchor.example.org"
    leaf = "https://algorithm-leaf.example.org"
    anchor_key = algorithm_keys[alg]
    leaf_key = new_ec_key(crv="P-256", kid="leaf", use="sig")
    public = {owner: {"keys": [key.serialize(private=False)]}
              for owner, key in ((anchor, anchor_key), (leaf, leaf_key))}
    entity = make_federation_entity(
        "https://verifier.example.org", trust_anchors={anchor: public[anchor]},
        key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]},
        endpoints=["entity_configuration"],
    )
    now = utc_time_sans_frac()
    anchor_claims = dict(iss=anchor, sub=anchor, iat=now - 10, exp=now + 3600,
                         jwks=public[anchor], metadata={"federation_entity": {
                             "federation_fetch_endpoint": anchor + "/fetch"}})
    leaf_claims = dict(iss=leaf, sub=leaf, iat=now - 10, exp=now + 3600,
                       jwks=public[leaf], authority_hints=[anchor])
    ss_claims = dict(iss=anchor, sub=leaf, iat=now - 10, exp=now + 3600, jwks=public[leaf])
    anchor_ec = compact(registry.ENTITY_CONFIGURATION, anchor_claims, anchor_key, alg)
    leaf_ec = compact(registry.ENTITY_CONFIGURATION, leaf_claims, leaf_key, "ES256")
    ss = compact(registry.SUBORDINATE_STATEMENT, ss_claims, anchor_key, alg)
    assert verify_self_signed_signature(anchor_ec) == anchor_claims
    with responses.RequestsMock() as http:
        add_response(http, leaf + "/.well-known/openid-federation", leaf_ec)
        add_response(http, anchor + "/.well-known/openid-federation", anchor_ec)
        add_response(http, anchor + "/fetch?sub=" + leaf, ss)
        candidates, returned = collect_trust_chains(entity, leaf)
        verified = verify_trust_chains(entity, candidates, returned)
    assert returned == leaf_ec
    assert len(verified) == 1
    assert [statement["iss"] for statement in verified[0].verified_chain] == [anchor, leaf]
    assert verified[0].verified_chain[-1]["sub"] == leaf


@pytest.mark.parametrize("alg", REQUIRED_ALGORITHMS)
def test_resolve_consumer_preserves_request_binding(alg, algorithm_keys, peer, client):
    key = algorithm_keys[alg]
    client.get_attribute("keyjar").import_jwks(
        {"keys": [key.serialize(private=False)]}, RESOLVER)
    payload = peer.payload()
    token = compact(registry.RESOLVE_RESPONSE, payload, key, alg)
    with responses.RequestsMock() as http:
        respond(http, token)
        result = resolve_request(client)
        assert result["iss"] == RESOLVER
        assert result["sub"] == SUBJECT
        assert result["trust_chain"] == payload["trust_chain"]
        with pytest.raises(WrongSubject):
            resolve_request(client, subject="https://different.example.org")


@pytest.fixture
def status_federation(tmp_path):
    config = deepcopy(FEDERATION_CONFIG)
    config[TRUST_MARK_ISSUER_ID]["kwargs"]["trust_mark_entity"]["kwargs"][
        "trust_mark_db"]["kwargs"]["https://refeds.org/sirtfi"] = str(tmp_path / "marks")
    return build_federation(config)


def issued_mark(federation, key, alg, profile=registry.TRUST_MARK):
    tmi = federation[TRUST_MARK_ISSUER_ID]
    endpoint = tmi.get_endpoint("trust_mark_status")
    issuer = endpoint.upstream_get("unit")
    original = issuer.create_trust_mark("https://refeds.org/sirtfi", SUBJECT)
    tmi.keyjar.import_jwks({"keys": [key.serialize(private=False)]}, tmi.entity_id)
    payload = factory(original).jwt.payload()
    token = compact(profile, payload, key, alg)
    assert issuer.find(payload["trust_mark_type"], SUBJECT)
    return endpoint, issuer, token, payload


@pytest.mark.parametrize("alg", REQUIRED_ALGORITHMS)
def test_status_accepts_issued_mark_and_consumer_verifies_response(
        alg, algorithm_keys, status_federation):
    endpoint, issuer, token, payload = issued_mark(
        status_federation, algorithm_keys[alg], alg)
    result = endpoint.process_request({"trust_mark": token})
    assert "error" not in result
    mark = issuer.unpack_trust_mark(token, entity_id=SUBJECT)
    assert isinstance(mark, TrustMark)
    assert mark.to_dict() == payload
    with pytest.raises(WrongSubject):
        issuer.unpack_trust_mark(token, entity_id="https://different.example.org")
    envelope = endpoint.do_response(**result)
    assert ("Content-type", registry.TRUST_MARK_STATUS_RESPONSE.content_type) in envelope["http_headers"]
    assert factory(envelope["response"]).jwt.headers["alg"] == "RS256"
    tmi = status_federation[TRUST_MARK_ISSUER_ID]
    consumer = status_federation[TA_ID]
    consumer.keyjar.import_jwks(tmi.keyjar.export_jwks(), tmi.entity_id)
    response = Response()
    response.status_code = 200
    response._content = envelope["response"].encode("ascii")
    response.headers["Content-Type"] = registry.TRUST_MARK_STATUS_RESPONSE.content_type
    response.url = endpoint.full_path
    service = consumer.get_service("trust_mark_status")
    parsed = consumer.client.parse_request_response(
        service, response, response_body_type=service.response_body_type)
    assert isinstance(parsed, TrustMarkStatusResponse)
    assert parsed["trust_mark"] == token
    assert parsed["status"] == "active"


@pytest.mark.parametrize("alg", ("RS384", "RS512", "ES256"))
def test_bad_signatures_fail_at_boundary_and_status(alg, algorithm_keys, status_federation):
    endpoint, issuer, token, payload = issued_mark(
        status_federation, algorithm_keys[alg], alg)
    corrupted = corrupt_signature(token)
    with pytest.raises(FederationJwtSignatureError):
        verify_federation_jwt(registry.TRUST_MARK, corrupted,
                              public_jar(payload["iss"], algorithm_keys[alg]))
    with pytest.raises(FederationJwtSignatureError):
        issuer.unpack_trust_mark(corrupted)
    assert endpoint.process_request({"trust_mark": corrupted})["error"] == "invalid_request"


@pytest.mark.parametrize("case", ("unknown_key", "wrong_typ", "none", "HS256", "malformed"))
def test_unacceptable_status_inputs_remain_rejected(case, algorithm_keys, status_federation):
    key = algorithm_keys["RS256"]
    endpoint, issuer, token, payload = issued_mark(status_federation, key, "RS256")
    error = FederationJwtHeaderError
    if case == "unknown_key":
        token = compact(registry.TRUST_MARK, payload, new_rsa_key(kid="unknown"), "RS256")
        error = FederationJwtKeyResolutionError
    elif case == "wrong_typ":
        token = compact(registry.TRUST_MARK_DELEGATION, payload, key, "RS256")
    elif case == "none":
        token = compact(registry.TRUST_MARK, payload, None, "none")
    elif case == "HS256":
        token = compact(registry.TRUST_MARK, payload, new_sym_key(kid="symmetric"), "HS256")
    else:
        token = "not-a-jwt"
    with pytest.raises(error):
        verify_federation_jwt(registry.TRUST_MARK, token, public_jar(payload["iss"], key))
    with pytest.raises(error):
        issuer.unpack_trust_mark(token)
    assert endpoint.process_request({"trust_mark": token})["error"] == "invalid_request"
