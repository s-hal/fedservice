"""Requested-subject binding with signed statements and real consumer paths."""

from types import SimpleNamespace
from urllib.parse import urlencode

from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
import pytest
import responses

from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import cache_key
from fedservice.entity.function.trust_chain_collector import time_key
from fedservice.entity.function.trust_chain_collector import unverified_entity_statement
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.entity_statement.create import create_entity_configuration
from fedservice.entity_statement.create import create_subordinate_statement
from fedservice.exception import WrongSubject
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.utils import make_federation_entity


TA = "https://ta.example.org"
LEAF = "https://leaf.example.org"
REQUEST = "https://requested.example.org"
OTHER = "https://other.example.org"


@pytest.fixture(scope="module")
def signing_keys():
    return {owner: new_ec_key(crv="P-256", kid=str(index), use="sig")
            for index, owner in enumerate((TA, LEAF, REQUEST, OTHER))}


@pytest.fixture
def federation(signing_keys):
    public = {owner: {"keys": [key.serialize(private=False)]}
              for owner, key in signing_keys.items()}
    signing = KeyJar()
    for owner, key in signing_keys.items():
        signing.import_jwks({"keys": [key.serialize(private=True)]}, owner)
    entity = make_federation_entity(
        "https://verifier.example.org",
        key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]},
        trust_anchors={TA: public[TA]}, endpoints=["entity_configuration"],
    )

    def ec(subject):
        return create_entity_configuration(
            subject, signing, signing_alg="ES256", jwks=public[subject],
            authority_hints=None if subject == TA else [TA],
            metadata={"federation_entity": {
                "organization_name": subject,
                "federation_fetch_endpoint": subject + "/fetch",
            }},
        )

    def ss(subject):
        return create_subordinate_statement(
            TA, subject, signing, signing_alg="ES256", jwks=public[subject],
        )

    return SimpleNamespace(entity=entity, collector=entity.function.trust_chain_collector,
                           public=public, ec=ec, ss=ss)


def add_response(http, url, token):
    http.add("GET", url, body=token, content_type=ENTITY_CONFIGURATION.content_type)


def add_chain(http, federation, requested, ec_subject, ss_subject):
    add_response(http, requested + "/.well-known/openid-federation", federation.ec(ec_subject))
    add_response(http, TA + "/.well-known/openid-federation", federation.ec(TA))
    add_response(http, TA + "/fetch?" + urlencode({"sub": requested}), federation.ss(ss_subject))


def cached_ec(federation, subject):
    token = federation.ec(subject)
    claims = verify_self_signed_signature(token)
    claims["_jws"] = token
    return claims


def corrupt_signature(token):
    parts = token.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    return ".".join(parts)


def key_material_snapshot(keyjar):
    return {
        owner: keyjar.export_jwks(issuer_id=owner)
        for owner in keyjar.owners()
    }


@pytest.mark.parametrize("authority_hints", [None, [TA]], ids=["token-hints", "override"])
def test_supplied_ec_wrong_subject_rejected_without_side_effects(
        federation, authority_hints):
    collector = federation.collector
    config_cache = dict(collector.config_cache._db)
    statement_cache = dict(collector.entity_statement_cache._db)
    key_material = key_material_snapshot(federation.entity.keyjar)

    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        with pytest.raises(WrongSubject):
            collect_trust_chains(
                federation.entity,
                REQUEST,
                signed_entity_configuration=federation.ec(OTHER),
                authority_hints=authority_hints,
            )
        assert len(http.calls) == 0

    assert collector.config_cache._db == config_cache
    assert collector.entity_statement_cache._db == statement_cache
    assert key_material_snapshot(federation.entity.keyjar) == key_material


@pytest.mark.parametrize("authority_hints", [None, [TA]], ids=["token-hints", "override"])
def test_matching_supplied_ec_collects_and_verifies(federation, authority_hints):
    supplied = federation.ec(REQUEST)
    with responses.RequestsMock() as http:
        add_response(http, TA + "/.well-known/openid-federation", federation.ec(TA))
        add_response(http, TA + "/fetch?" + urlencode({"sub": REQUEST}),
                     federation.ss(REQUEST))
        candidates, returned = collect_trust_chains(
            federation.entity,
            REQUEST,
            signed_entity_configuration=supplied,
            authority_hints=authority_hints,
        )
        verified = verify_trust_chains(federation.entity, candidates, returned)

    assert returned == supplied
    assert len(verified) == 1
    assert verified[0].verified_chain[-1]["sub"] == REQUEST


def test_matching_supplied_ec_bad_signature_fails_bootstrap(federation):
    with responses.RequestsMock() as http:
        with pytest.raises(FederationJwtSignatureError):
            collect_trust_chains(
                federation.entity,
                REQUEST,
                signed_entity_configuration=corrupt_signature(federation.ec(REQUEST)),
            )
        assert len(http.calls) == 0
    assert len(federation.collector.config_cache) == 0
    assert len(federation.collector.entity_statement_cache) == 0


def test_a04_wrong_requested_ec_rejected_before_cache(federation):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        add_chain(http, federation, REQUEST, LEAF, LEAF)
        with pytest.raises(WrongSubject):
            candidates, ec = collect_trust_chains(federation.entity, REQUEST)
            verify_trust_chains(federation.entity, candidates, ec)
        assert len(http.calls) == 1
    assert REQUEST not in federation.collector.config_cache
    assert LEAF not in federation.entity.keyjar.owners()


def test_a04_matching_collection_and_warm_cache_verify(federation):
    with responses.RequestsMock() as http:
        add_chain(http, federation, LEAF, LEAF, LEAF)
        for _ in range(2):
            candidates, ec = collect_trust_chains(federation.entity, LEAF)
            verified = verify_trust_chains(federation.entity, candidates, ec)
            assert len(verified) == 1
            statements = verified[0].verified_chain
            assert [statement["iss"] for statement in statements] == [TA, LEAF]
            assert statements[-1]["metadata"]["federation_entity"]["organization_name"] == LEAF
        assert len(http.calls) == 3
    assert federation.collector.get_metadata(LEAF)["federation_entity"]["organization_name"] == LEAF
    assert federation.collector.get_federation_fetch_endpoint(TA) == TA + "/fetch"


def test_ss_only_mismatch_is_candidate_failure_without_cache(federation, caplog):
    with responses.RequestsMock() as http:
        add_chain(http, federation, REQUEST, REQUEST, LEAF)
        candidates, ec = collect_trust_chains(federation.entity, REQUEST)
        assert candidates == []
        assert verify_trust_chains(federation.entity, candidates, ec) == []
    assert "WrongSubject" in caplog.text
    assert federation.collector.config_cache[REQUEST]["sub"] == REQUEST
    assert cache_key(TA, REQUEST) not in federation.collector.entity_statement_cache
    assert time_key(TA, REQUEST) not in federation.collector.entity_statement_cache


@pytest.mark.parametrize("method", ["get_entity_configuration",
                                    "get_verified_self_signed_entity_configuration",
                                    "get_federation_fetch_endpoint"])
@pytest.mark.parametrize("matching", [False, True])
def test_ec_retrieval_boundaries(federation, method, matching):
    subject = REQUEST if matching else OTHER
    with responses.RequestsMock() as http:
        add_response(http, REQUEST + "/.well-known/openid-federation", federation.ec(subject))
        operation = getattr(federation.collector, method)
        if matching:
            result = operation(REQUEST)
            if method == "get_federation_fetch_endpoint":
                assert result == REQUEST + "/fetch"
            elif method == "get_verified_self_signed_entity_configuration":
                assert result["sub"] == REQUEST
            else:
                assert unverified_entity_statement(result)["sub"] == REQUEST
        else:
            with pytest.raises(WrongSubject):
                operation(REQUEST)
            assert REQUEST not in federation.collector.config_cache
    assert subject not in federation.entity.keyjar.owners()


@pytest.mark.parametrize("method", ["__call__", "get_metadata", "get_federation_fetch_endpoint"])
def test_wrong_warm_ec_never_used(federation, method):
    cache = federation.collector.config_cache
    cache[REQUEST] = cached_ec(federation, OTHER)
    cache[TA] = cached_ec(federation, TA)
    unrelated = cache[TA]
    with responses.RequestsMock() as http:
        with pytest.raises(WrongSubject):
            getattr(federation.collector, method)(REQUEST)
        assert len(http.calls) == 0
    assert cache[TA] is unrelated


@pytest.mark.parametrize("matching", [False, True])
def test_warm_ss_binding(federation, matching):
    token = federation.ss(REQUEST if matching else OTHER)
    cache = federation.collector.entity_statement_cache
    cache[cache_key(TA, REQUEST)] = token
    expiry = unverified_entity_statement(token)["exp"]
    cache[time_key(TA, REQUEST)] = expiry
    cache[cache_key(TA, LEAF)] = federation.ss(LEAF)
    with responses.RequestsMock() as http:
        if matching:
            assert federation.collector._get_entity_statement(REQUEST, TA) == token
        else:
            with pytest.raises(WrongSubject):
                federation.collector._get_entity_statement(REQUEST, TA)
        assert len(http.calls) == 0
    assert cache[time_key(TA, REQUEST)] == expiry
    assert cache_key(TA, LEAF) in cache


@pytest.mark.parametrize("service", ["entity_configuration", "entity_statement"])
@pytest.mark.parametrize("matching", [False, True])
def test_client_do_request_subject_context(federation, service, matching):
    for subject, jwks in federation.public.items():
        federation.entity.keyjar.import_jwks(jwks, subject)
    with responses.RequestsMock() as http:
        for requested in (REQUEST, LEAF):
            delivered = requested if matching else OTHER
            if service == "entity_configuration":
                token = federation.ec(delivered)
                url = requested + "/.well-known/openid-federation"
                # The request_args value, not the conflicting kwarg, builds the URL.
                kwargs = {"request_args": {"entity_id": requested}, "entity_id": OTHER}
            else:
                token = federation.ss(delivered)
                url = TA + "/fetch?" + urlencode({"sub": requested})
                kwargs = {"issuer": TA, "subject": requested, "fetch_endpoint": TA + "/fetch"}
            add_response(http, url, token)
            if matching:
                response = federation.entity.client.do_request(service, **kwargs)
                assert response["sub"] == requested
            else:
                with pytest.raises(WrongSubject):
                    federation.entity.client.do_request(service, **kwargs)
                assert delivered not in federation.collector.config_cache


def test_client_cached_superior_ec_binding(federation):
    federation.collector.config_cache[TA] = cached_ec(federation, OTHER)
    with responses.RequestsMock() as http:
        with pytest.raises(WrongSubject):
            federation.entity.client.do_request("entity_statement", issuer=TA, subject=REQUEST)
        assert len(http.calls) == 0


@pytest.mark.parametrize("service", ["entity_configuration", "entity_statement"])
def test_matching_subject_bad_signature_still_fails_client(federation, service):
    federation.entity.keyjar.import_jwks(federation.public[REQUEST], REQUEST)
    if service == "entity_configuration":
        token = federation.ec(REQUEST)
        url = REQUEST + "/.well-known/openid-federation"
        kwargs = {"entity_id": REQUEST}
    else:
        token = federation.ss(REQUEST)
        url = TA + "/fetch?" + urlencode({"sub": REQUEST})
        kwargs = {"issuer": TA, "subject": REQUEST, "fetch_endpoint": TA + "/fetch"}
    with responses.RequestsMock() as http:
        add_response(http, url, corrupt_signature(token))
        with pytest.raises(FederationJwtSignatureError):
            federation.entity.client.do_request(service, **kwargs)
    assert REQUEST not in federation.collector.config_cache


def test_matching_ec_bad_signature_fails_bootstrap(federation):
    with responses.RequestsMock() as http:
        add_response(http, REQUEST + "/.well-known/openid-federation",
                     corrupt_signature(federation.ec(REQUEST)))
        with pytest.raises(FederationJwtSignatureError):
            collect_trust_chains(federation.entity, REQUEST)
    assert REQUEST not in federation.collector.config_cache


def test_matching_ss_bad_signature_fails_chain_verification(federation):
    with responses.RequestsMock() as http:
        add_response(http, REQUEST + "/.well-known/openid-federation", federation.ec(REQUEST))
        add_response(http, TA + "/.well-known/openid-federation", federation.ec(TA))
        add_response(http, TA + "/fetch?" + urlencode({"sub": REQUEST}),
                     corrupt_signature(federation.ss(REQUEST)))
        candidates, ec = collect_trust_chains(federation.entity, REQUEST)
        assert len(candidates) == 1
        with pytest.raises(FederationJwtSignatureError):
            verify_trust_chains(federation.entity, candidates, ec)
