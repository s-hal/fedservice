"""Shared cache deadlines and collector refresh with real signed statements."""

from copy import deepcopy
import re
from types import SimpleNamespace
from urllib.parse import urlencode

from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwt import utc_time_sans_frac
import pytest
import responses

from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.trust_chain_collector import cache_key
from fedservice.entity.function.trust_chain_collector import time_key
from fedservice.entity_statement.cache import ESCache
from fedservice.exception import FailedConfigurationRetrieval
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.utils import make_federation_entity


ANCHOR = "https://anchor.example.org"
LEAF = "https://leaf.example.org"
OTHER = "https://other.example.org"
INTERMEDIATE = "https://intermediate.example.org"


def ec_url(owner):
    return owner + "/.well-known/openid-federation"


def ss_url(owner, subject, path="/fetch"):
    return owner + path + "?" + urlencode({"sub": subject})


@pytest.fixture
def clock(monkeypatch):
    current = [utc_time_sans_frac()]
    for module in ("cryptojwt.jwt", "fedservice.federation_jwt.jose"):
        monkeypatch.setattr(module + ".utc_time_sans_frac", lambda: int(current[0]))
    monkeypatch.setattr("fedservice.entity_statement.cache.time", lambda: current[0])
    monkeypatch.setattr("fedservice.entity.function.trust_chain_collector.time",
                        SimpleNamespace(time=lambda: current[0]))
    for module in ("fedservice.entity.server.resolve", "fedservice.entity_statement.create"):
        monkeypatch.setattr(module + ".time", lambda: current[0])
    return current


@pytest.fixture
def federation(clock):
    now = clock[0]
    signing = KeyJar()
    public = {}
    for owner in (ANCHOR, LEAF, OTHER, INTERMEDIATE):
        key = new_ec_key(crv="P-256", use="sig")
        signing.import_jwks({"keys": [key.serialize(private=True)]}, owner)
        public[owner] = {"keys": [key.serialize(private=False)]}
    resolver = make_federation_entity(
        "https://resolver.example.org", signing_alg="ES256",
        key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]},
        trust_anchors={ANCHOR: public[ANCHOR]},
        endpoints=["entity_configuration", "resolve"],
        services=["entity_configuration", "entity_statement"],
    )
    documents = {}

    def ec(owner, expires_at, name="original", hints=None, path="/fetch"):
        payload = {"sub": owner, "jwks": public[owner], "exp": expires_at,
                   "metadata": {"federation_entity": {
                       "organization_name": name}}}
        if path is not None:
            payload["metadata"]["federation_entity"]["federation_fetch_endpoint"] = owner + path
        if hints is not None:
            payload["authority_hints"] = hints
        elif owner == LEAF:
            payload["authority_hints"] = [ANCHOR]
        token = sign_federation_jwt(ENTITY_CONFIGURATION, payload, signing, owner,
                                    "ES256", iat=now - 60)
        documents[ec_url(owner)] = token
        return token

    def ss(owner, subject, expires_at, path="/fetch"):
        token = sign_federation_jwt(
            SUBORDINATE_STATEMENT,
            {"sub": subject, "jwks": public[subject], "exp": expires_at},
            signing, owner, "ES256", iat=now - 60)
        documents[ss_url(owner, subject, path)] = token
        return token

    ec(ANCHOR, now + 7200)
    ec(LEAF, now + 1200.5)
    ss(ANCHOR, LEAF, now + 5400)

    def retrieve(request):
        result = documents.get(request.url, (404, {}, "missing"))
        if isinstance(result, Exception):
            raise result
        if callable(result):
            return result(request)
        if isinstance(result, tuple):
            return result
        return 200, {"Content-Type": ENTITY_CONFIGURATION.content_type}, result

    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        http.add_callback("GET", re.compile(r"https://.*"), callback=retrieve)
        yield SimpleNamespace(resolver=resolver, collector=resolver.function.trust_chain_collector,
                              signing=signing, public=public, clock=clock, now=now,
                              documents=documents, ec=ec, ss=ss, http=http)


def collect(fed):
    candidates, token = collect_trust_chains(fed.resolver, LEAF)
    verified = verify_trust_chains(fed.resolver, candidates, token)
    assert len(verified) == 1
    return token


@pytest.mark.parametrize("fraction", [0, 0.5])
@pytest.mark.parametrize("offset", [-0.125, 0, 0.125])
def test_cache_reads_share_hard_deadline(federation, fraction, offset):
    fed = federation
    expiry = fed.now + 1200 + fraction
    token = fed.ec(LEAF, expiry)
    verified = verify_federation_jwt(ENTITY_CONFIGURATION, token, fed.signing)
    value = verified.message().to_dict()
    value["_jws"] = verified.raw_token()
    cache = ESCache(allowed_delta=600)
    for key in ("indexed", "get", "default"):
        cache[key] = deepcopy(value)
    fed.clock[0] = expiry + offset
    assert cache["missing"] is None
    sentinel = object()
    assert cache.get("missing", sentinel) is sentinel
    if offset < 0:
        assert cache["indexed"] == cache.get("get") == cache.get("default", sentinel) == value
        assert cache["indexed"]["exp"] == expiry
        assert cache["indexed"]["_jws"] == token
    else:
        assert cache["indexed"] is None
        assert cache.get("get") is None
        assert cache.get("default", sentinel) is sentinel
        assert not list(cache.keys())


def test_cache_round_trip_preserves_state_and_raw_values(federation):
    fed = federation
    token = fed.documents[ec_url(LEAF)]
    value = verify_federation_jwt(ENTITY_CONFIGURATION, token, fed.signing).message().to_dict()
    value["_jws"] = token
    cache = ESCache(allowed_delta=600)
    cache[LEAF] = value
    cache["compact"] = fed.documents[ss_url(ANCHOR, LEAF)]
    cache["expiry"] = fed.now + 5400.5
    state = cache.dump()
    assert set(state) == {"_db", "allowed_delta"}
    restored = ESCache().load(deepcopy(state))
    assert restored.dump() == state
    assert restored[LEAF] == value
    assert restored["compact"] == cache["compact"]
    assert restored["expiry"] == fed.now + 5400.5
    fed.clock[0] = value["exp"]
    assert restored.get(LEAF, "absent") == "absent"


def test_cache_message_view_obeys_same_deadline(federation):
    fed = federation
    token = fed.documents[ec_url(LEAF)]
    message = verify_federation_jwt(ENTITY_CONFIGURATION, token, fed.signing).message()
    cache = ESCache()
    cache[LEAF] = message
    assert cache.get(LEAF) is message
    fed.clock[0] = message["exp"]
    assert cache.get(LEAF) is None


@pytest.mark.parametrize("value", [None, False, 0, 123.5, "compact-token"])
def test_raw_scalar_entries_are_not_reinterpreted(value):
    cache = ESCache()
    cache["raw"] = value
    assert cache["raw"] == value
    assert cache.get("raw", object()) == value


@pytest.mark.parametrize("lead", [0, 600])
@pytest.mark.parametrize("fraction", [0, 0.5])
def test_collection_reuses_then_refreshes_at_lead_boundary(federation, lead, fraction):
    fed = federation
    assert TrustChainCollector(fed.resolver.unit_get, {}).allowed_delta == 300
    assert fed.collector.allowed_delta == 600
    fed.collector.allowed_delta = lead
    expiry = fed.now + 1200 + fraction
    original = fed.ec(LEAF, expiry)
    assert collect(fed) == original
    assert len(fed.http.calls) == 3
    assert collect(fed) == original
    fed.clock[0] = expiry - lead - 0.125
    assert collect(fed) == original
    assert len(fed.http.calls) == 3
    replacement = fed.ec(LEAF, expiry + 7200, name="replacement")
    fed.clock[0] = expiry - lead
    assert collect(fed) == replacement
    assert len(fed.http.calls) == 4
    assert fed.collector.get_chain([LEAF, ANCHOR], ANCHOR)[0] == replacement


@pytest.mark.parametrize("operation", ["get_metadata", "get_federation_fetch_endpoint"])
def test_metadata_and_endpoint_discovery_refresh_together(federation, operation):
    fed = federation
    collect(fed)
    expiry = fed.now + 1200.5
    fed.clock[0] = expiry - 600
    fresh = fed.ec(LEAF, expiry + 7200, name="replacement", path="/new-fetch")
    result = getattr(fed.collector, operation)(LEAF)
    if operation == "get_metadata":
        assert result["federation_entity"]["organization_name"] == "replacement"
    else:
        assert result == LEAF + "/new-fetch"
    assert len(fed.http.calls) == 4
    assert fed.collector.config_cache[LEAF]["_jws"] == fresh


@pytest.mark.parametrize("lead", [0, 600])
@pytest.mark.parametrize("missing", [None, "token", "expiry"])
def test_subordinate_pair_refreshes_without_truncation(federation, lead, missing):
    fed = federation
    fed.collector.allowed_delta = lead
    expiry = fed.now + 1200.5
    original = fed.ss(ANCHOR, LEAF, expiry)
    collect(fed)
    token_key, expiry_key = cache_key(ANCHOR, LEAF), time_key(ANCHOR, LEAF)
    assert fed.collector.entity_statement_cache[token_key] == original
    assert fed.collector.entity_statement_cache[expiry_key] == expiry
    if missing:
        del fed.collector.entity_statement_cache[token_key if missing == "token" else expiry_key]
    else:
        fed.clock[0] = expiry - lead - 0.125
        assert fed.collector._get_entity_statement(LEAF, ANCHOR) == original
        assert len(fed.http.calls) == 3
        fed.clock[0] = expiry - lead
    replacement = fed.ss(ANCHOR, LEAF, expiry + 7200)
    assert fed.collector._get_entity_statement(LEAF, ANCHOR) == replacement
    assert fed.collector.entity_statement_cache[expiry_key] == expiry + 7200
    assert fed.http.calls[-1].request.url == ss_url(ANCHOR, LEAF)


def test_failed_pair_refresh_removes_both_entries(federation):
    fed = federation
    expiry = fed.now + 1200.5
    fed.ss(ANCHOR, LEAF, expiry)
    collect(fed)
    fed.clock[0] = expiry
    # A validly signed but expired response is not current-use evidence.
    assert verify_federation_jwt(
        SUBORDINATE_STATEMENT, fed.documents[ss_url(ANCHOR, LEAF)],
        fed.signing).claims()["exp"] == expiry
    assert fed.collector._get_entity_statement(LEAF, ANCHOR) is None
    assert cache_key(ANCHOR, LEAF) not in fed.collector.entity_statement_cache
    assert time_key(ANCHOR, LEAF) not in fed.collector.entity_statement_cache


def test_metadata_without_current_chain_is_available_on_repeated_access(federation):
    fed = federation
    collect(fed)
    fed.clock[0] = fed.now + 5400
    token = fed.ec(LEAF, fed.clock[0] + 3600, name="refreshed")
    expected = verify_federation_jwt(ENTITY_CONFIGURATION, token, fed.signing).claims()["metadata"]
    # EC metadata access does not establish trust through the expired chain.
    assert fed.collector.get_metadata(LEAF) == expected
    count = len(fed.http.calls)
    assert fed.collector.get_metadata(LEAF) == expected
    assert len(fed.http.calls) == count
    assert fed.collector.config_cache[LEAF]["_jws"] == token
    assert cache_key(ANCHOR, LEAF) not in fed.collector.entity_statement_cache


@pytest.mark.parametrize("owner", [OTHER, ANCHOR])
def test_metadata_without_authority_hints_is_consistent(federation, owner):
    fed = federation
    token = fed.ec(owner, fed.now + 7200, name="current EC")
    claims = verify_federation_jwt(ENTITY_CONFIGURATION, token, fed.signing).claims()
    assert "authority_hints" not in claims
    assert (owner in fed.resolver.trust_anchors) is (owner == ANCHOR)
    assert fed.collector.get_metadata(owner) == claims["metadata"]
    assert fed.collector.get_metadata(owner) == claims["metadata"]
    assert len(fed.http.calls) == 1


def test_ec_expiring_during_metadata_collection_is_controlled(federation):
    fed = federation
    expiry = fed.now + 100.5
    fed.ec(LEAF, expiry)
    subordinate = fed.documents[ss_url(ANCHOR, LEAF)]

    def advance_clock(request):
        fed.clock[0] = expiry
        return 200, {"Content-Type": SUBORDINATE_STATEMENT.content_type}, subordinate

    fed.documents[ss_url(ANCHOR, LEAF)] = advance_clock
    with pytest.raises(FailedConfigurationRetrieval, match="expired during metadata retrieval"):
        fed.collector.get_metadata(LEAF)
    assert fed.collector.config_cache[LEAF] is None


@pytest.mark.parametrize("corrected", [False, True])
def test_cached_ec_without_fetch_endpoint_is_refreshed_for_discovery(federation, corrected):
    fed = federation
    token = fed.ec(ANCHOR, fed.now + 7200, path=None)
    fed.collector(ANCHOR)
    assert len(fed.http.calls) == 1
    assert fed.collector.config_cache[ANCHOR]["_jws"] == token
    if corrected:
        token = fed.ec(ANCHOR, fed.now + 7200, path="/corrected-fetch")
    expected = ANCHOR + "/corrected-fetch" if corrected else None
    assert fed.collector.get_federation_fetch_endpoint(ANCHOR) == expected
    assert len(fed.http.calls) == 2
    assert fed.collector.config_cache[ANCHOR]["_jws"] == token
    assert fed.collector.get_federation_fetch_endpoint(ANCHOR) == expected
    assert len(fed.http.calls) == (2 if corrected else 3)


def test_direct_verified_ec_retrieval_rejects_expired_material(federation):
    fed = federation
    token = fed.documents[ec_url(LEAF)]
    fed.clock[0] = fed.now + 1200.5
    assert verify_federation_jwt(ENTITY_CONFIGURATION, token, fed.signing).raw_token() == token
    with pytest.raises(FederationJwtPayloadError, match="expired"):
        fed.collector.get_verified_self_signed_entity_configuration(LEAF)
    assert fed.collector.config_cache[LEAF] is None
