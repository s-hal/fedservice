"""Federation authentication capabilities on reception and real publication."""

from copy import deepcopy
import json

from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.server.client_authn import PrivateKeyJWT
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import InvalidToken
import pytest

from fedservice.entity import FederationEntity
from fedservice.defaults import federation_endpoints
from fedservice.federation_jwt import registry
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.message import FederationEntity as FederationMetadata
from fedservice.message import Metadata
from fedservice.utils import build_entity_config
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from tests.test_08_trust_mark import FEDERATION_CONFIG
from tests.test_08_trust_mark import TRUST_MARK_ISSUER_ID
from tests.test_55_entity_statement_subject_binding import corrupt_signature
from tests.test_82_federation_jwt_algorithms import algorithm_keys
from tests.test_82_federation_jwt_algorithms import compact
from tests.test_82_federation_jwt_algorithms import current_payload
from tests.test_82_federation_jwt_algorithms import ISSUER
from tests.test_82_federation_jwt_algorithms import public_jar


FIELD = "endpoint_auth_signing_alg_values_supported"
ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
OWNER = "https://authentication.example.org"
CLIENT = "https://client.example.org"
OMITTED = object()
MALFORMED = ["RS256", "", {}, True, False, 0, None, [False], [1], [None], [""], ["none"]]


def construct(path="utility", preference=OMITTED, endpoint=OMITTED,
              other=OMITTED, mark=OMITTED, tmp_path=None):
    options = dict(
        entity_id=OWNER, signing_alg="ES256",
        key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]},
        preference={} if preference is OMITTED else {FIELD: preference},
        endpoints=deepcopy(federation_endpoints("entity_configuration", "fetch", "resolve")),
    )
    for name, value in (("fetch", endpoint), ("resolve", other)):
        args = {"client_authn_method": ["private_key_jwt"]}
        if value is not OMITTED:
            args["auth_signing_alg_values"] = value
        options["endpoints"][name]["kwargs"].update(args)
    if mark is not OMITTED:
        spec = deepcopy(FEDERATION_CONFIG[TRUST_MARK_ISSUER_ID]["kwargs"]["trust_mark_entity"])
        spec["kwargs"]["trust_mark_db"]["kwargs"]["https://refeds.org/sirtfi"] = str(tmp_path / "marks")
        spec["kwargs"]["endpoint"]["trust_mark"]["kwargs"]["auth_signing_alg_values"] = mark
        options["trust_mark_entity"] = spec
    before = deepcopy(options)
    if path == "direct":
        entity = FederationEntity(**build_entity_config(**options))
    elif path == "combo":
        entity = make_federation_combo(**options, entity_type={"application": {}})["federation_entity"]
    else:
        entity = make_federation_entity(**options)
    assert options == before
    return entity


def published(entity):
    metadata = entity.get_metadata()["federation_entity"]
    token = entity.get_endpoint("entity_configuration").process_request({})["response"]
    verified = verify_federation_jwt(registry.ENTITY_CONFIGURATION, token, entity.keyjar)
    assert verified.raw_token() == token
    assert verified.header()["alg"] == entity.context.signing_alg
    received = verified.message()["metadata"]["federation_entity"]
    assert received.to_dict() == metadata
    assert not any(name.endswith("_auth_signing_alg_values") for name in metadata)
    assert metadata["federation_fetch_endpoint"] == OWNER + "/fetch"
    assert metadata["federation_fetch_endpoint_auth_methods"] == entity.get_endpoint("fetch").client_authn_method
    return metadata


@pytest.mark.parametrize("value", [OMITTED, [], ALGORITHMS, ["future-alg"]])
def test_peer_capabilities_preserved(value, algorithm_keys):
    key = algorithm_keys["ES256"]
    payload = current_payload(registry.ENTITY_CONFIGURATION, key)
    metadata = {} if value is OMITTED else {FIELD: value}
    payload["metadata"] = {"federation_entity": metadata}
    token = compact(registry.ENTITY_CONFIGURATION, payload, key, "ES256")
    result = verify_federation_jwt(registry.ENTITY_CONFIGURATION, token, public_jar(ISSUER, key))
    assert result.message()["metadata"]["federation_entity"].to_dict() == metadata
    assert result.raw_token() == token


@pytest.mark.parametrize("value", MALFORMED)
def test_signed_original_rejected(value, algorithm_keys):
    key = algorithm_keys["ES256"]
    payload = current_payload(registry.ENTITY_CONFIGURATION, key)
    payload["metadata"] = {"federation_entity": {FIELD: value}}
    token = compact(registry.ENTITY_CONFIGURATION, payload, key, "ES256")
    with pytest.raises(ValueError):
        verify_federation_jwt(registry.ENTITY_CONFIGURATION, token, public_jar(ISSUER, key))


@pytest.mark.parametrize("value", MALFORMED)
def test_current_metadata_rejected(value):
    metadata = FederationMetadata()
    metadata._dict[FIELD] = value
    with pytest.raises(ValueError):
        metadata.verify()
    container = Metadata(federation_entity={})
    container["federation_entity"] = metadata
    with pytest.raises(ValueError):
        container.verify()


@pytest.mark.parametrize("path", ["direct", "utility", "combo"])
@pytest.mark.parametrize("source", ["preference", "endpoint", "both"])
def test_configuration_publication(path, source):
    values = {}
    if source in ("preference", "both"):
        values["preference"] = ALGORITHMS
    if source in ("endpoint", "both"):
        values["endpoint"] = list(reversed(ALGORITHMS))
    entity = construct(path, **values)
    expected = ALGORITHMS if source != "endpoint" else list(reversed(ALGORITHMS))
    assert published(entity)[FIELD] == expected
    assert not entity.keyjar.get_signing_key(issuer_id=OWNER, alg="RS256")


@pytest.mark.parametrize("path", ["utility", "combo"])
def test_late_trust_mark_endpoint(path, tmp_path):
    entity = construct(path, mark=ALGORITHMS, tmp_path=tmp_path)
    assert published(entity)[FIELD] == ALGORITHMS
    assert entity.get_metadata()["federation_entity"]["federation_trust_mark_endpoint_auth_methods"] == ["private_key_jwt"]
    with pytest.raises(ValueError, match="auth_signing_alg_values"):
        construct(path, preference=["ES256"], mark=["RS256"], tmp_path=tmp_path)


@pytest.mark.parametrize("preference,endpoint,expected", [
    (OMITTED, OMITTED, OMITTED), (OMITTED, [], OMITTED), ([], [], []),
    (["RS256"], [], ["RS256"]), (OMITTED, ["RS256"], ["RS256"]),
])
def test_omission_and_empty(preference, endpoint, expected):
    result = published(construct(preference=preference, endpoint=endpoint))
    if expected is OMITTED:
        assert FIELD not in result
    else:
        assert result[FIELD] == expected


@pytest.mark.parametrize("values", [
    {"preference": [], "endpoint": ["RS256"]},
    {"preference": ["ES256"], "endpoint": ["RS256"]},
    {"endpoint": ["ES256"], "other": ["RS256"]},
])
def test_conflicting_sources(values):
    with pytest.raises(ValueError, match="auth_signing_alg_values"):
        construct(**values)


@pytest.mark.parametrize("value", MALFORMED + [["HS256"], ["unknown"]])
@pytest.mark.parametrize("source", ["preference", "endpoint", "mark"])
def test_malformed_local_declarations(source, value, tmp_path):
    with pytest.raises(ValueError, match="auth_signing_alg_values"):
        construct(tmp_path=tmp_path, **{source: value})


def test_mutation_revalidation_and_isolation():
    entity = construct(endpoint=ALGORITHMS, other=list(reversed(ALGORITHMS)))
    second = construct()
    assert published(entity)[FIELD] == ALGORITHMS
    endpoint = entity.get_endpoint("fetch")
    endpoint.auth_signing_alg_values = ["RS256"]
    with pytest.raises(ValueError, match="attribute.*kwargs|kwargs.*attribute"):
        entity.get_metadata()
    endpoint.auth_signing_alg_values = list(reversed(ALGORITHMS))
    assert published(entity)[FIELD] == list(reversed(ALGORITHMS))
    endpoint.client_authn_method = ["none"]
    endpoint.auth_signing_alg_values = "ignored-for-non-private-key-auth"
    assert published(entity)[FIELD] == list(reversed(ALGORITHMS))
    entity.get_endpoint("resolve").kwargs["auth_signing_alg_values"] = []
    assert FIELD not in entity.get_metadata()["federation_entity"]
    assert FIELD not in published(second)


def test_preference_changes_are_revalidated_without_repair():
    entity = construct(preference=["RS256"], endpoint=["RS256"])
    entity.get_preferences()
    assert published(entity)[FIELD] == ["RS256"]
    entity.context.claims.prefer[FIELD] = []
    with pytest.raises(ValueError, match="preference"):
        entity.get_metadata()
    entity.get_endpoint("fetch").kwargs["auth_signing_alg_values"] = []
    assert published(entity)[FIELD] == []
    entity.context.claims.prefer[FIELD] = None
    with pytest.raises(ValueError, match="preference"):
        entity.get_metadata()


def test_local_verifier_capabilities_are_not_federation_issuing_policy():
    entity = construct(preference=["PS256", "EdDSA"])
    assert published(entity)[FIELD] == ["PS256", "EdDSA"]


@pytest.mark.parametrize("alg", ALGORITHMS + ["PS256", "EdDSA"])
def test_real_authentication_independent_of_issuing_algorithm(alg, algorithm_keys):
    entity = construct(preference=ALGORITHMS)
    assert published(entity)[FIELD] == ALGORITHMS
    key = algorithm_keys["RS256" if alg == "PS256" else alg]
    entity.keyjar.import_jwks({"keys": [key.serialize(private=False)]}, CLIENT)
    entity.context.jti_db = {}
    entity.context.cdb = {CLIENT: {"client_id": CLIENT}}
    endpoint = entity.get_endpoint("fetch")
    method = PrivateKeyJWT(entity.unit_get)
    now = utc_time_sans_frac()
    payload = dict(iss=CLIENT, sub=CLIENT, aud=[endpoint.full_path], iat=now, exp=now + 60)

    def assertion(claims):
        return JWS(json.dumps(claims), alg=alg).sign_compact([key])

    result = method.verify({"client_assertion": assertion(payload)}, endpoint=endpoint, client_id=CLIENT)
    assert result["client_id"] == CLIENT
    assert result["jwt"]["sub"] == CLIENT
    assert result["jwt"].jws_header["alg"] == alg
    with pytest.raises(ClientAuthenticationError):
        method.verify({"client_assertion": corrupt_signature(assertion(payload))}, endpoint=endpoint)
    payload["aud"] = ["https://wrong.example.org"]
    with pytest.raises(InvalidToken):
        method.verify({"client_assertion": assertion(payload)}, endpoint=endpoint)
    entity.context.signing_alg = "RS256"
    assert entity.get_metadata()["federation_entity"][FIELD] == ALGORITHMS
