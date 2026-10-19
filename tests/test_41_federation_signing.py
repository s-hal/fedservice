"""Entity-local signing configuration through construction and real issuance."""

import json
from copy import deepcopy
from types import SimpleNamespace

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import NoSuitableSigningKeys
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server.authn_event import create_authn_event
import pytest
from requests import Response
import responses

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_SIGNING_ALGORITHM
from fedservice.entity import FederationEntity
from fedservice.entity.context import FederationContext
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.entity_statement import create
from fedservice.federation_jwt import registry
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.trust_mark_entity.entity import create_trust_mark as create_mark
from fedservice.trust_mark_entity.server.trust_mark import create_trust_mark as endpoint_create_mark
from fedservice.trust_mark_entity.server.trust_mark_list import create_trust_mark as list_create_mark
from fedservice.trust_mark_entity.server.trust_mark_status import create_trust_mark_status_response
from fedservice.utils import build_entity_config
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from tests import test_10_explicit_registration_oidc as oidc_registration
from tests import test_12_explicit_registration_oauth as oauth_registration
from tests.build_federation import build_federation
from tests.build_federation import get_subordinate_info
from tests.entities.openid_provider import OPENID_PROVIDER_CONFIG
from tests.test_08_trust_mark import FEDERATION_CONFIG as MARK_CONFIG
from tests.test_08_trust_mark import TRUST_MARK_ISSUER_ID
from tests.test_55_entity_statement_subject_binding import add_response
from tests.test_55_entity_statement_subject_binding import corrupt_signature
from tests.test_82_federation_jwt_algorithms import algorithm_keys
from tests.test_82_federation_jwt_algorithms import compact
from tests.test_82_federation_jwt_algorithms import current_payload
from tests.test_82_federation_jwt_algorithms import ISSUER


OWNER = "https://owner.example.org"
SUBJECT = "https://subject.example.org"
MARK = "https://refeds.org/sirtfi"
EC_KEYS = {"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]}
RSA_KEYS = {"key_defs": [{"type": "RSA", "use": ["sig"]}]}
BOTH_KEYS = {"key_defs": RSA_KEYS["key_defs"] + EC_KEYS["key_defs"]}
OMITTED = object()


def entity_options(alg=OMITTED, key_config=None):
    result = dict(entity_id=OWNER, key_config=deepcopy(key_config or BOTH_KEYS),
                  endpoints=["entity_configuration", "fetch", "resolve"],
                  services=["entity_configuration", "entity_statement", "resolve",
                            "trust_mark", "trust_mark_status"],
                  preference={"organization_name": "Configured entity"})
    if alg is not OMITTED:
        result["signing_alg"] = alg
    return result


def construct(path, alg=OMITTED, key_config=None):
    options = entity_options(alg, key_config)
    if path == "entity":
        return make_federation_entity(**options)
    if path == "combo_helper":
        return make_federation_combo(**options, entity_type={"application": {}})["federation_entity"]
    if path == "combo_plain":
        return make_federation_combo(**options)
    # Direct construction must expose ignored **kwargs via a real signed output.
    configured = options.pop("signing_alg", OMITTED)
    config = build_entity_config(**options)
    if configured is not OMITTED:
        config["signing_alg"] = configured
    if path == "component":
        return FederationCombo({"entity_id": OWNER, "federation_entity": {
            "class": FederationEntity, "kwargs": config}})["federation_entity"]
    return FederationEntity(**config)


def verified_output(entity, profile, token, alg):
    verified = verify_federation_jwt(profile, token, entity.keyjar)
    header = verified.header()
    assert header["alg"] == alg
    assert header["typ"] == profile.typ
    signing_keys = entity.keyjar.get_signing_key(issuer_id=entity.entity_id, alg=alg)
    assert header["kid"] in {key.kid for key in signing_keys}
    assert verified.raw_token() == token
    assert verified.claims()["iss"] == entity.entity_id
    assert "signing_alg" not in verified.claims()
    return verified


@pytest.mark.parametrize("path", ["entity", "direct", "component", "combo_helper", "combo_plain"])
@pytest.mark.parametrize("key_config", [EC_KEYS, BOTH_KEYS], ids=["ec-only", "both"])
def test_construction_reaches_actual_ec_output(path, key_config):
    entity = construct(path, "ES256", key_config)
    endpoint = entity.get_endpoint("entity_configuration")
    result = endpoint.process_request({"signing_alg": "RS256"})
    verified = verified_output(entity, registry.ENTITY_CONFIGURATION, result["response"], "ES256")
    assert verified.claims()["sub"] == OWNER
    assert verify_self_signed_signature(result["response"])["sub"] == OWNER
    assert entity.context.signing_alg == "ES256"
    assert "signing_alg" not in entity.get_metadata()["federation_entity"]


def test_builder_and_config_forward_scalar_without_mutating_input():
    options = entity_options("ES256", EC_KEYS)
    before = deepcopy(options)
    builder = FederationEntityBuilder(OWNER, key_conf=deepcopy(EC_KEYS), signing_alg="ES256")
    assert builder.conf["signing_alg"] == "ES256"
    config = build_entity_config(**options)
    assert config["signing_alg"] == "ES256"
    entity = FederationEntity(**config)
    token = entity.get_endpoint("entity_configuration").process_request({})["response"]
    verified_output(entity, registry.ENTITY_CONFIGURATION, token, "ES256")
    assert options == before


def test_configuration_wrappers_leave_omission_to_owner():
    assert "signing_alg" not in FederationEntityBuilder(OWNER).conf
    config = build_entity_config(**entity_options())
    assert "signing_alg" not in config
    entity = FederationEntity(**config)
    assert entity.context.signing_alg == DEFAULT_SIGNING_ALGORITHM
    assert entity.context.dump()["signing_alg"] == "RS256"


@pytest.mark.parametrize("path", ["entity", "direct", "component", "combo_helper"])
@pytest.mark.parametrize("value", ["", "  ", None, 0, False, [], {}, "none", "HS256", "unknown", "es256"])
def test_invalid_configuration_is_not_defaulted(path, value):
    with pytest.raises(ValueError) as error:
        construct(path, value, EC_KEYS)
    assert "signing_alg" in str(error.value)
    assert repr(value) in str(error.value)


@pytest.mark.parametrize("alg", [OMITTED, "ES256"], ids=["default", "configured"])
def test_ec_fetch_resolve_and_consumers(alg):
    expected = "RS256" if alg is OMITTED else alg
    owner = construct("entity", alg, RSA_KEYS if alg is OMITTED else EC_KEYS)
    leaf = make_federation_entity(
        SUBJECT, authority_hints=[OWNER], key_config=deepcopy(RSA_KEYS),
        endpoints=["entity_configuration"],
        preference={"organization_name": "Leaf"},
    )
    owner.server.subordinate[SUBJECT] = {"jwks": leaf.keyjar.export_jwks()}
    owner.add_trust_anchor(OWNER, owner.keyjar.export_jwks())
    ec_endpoint = owner.get_endpoint("entity_configuration")
    ec_result = ec_endpoint.process_request({"signing_alg": "HS256"})
    ec = ec_result["response"]
    verified_output(owner, registry.ENTITY_CONFIGURATION, ec, expected)
    ec_envelope = ec_endpoint.do_response(**ec_result)
    assert ("Content-type", registry.ENTITY_CONFIGURATION.content_type) in ec_envelope["http_headers"]
    fetch = owner.get_endpoint("fetch")
    fetched = fetch.process_request({"sub": SUBJECT, "signing_alg": "HS256"})
    ss = fetched["response_msg"]
    verified_output(owner, registry.SUBORDINATE_STATEMENT, ss, expected)
    assert ("Content-type", registry.SUBORDINATE_STATEMENT.content_type) in fetch.do_response(**fetched)["http_headers"]
    leaf_ec = leaf.get_endpoint("entity_configuration").process_request({})["response"]
    endpoint = owner.get_endpoint("resolve")
    with responses.RequestsMock() as http:
        add_response(http, SUBJECT + "/.well-known/openid-federation", leaf_ec)
        add_response(http, OWNER + "/.well-known/openid-federation", ec)
        add_response(http, OWNER + "/fetch?sub=" + SUBJECT, ss)
        result = endpoint.process_request({"sub": SUBJECT, "trust_anchor": [OWNER],
                                           "signing_alg": "HS256"}, with_ta_ec=True)
    verified = verified_output(owner, registry.RESOLVE_RESPONSE, result["response_args"], expected)
    assert verified.claims()["sub"] == SUBJECT
    assert verified.claims()["trust_chain"] == (leaf_ec, ss, ec)
    assert verified.claims()["exp"] <= factory(ec).jwt.payload()["exp"]
    envelope = endpoint.do_response(**result)
    assert ("Content-type", registry.RESOLVE_RESPONSE.content_type) in envelope["http_headers"]
    leaf.keyjar.import_jwks(owner.keyjar.export_jwks(), OWNER)
    with responses.RequestsMock() as http:
        http.add("GET", OWNER + "/resolve", body=envelope["response"],
                 content_type=registry.RESOLVE_RESPONSE.content_type)
        parsed = leaf.client.do_request("resolve", entity_id=OWNER, endpoint=OWNER + "/resolve",
                                        request_args={"sub": SUBJECT, "trust_anchor": OWNER})
    assert parsed["sub"] == SUBJECT
    assert parsed["trust_chain"] == [leaf_ec, ss, ec]


def mark_entity(alg=OMITTED, key_config=None):
    spec = deepcopy(MARK_CONFIG[TRUST_MARK_ISSUER_ID]["kwargs"]["trust_mark_entity"])
    spec["kwargs"].pop("trust_mark_db")
    before = deepcopy(spec)
    entity = make_federation_entity(
        **entity_options(alg, key_config), trust_mark_entity=spec,
        self_signed_trust_mark_entity={
            "class": "fedservice.trust_mark_entity.entity.SelfSignedTrustMarkEntity",
            "kwargs": {"trust_mark_specification": {MARK: {}}}},
    )
    assert spec == before
    return entity


@pytest.mark.parametrize("alg", [OMITTED, "ES256"], ids=["default", "configured"])
def test_trust_mark_operations_and_self_signed_producers(alg):
    expected = "RS256" if alg is OMITTED else alg
    entity = mark_entity(alg, RSA_KEYS if alg is OMITTED else EC_KEYS)
    endpoint = entity.get_endpoint("trust_mark")
    result = endpoint.process_request({"sub": SUBJECT, "trust_mark_type": MARK,
                                       "signing_alg": "HS256"})
    token = result["response"]
    verified_output(entity, registry.TRUST_MARK, token, expected)
    assert entity.server.trust_mark_entity.unpack_trust_mark(token)["sub"] == SUBJECT
    status = entity.get_endpoint("trust_mark_status")
    envelope = status.do_response(**status.process_request({"trust_mark": token, "signing_alg": "HS256"}))
    verified = verified_output(entity, registry.TRUST_MARK_STATUS_RESPONSE, envelope["response"], expected)
    assert verified.claims()["trust_mark"] == token
    response = Response()
    response.status_code = 200
    response._content = envelope["response"].encode("ascii")
    response.headers["Content-Type"] = registry.TRUST_MARK_STATUS_RESPONSE.content_type
    service = entity.get_service("trust_mark_status")
    parsed = entity.client.parse_request_response(service, response, response_body_type="jwt")
    assert parsed["status"] == "active"
    assert parsed["trust_mark"] == token
    for token in (entity.server.trust_mark_entity.self_signed_trust_mark(trust_mark_type=MARK),
                  entity.server.self_signed_trust_mark_entity(MARK)):
        verified = verified_output(entity, registry.TRUST_MARK, token, expected)
        assert verified.claims()["sub"] == OWNER
    assert entity.context.trust_marks == [token]


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
@pytest.mark.parametrize("creator", [create_mark, endpoint_create_mark, list_create_mark])
def test_standalone_mark_helpers(creator, alg):
    entity = construct("direct", "ES256" if alg == "RS256" else "RS256")
    token = creator(entity.keyjar, OWNER, sub=SUBJECT, trust_mark_type=MARK, signing_alg=alg)
    verified_output(entity, registry.TRUST_MARK, token, alg)


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_standalone_statement_and_status_helpers(alg):
    entity = construct("direct", "ES256" if alg == "RS256" else "RS256")
    options = {"signing_alg": alg}
    expected = alg
    kid = entity.keyjar.get_signing_key(issuer_id=OWNER, alg=expected)[0].kid
    ec = create.create_entity_configuration(OWNER, entity.keyjar, kid=kid, **options)
    ss = create.create_subordinate_statement(OWNER, SUBJECT, entity.keyjar, kid=kid, **options)
    now = utc_time_sans_frac()
    metadata = {"federation_entity": {}}
    rr = create.create_resolve_response(OWNER, SUBJECT, entity.keyjar, metadata, [ec, ss], now + 300,
                                        kid=kid, **options)
    er = create.create_explicit_registration_response(
        OWNER, SUBJECT, entity.keyjar, metadata, OWNER, OWNER, now + 300, kid=kid, **options)
    mark = create_mark(entity.keyjar, OWNER, sub=SUBJECT, trust_mark_type=MARK, **options)
    verified_mark = verified_output(entity, registry.TRUST_MARK, mark, expected)
    assert verified_mark.header()["kid"] == kid
    assert verified_mark.claims()["sub"] == SUBJECT
    status = create_trust_mark_status_response(entity.keyjar, OWNER, mark, "active", **options)
    for profile, token in ((registry.ENTITY_CONFIGURATION, ec), (registry.SUBORDINATE_STATEMENT, ss),
                           (registry.RESOLVE_RESPONSE, rr), (registry.EXPLICIT_REGISTRATION_RESPONSE, er),
                           (registry.TRUST_MARK_STATUS_RESPONSE, status)):
        verified = verified_output(entity, profile, token, expected)
        assert verified.header()["kid"] == kid
        if profile is registry.TRUST_MARK_STATUS_RESPONSE:
            assert verified.claims()["trust_mark"] == verified_mark.raw_token()
            assert verified.claims()["status"] == "active"


@pytest.mark.parametrize("alg", [OMITTED, "ES256"], ids=["default", "configured"])
def test_context_and_mark_owner_signing(alg):
    entity = mark_entity(alg, RSA_KEYS if alg is OMITTED else EC_KEYS)
    expected = "RS256" if alg is OMITTED else "ES256"
    kid = entity.keyjar.get_signing_key(issuer_id=OWNER, alg=expected)[0].kid
    chain = SimpleNamespace(anchor=OWNER, iss_path=[SUBJECT, OWNER], exp=utc_time_sans_frac() + 600)
    tokens = [
        (registry.ENTITY_CONFIGURATION, entity.context.create_entity_configuration(OWNER, kid=kid)),
        (registry.EXPLICIT_REGISTRATION_RESPONSE,
         entity.context.create_explicit_registration_response(SUBJECT, {"federation_entity": {}}, chain, kid=kid)),
        (registry.TRUST_MARK, entity.server.trust_mark_entity.create_trust_mark(MARK, SUBJECT)),
        (registry.TRUST_MARK, entity.server.trust_mark_entity.self_signed_trust_mark(trust_mark_type=MARK)),
        (registry.TRUST_MARK, entity.server.self_signed_trust_mark_entity(MARK)),
    ]
    for profile, token in tokens:
        verified_output(entity, profile, token, expected)
    assert entity.context.signing_alg == ("RS256" if alg is OMITTED else alg)


@pytest.mark.parametrize("method", ["ec", "registration", "mark", "self_signed", "published"])
@pytest.mark.parametrize("override", ["ES256", "RS256", None])
def test_owner_rejects_legacy_algorithm_keyword_without_side_effects(method, override):
    entity = mark_entity("ES256", BOTH_KEYS)
    mark = entity.server.trust_mark_entity
    published = entity.server.self_signed_trust_mark_entity
    chain = SimpleNamespace(anchor=OWNER, iss_path=[SUBJECT, OWNER], exp=utc_time_sans_frac() + 600)
    operations = {
        "ec": lambda: entity.context.create_entity_configuration(OWNER, signing_alg=override),
        "registration": lambda: entity.context.create_explicit_registration_response(
            SUBJECT, {"federation_entity": {}}, chain, signing_alg=override),
        "mark": lambda: mark.create_trust_mark(MARK, SUBJECT, signing_alg=override),
        "self_signed": lambda: mark.self_signed_trust_mark(trust_mark_type=MARK, signing_alg=override),
        "published": lambda: published(MARK, signing_alg=override),
    }
    before = deepcopy((mark.issued.dump(), published.issued, entity.context.trust_marks))
    with pytest.raises(TypeError, match="signing_alg"):
        operations[method]()
    assert (mark.issued.dump(), published.issued, entity.context.trust_marks) == before
    assert entity.context.signing_alg == "ES256"


def test_removed_owner_positional_algorithm_cannot_rebind_to_kid():
    entity = mark_entity("ES256", BOTH_KEYS)
    chain = SimpleNamespace(anchor=OWNER, iss_path=[SUBJECT, OWNER], exp=utc_time_sans_frac() + 600)
    with pytest.raises(TypeError):
        entity.context.create_explicit_registration_response(SUBJECT, {}, chain, None, "RS256")
    with pytest.raises(TypeError):
        entity.server.trust_mark_entity.create_trust_mark(MARK, SUBJECT, "RS256")
    with pytest.raises(TypeError):
        entity.server.trust_mark_entity.self_signed_trust_mark("RS256", trust_mark_type=MARK)
    with pytest.raises(TypeError):
        entity.server.self_signed_trust_mark_entity(MARK, "RS256")
    assert entity.server.trust_mark_entity.issued.dump() == {}
    assert entity.server.self_signed_trust_mark_entity.issued == []
    assert entity.context.trust_marks == []


@pytest.mark.parametrize("helper", ["statement", "ec", "ss", "resolve", "registration",
                                  "mark", "endpoint_mark", "list_mark", "status"])
def test_standalone_helpers_require_explicit_algorithm(helper):
    entity = construct("direct", "ES256")
    now = utc_time_sans_frac()
    mark = create_mark(entity.keyjar, OWNER, signing_alg="ES256", sub=SUBJECT, trust_mark_type=MARK)
    operations = {
        "statement": (create.create_entity_statement, (OWNER, OWNER, entity.keyjar, registry.ENTITY_CONFIGURATION)),
        "ec": (create.create_entity_configuration, (OWNER, entity.keyjar)),
        "ss": (create.create_subordinate_statement, (OWNER, SUBJECT, entity.keyjar)),
        "resolve": (create.create_resolve_response, (OWNER, SUBJECT, entity.keyjar, {}, [mark], now + 300)),
        "registration": (create.create_explicit_registration_response,
                         (OWNER, SUBJECT, entity.keyjar, {}, OWNER, OWNER, now + 300)),
        "mark": (create_mark, (entity.keyjar, OWNER)),
        "endpoint_mark": (endpoint_create_mark, (entity.keyjar, OWNER)),
        "list_mark": (list_create_mark, (entity.keyjar, OWNER)),
        "status": (create_trust_mark_status_response, (entity.keyjar, OWNER, mark, "active")),
    }
    operation, args = operations[helper]
    with pytest.raises(TypeError, match="signing_alg"):
        operation(*args)
    with pytest.raises(FederationJwtHeaderError, match="alg"):
        operation(*args, signing_alg=None)


@pytest.mark.parametrize("order", [("ES256", "RS256"), ("RS256", "ES256")])
def test_entity_isolation_and_context_persistence(order):
    policy_before = tuple(profile.allowed_algs for profile in registry.ALL_PROFILES)
    config = entity_options(order[0])
    before = deepcopy(config)
    entities = [make_federation_entity(**config), construct("entity", order[1])]
    assert config == before
    for entity, alg in zip(entities, order):
        token = entity.context.create_entity_configuration(OWNER)
        verified_output(entity, registry.ENTITY_CONFIGURATION, token, alg)
        state = entity.context.dump()
        assert state["signing_alg"] == alg
        restored = FederationContext(entity_id=OWNER, keyjar=entity.keyjar)
        restored.load(state)
        assert restored.signing_alg == alg
        del state["signing_alg"]
        restored.load(state)
        assert restored.signing_alg == alg
        legacy = FederationContext(entity_id=OWNER, keyjar=entity.keyjar)
        legacy.load(state)
        assert legacy.signing_alg == DEFAULT_SIGNING_ALGORITHM
    assert DEFAULT_SIGNING_ALGORITHM == "RS256"
    assert tuple(profile.allowed_algs for profile in registry.ALL_PROFILES) == policy_before


@pytest.mark.parametrize("missing", [False, True])
def test_key_suitability_is_checked_at_signing_without_fallback(missing):
    entity = construct("entity", "ES256", RSA_KEYS)
    if missing:
        entity.keyjar = KeyJar()
        # Keep the existing owner lookup usable while supplying no signing keys.
        entity.keyjar.add_keys(OWNER, [])
    before = entity.keyjar.export_jwks(private=True, issuer_id=OWNER)
    with pytest.raises(FederationJwtKeyResolutionError):
        entity.get_endpoint("entity_configuration").process_request({})
    assert entity.context.signing_alg == "ES256"
    assert entity.keyjar.export_jwks(private=True, issuer_id=OWNER) == before


@pytest.mark.parametrize("alg", sorted(registry.ENTITY_CONFIGURATION.allowed_algs))
def test_configuration_does_not_require_all_verification_keys(alg):
    entity = construct("entity", alg, EC_KEYS)
    assert entity.context.signing_alg == alg


def test_consumer_can_be_constructed_before_signing_keys_are_supplied():
    config = build_entity_config(**entity_options("ES256", EC_KEYS))
    del config["key_conf"]
    jar = KeyJar()
    jar.add_keys(OWNER, [])
    entity = FederationEntity(keyjar=jar, **config)
    assert entity.context.signing_alg == "ES256"
    with pytest.raises(FederationJwtKeyResolutionError):
        entity.get_endpoint("entity_configuration").process_request({})


@pytest.mark.parametrize("source", ["subordinate", "policy", "trust_mark", "self_signed_mark"])
@pytest.mark.parametrize("stored", ["RS256", "ES256"])
def test_stored_control_does_not_override_owner_or_leak(source, stored):
    entity = mark_entity("ES256", BOTH_KEYS)
    entity.server.subordinate[SUBJECT] = {"jwks": entity.keyjar.export_jwks()}
    if source in ("subordinate", "policy"):
        store = getattr(entity.server, source)
        value = dict(store.get(SUBJECT) or {}, signing_alg=stored)
        store[SUBJECT] = value
        operation = lambda: entity.get_endpoint("fetch").process_request({"sub": SUBJECT})["response_msg"]
        profile = registry.SUBORDINATE_STATEMENT
    else:
        unit = (entity.server.trust_mark_entity if source == "trust_mark"
                else entity.server.self_signed_trust_mark_entity)
        value = {"signing_alg": stored}
        unit.trust_mark_specification[MARK] = value
        operation = (lambda: unit.create_trust_mark(MARK, SUBJECT)) if source == "trust_mark" else (lambda: unit(MARK))
        profile = registry.TRUST_MARK
    before = deepcopy(value)
    if stored == "RS256":
        with pytest.raises(ValueError, match="signing_alg.*RS256"):
            operation()
    else:
        verified_output(entity, profile, operation(), "ES256")
    assert value == before


@pytest.mark.parametrize("source", ["trust_mark", "self_signed_mark"])
@pytest.mark.parametrize("stored", ["ES256", "RS256"])
@pytest.mark.parametrize("override", [OMITTED, "ES256", "RS256", None])
def test_trust_mark_stored_control_is_checked_against_owner(source, stored, override):
    entity = mark_entity("ES256", BOTH_KEYS)
    unit = (entity.server.trust_mark_entity if source == "trust_mark"
            else entity.server.self_signed_trust_mark_entity)
    specification = {MARK: {"signing_alg": stored}}
    unit.trust_mark_specification = specification
    specification_before = deepcopy(specification)
    issued_before = deepcopy(unit.issued.dump() if source == "trust_mark" else unit.issued)
    published_before = list(entity.context.trust_marks)
    options = {} if override is OMITTED else {"signing_alg": override}

    def issue():
        if source == "trust_mark":
            return unit.create_trust_mark(MARK, SUBJECT, **options)
        return unit(MARK, **options)

    if override is not OMITTED or stored != "ES256":
        error = TypeError if override is not OMITTED else ValueError
        with pytest.raises(error, match="signing_alg"):
            issue()
        issued_after = unit.issued.dump() if source == "trust_mark" else unit.issued
        assert issued_after == issued_before
        assert entity.context.trust_marks == published_before
    else:
        token = issue()
        verified = verified_output(entity, registry.TRUST_MARK, token, "ES256")
        assert verified.claims()["sub"] == (SUBJECT if source == "trust_mark" else OWNER)
        assert verified.claims()["trust_mark_type"] == MARK
        issued_claims = {key: value for key, value in verified.claims().items() if key != "iss"}
        if source == "trust_mark":
            assert unit.issued[MARK][SUBJECT] == issued_claims
            assert entity.context.trust_marks == published_before
        else:
            assert unit.issued == issued_before + [issued_claims]
            assert entity.context.trust_marks == published_before + [token]
    assert unit.trust_mark_specification is specification
    assert specification == specification_before
    assert entity.context.signing_alg == "ES256"
    assert DEFAULT_SIGNING_ALGORITHM == "RS256"


@pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512"])
def test_ec_only_issuer_still_verifies_rsa_peers(alg, algorithm_keys):
    entity = construct("entity", "ES256", EC_KEYS)
    key = algorithm_keys[alg]
    entity.keyjar.import_jwks({"keys": [key.serialize(private=False)]}, ISSUER)
    token = compact(registry.TRUST_MARK, current_payload(registry.TRUST_MARK, key), key, alg)
    assert verify_federation_jwt(registry.TRUST_MARK, token, entity.keyjar).raw_token() == token
    with pytest.raises(FederationJwtSignatureError):
        verify_federation_jwt(registry.TRUST_MARK, corrupt_signature(token), entity.keyjar)
    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(registry.RESOLVE_RESPONSE, token, entity.keyjar)


@pytest.mark.parametrize("protocol", ["oidc", "oauth"])
def test_explicit_registration_context_callers_use_ec_only_owner(protocol, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    module = oidc_registration if protocol == "oidc" else oauth_registration
    config = deepcopy(module.FEDERATION_CONFIG)
    server_id = module.OP_ID if protocol == "oidc" else module.AS_ID
    server_options = config.pop(server_id)["kwargs"]
    config[module.TA_ID]["subordinates"].remove(server_id)
    federation = build_federation(config)
    app_config = deepcopy(OPENID_PROVIDER_CONFIG if protocol == "oidc"
                           else server_options["entity_type_config"])
    app_type = "openid_provider" if protocol == "oidc" else "oauth_authorization_server"
    combo = make_federation_combo(
        server_id, signing_alg="ES256", key_config=deepcopy(EC_KEYS),
        authority_hints=[module.TA_ID], endpoints=["entity_configuration"],
        trust_anchors={module.TA_ID: federation[module.TA_ID].keyjar.export_jwks()},
        entity_type={app_type: {"class": "fedservice.appserver.ServerEntity", "kwargs": {
            "config": app_config, "key_conf": deepcopy(BOTH_KEYS)}}},
    )
    federation[module.TA_ID].server.subordinate[server_id] = get_subordinate_info(combo)
    flow = module.TestRpService()
    flow.ta, flow.im, flow.rp = (federation[item] for item in (module.TA_ID, module.IM_ID, module.RP_ID))
    if protocol == "oidc":
        flow.op = combo
        context = flow.rp["openid_relying_party"].context
        context.issuer = server_id
        context.construct_uris(context.get_preference("response_types_supported", []))
        flow.entity_config_service = flow.rp["federation_entity"].get_service("entity_configuration")
        flow.entity_config_service.upstream_get("context").issuer = server_id
        flow.registration_service = flow.rp["federation_entity"].get_service("registration")
    else:
        flow.oas = combo
        flow.registration_service = flow.rp["oauth_client"].get_service("registration")
    token, request, _ = flow._registration_response()
    verified_output(combo["federation_entity"], registry.EXPLICIT_REGISTRATION_RESPONSE, token, "ES256")
    parsed = flow._parse_registration_response_with_fallback(token, request)
    assert parsed["metadata"]["openid_relying_party" if protocol == "oidc" else "oauth_client"]["client_id"]


def application_combo(federation_alg, application_alg, application_keys):
    config = deepcopy(OPENID_PROVIDER_CONFIG)
    config["token_handler_args"]["jwks_def"]["private_path"] = ""
    config["token_handler_args"]["token"]["kwargs"]["alg"] = application_alg
    return make_federation_combo(
        OWNER, signing_alg=federation_alg,
        key_config=deepcopy(EC_KEYS if federation_alg == "ES256" else RSA_KEYS),
        endpoints=["entity_configuration"],
        entity_type={"openid_provider": {"class": "fedservice.appserver.ServerEntity",
                     "kwargs": {"config": config, "key_conf": deepcopy(application_keys)}}},
    )


def application_session(application, client_info):
    context = application.context
    context.cdb[SUBJECT] = dict(client_info)
    request = AuthorizationRequest(client_id=SUBJECT, response_type=["code"],
                                   scope=["openid"], redirect_uri=SUBJECT + "/cb", nonce="nonce")
    return context.session_manager.create_session(
        create_authn_event("user", "password"), request, user_id="user", client_id=SUBJECT)


@pytest.mark.parametrize("federation_alg,application_alg", [("ES256", "RS256"), ("RS256", "ES256")])
def test_application_signing_is_independent_of_federation(federation_alg, application_alg, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    combo = application_combo(federation_alg, application_alg,
                              RSA_KEYS if application_alg == "RS256" else EC_KEYS)
    federation = combo["federation_entity"]
    application = combo["openid_provider"]
    assert application.keyjar is not federation.keyjar
    application_keys = application.keyjar.export_jwks(private=True, issuer_id=OWNER)
    federation_keys = federation.keyjar.export_jwks(private=True, issuer_id=OWNER)
    assert application_keys != federation_keys
    verified_output(federation, registry.ENTITY_CONFIGURATION,
                    federation.context.create_entity_configuration(OWNER), federation_alg)
    sid = application_session(application, {
        "id_token_signed_response_alg": application_alg,
        "userinfo_signed_response_alg": application_alg,
    })
    handlers = application.context.session_manager.token_handler
    id_token = handlers["id_token"](session_id=sid, name="Test user")
    userinfo = application.get_endpoint("userinfo").do_response(
        response_args={"sub": "user", "name": "Test user"}, client_id=SUBJECT)
    access_token = handlers["access_token"](session_id=sid, sub="user", client_id=SUBJECT, aud=[SUBJECT])
    for token in (id_token, userinfo["response"], access_token):
        payload = JWT(key_jar=application.keyjar, allowed_sign_algs=[application_alg]).unpack(token)
        assert payload["iss"] == OWNER
        assert payload["sub"]
        header = factory(token).jwt.headers
        assert header["alg"] == application_alg
        assert header["kid"] in {key.kid for key in application.keyjar.get_signing_key(
            issuer_id=OWNER, alg=application_alg)}
        assert "signing_alg" not in payload
    assert ("Content-type", "application/jwt") in userinfo["http_headers"]
    assert handlers["access_token"].alg == application_alg
    assert federation.context.signing_alg == federation_alg
    assert application.keyjar.export_jwks(private=True, issuer_id=OWNER) == application_keys
    assert federation.keyjar.export_jwks(private=True, issuer_id=OWNER) == federation_keys


def test_application_defaults_and_unsigned_userinfo_survive(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    combo = application_combo("ES256", "RS256", RSA_KEYS)
    application = combo["openid_provider"]
    sid = application_session(application, {})
    token = application.context.session_manager.token_handler["id_token"](session_id=sid, name="Test user")
    assert JWT(key_jar=application.keyjar, allowed_sign_algs=["RS256"]).unpack(token)["iss"] == OWNER
    assert factory(token).jwt.headers["alg"] == "RS256"
    response = application.get_endpoint("userinfo").do_response(
        response_args={"sub": "user"}, client_id=SUBJECT)
    assert json.loads(response["response"]) == {"sub": "user"}
    assert ("Content-type", "application/json") in response["http_headers"]
    assert combo["federation_entity"].context.signing_alg == "ES256"


def test_application_missing_key_is_not_rescued_by_federation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    combo = application_combo("ES256", "RS256", EC_KEYS)
    application = combo["openid_provider"]
    sid = application_session(application, {"id_token_signed_response_alg": "RS256"})
    before = application.keyjar.export_jwks(private=True, issuer_id=OWNER)
    with pytest.raises(NoSuitableSigningKeys):
        application.context.session_manager.token_handler["id_token"](session_id=sid, name="Test user")
    assert application.keyjar.export_jwks(private=True, issuer_id=OWNER) == before
    assert application.context.cdb[SUBJECT]["id_token_signed_response_alg"] == "RS256"
    federation = combo["federation_entity"]
    verified_output(federation, registry.ENTITY_CONFIGURATION,
                    federation.context.create_entity_configuration(OWNER), "ES256")
