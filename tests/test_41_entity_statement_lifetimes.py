"""Issuance lifetime configuration through real construction and signed output."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.storage.abfile import AbstractFileSystem
import pytest

from fedservice import defaults
from fedservice.build_entity import FederationEntityBuilder
from fedservice.entity import FederationEntity
from fedservice.entity.context import FederationContext
from fedservice.entity_statement.create import create_entity_configuration
from fedservice.entity_statement.create import create_subordinate_statement
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import EXPLICIT_REGISTRATION_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.utils import build_entity_config
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity


OWNER = "https://issuer.example.org"
SUBJECT = "https://subject.example.org"
KEYS = {"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]}
OMITTED = object()
INVALID = [0, -1, True, False, None, 60.0, "60", [], {}]


@pytest.fixture
def clock(monkeypatch):
    current = [utc_time_sans_frac()]
    for module in ("cryptojwt.jwt", "fedservice.federation_jwt.jose",
                   "fedservice.entity_statement.create"):
        monkeypatch.setattr(module + ".utc_time_sans_frac", lambda: current[0])
    return current


def construct(path="entity", lifetime=OMITTED, endpoint_name="entity_configuration", **kwargs):
    """Use public helpers or pass a normalized component spec directly."""
    options = {"entity_id": OWNER, "key_config": deepcopy(KEYS), "signing_alg": "ES256",
               "endpoints": ["entity_configuration", "fetch"],
               "preference": {"organization_name": "Lifetime test"}}
    options.update(kwargs)
    if path == "normalized":
        config = build_entity_config(**options)
        if lifetime is not OMITTED:
            config["server"]["kwargs"]["endpoint"][endpoint_name]["kwargs"]["lifetime"] = lifetime
        return FederationEntity(**config)
    if lifetime is not OMITTED:
        options["init_kwargs"] = {"endpoint": {endpoint_name: {"lifetime": lifetime}}}
    if path == "combo":
        return make_federation_combo(**options, entity_type={"application": {}})["federation_entity"]
    return make_federation_entity(**options)


def ec_claims(entity, token):
    """Verify exact EC output using the issuing entity's keys and expected profile."""
    verified = verify_federation_jwt(ENTITY_CONFIGURATION, token, entity.keyjar)
    assert verified.header()["alg"] == "ES256"
    assert verified.header()["typ"] == ENTITY_CONFIGURATION.typ
    assert verified.raw_token() == token
    claims = verified.claims()
    assert claims["iss"] == claims["sub"] == OWNER
    assert "lifetime" not in claims
    assert all("lifetime" not in metadata for metadata in claims.get("metadata", {}).values())
    return claims


def issued_ec(entity):
    endpoint = entity.get_endpoint("entity_configuration")
    result = endpoint.process_request({"lifetime": 1}, lifetime=2)
    envelope = endpoint.do_response(**result)
    assert ("Content-type", ENTITY_CONFIGURATION.content_type) in envelope["http_headers"]
    return ec_claims(entity, result["response"])


@pytest.mark.parametrize("path", ["entity", "combo", "normalized"])
@pytest.mark.parametrize("lifetime", [OMITTED, 1, 604800], ids=["default", "one-second", "seven-days"])
def test_ec_configuration_reaches_on_demand_output(clock, path, lifetime):
    entity = construct(path, lifetime)
    expected = defaults.DEFAULT_ENTITY_CONFIGURATION_LIFETIME if lifetime is OMITTED else lifetime
    assert defaults.DEFAULT_ENTITY_CONFIGURATION_LIFETIME == 86400
    for now in (clock[0], clock[0] + 10):
        clock[0] = now
        claims = issued_ec(entity)
        assert claims["iat"] == now
        assert claims["exp"] - claims["iat"] == expected
        assert claims["metadata"]["federation_entity"]["organization_name"] == "Lifetime test"
    assert "lifetime" not in entity.get_metadata()["federation_entity"]


def source_options(source, value, endpoint_name="entity_configuration"):
    """Select one supported endpoint-setting source without premerging it."""
    if source == "spec":
        specs = deepcopy(defaults.federation_endpoints(endpoint_name))
        specs[endpoint_name]["kwargs"]["lifetime"] = value
        return {"endpoints": specs}
    return {source: {"endpoint": {endpoint_name: {"lifetime": value}}}}


@pytest.mark.parametrize("source", ["init_kwargs", "item_args", "spec", "normalized"])
@pytest.mark.parametrize("value", INVALID)
def test_invalid_ec_settings_fail_construction(source, value):
    with pytest.raises(ValueError) as error:
        if source == "normalized":
            construct("normalized", value)
        else:
            construct(**source_options(source, value))
    assert "entity_configuration.lifetime" in str(error.value)
    assert repr(value) in str(error.value)


@pytest.mark.parametrize("sources", [
    ("init_kwargs", "item_args"), ("spec", "init_kwargs"), ("spec", "item_args"),
])
@pytest.mark.parametrize("second", [604800, 3600, True])
def test_explicit_lifetime_sources_must_be_valid_and_agree(clock, sources, second):
    options = source_options(sources[0], 604800)
    options.update(source_options(sources[1], second))
    before = deepcopy(options)
    if second == 604800:
        claims = issued_ec(construct(**options))
        assert claims["exp"] - claims["iat"] == 604800
    else:
        with pytest.raises(ValueError, match="entity_configuration.lifetime"):
            construct(**options)
    assert options == before


@pytest.mark.parametrize("order", [(604800, OMITTED, 3600), (3600, OMITTED, 604800)])
def test_endpoint_settings_are_instance_local(clock, order):
    global_before = deepcopy(defaults.FEDERATION_ENDPOINTS)
    entities = [construct(lifetime=lifetime) for lifetime in order]
    for entity, lifetime in zip(entities, order):
        claims = issued_ec(entity)
        assert claims["exp"] - claims["iat"] == (86400 if lifetime is OMITTED else lifetime)
    assert defaults.FEDERATION_ENDPOINTS == global_before


def test_endpoint_builder_owns_specs_and_overrides_without_changing_other_precedence():
    specs = deepcopy(defaults.federation_endpoints("entity_configuration"))
    initial = {"entity_configuration": {"lifetime": 604800, "custom": {"source": "initial"}}}
    item = {"entity_configuration": {"lifetime": 604800, "custom": {"source": "item"}}}
    before = deepcopy((specs, initial, item, defaults.FEDERATION_ENDPOINTS))
    builder = FederationEntityBuilder(OWNER)
    builder.add_endpoints(kwargs_spec=initial, args=item, **specs)
    copied = builder.conf["server"]["kwargs"]["endpoint"]["entity_configuration"]["kwargs"]
    assert copied["custom"] == {"source": "item"}
    copied["custom"]["source"] = "changed"
    assert (specs, initial, item, defaults.FEDERATION_ENDPOINTS) == before
    builder.add_endpoints(kwargs_spec=initial, **specs)
    copied = builder.conf["server"]["kwargs"]["endpoint"]["entity_configuration"]["kwargs"]
    copied["custom"]["source"] = "changed again"
    assert (specs, initial, item, defaults.FEDERATION_ENDPOINTS) == before


@pytest.mark.parametrize("source", ["init_kwargs", "item_args", "spec"])
def test_reusing_public_inputs_leaves_lifetimes_isolated(clock, source):
    options = source_options(source, 604800)
    before = deepcopy(options)
    entities = [construct(**options), construct(), construct(**options)]
    assert options == before
    for entity, expected in zip(entities, (604800, 86400, 604800)):
        claims = issued_ec(entity)
        assert claims["exp"] - claims["iat"] == expected


@pytest.mark.parametrize("duration", [OMITTED, 0, None, False, 1200])
def test_context_inherits_ec_endpoint_but_not_registration_lifetime(clock, duration):
    entity = construct(lifetime=604800)
    original_default = entity.context.default_lifetime
    kwargs = {} if duration is OMITTED else {"lifetime": duration}
    token = entity.context.create_entity_configuration(OWNER, **kwargs)
    claims = ec_claims(entity, token)
    assert claims["exp"] - claims["iat"] == (1200 if duration == 1200 else 604800)
    assert entity.context.default_lifetime == original_default == 86400
    chain = SimpleNamespace(anchor=OWNER, iss_path=[SUBJECT, OWNER], exp=clock[0] + 1000000)
    registration = entity.context.create_explicit_registration_response(
        SUBJECT, {"federation_entity": {}}, chain)
    claims = verify_federation_jwt(EXPLICIT_REGISTRATION_RESPONSE, registration, entity.keyjar).claims()
    assert claims["exp"] - claims["iat"] == original_default


@pytest.mark.parametrize("standalone", [True, False])
def test_context_without_ec_endpoint_retains_legacy_default(clock, standalone):
    entity = construct(endpoints=["fetch"])
    context = (FederationContext(entity_id=OWNER, keyjar=entity.keyjar, signing_alg="ES256")
               if standalone else entity.context)
    context.default_lifetime = 1234
    for kwargs in ({}, {"lifetime": 0}, {"lifetime": 60}):
        token = context.create_entity_configuration(OWNER, key_jar=entity.keyjar, **kwargs)
        claims = ec_claims(entity, token)
        assert claims["exp"] - claims["iat"] == (kwargs.get("lifetime") or 1234)


def test_standalone_ec_helper_preserves_default_explicit_and_zero_durations(clock):
    entity = construct(lifetime=604800)
    for kwargs, expected in (({}, 86400), ({"lifetime": 60}, 60),
                             ({"lifetime": 0, "exp": clock[0] + 120}, 120)):
        token = create_entity_configuration(OWNER, entity.keyjar, signing_alg="ES256", **kwargs)
        claims = ec_claims(entity, token)
        assert claims["exp"] - claims["iat"] == expected


def issued_ss(entity, subject=SUBJECT):
    """Verify Fetch output, including its HTTP media type and issuance control isolation."""
    endpoint = entity.get_endpoint("fetch")
    result = endpoint.process_request({"sub": subject, "lifetime": 1}, lifetime=2)
    envelope = endpoint.do_response(**result)
    assert ("Content-type", SUBORDINATE_STATEMENT.content_type) in envelope["http_headers"]
    token = result["response_msg"]
    verified = verify_federation_jwt(SUBORDINATE_STATEMENT, token, entity.keyjar)
    assert verified.raw_token() == token
    assert verified.header()["alg"] == "ES256"
    claims = verified.claims()
    assert claims["iss"] == OWNER and claims["sub"] == subject
    assert "lifetime" not in claims
    assert "lifetime" not in entity.get_metadata()["federation_entity"]
    return claims


@pytest.mark.parametrize("path", ["entity", "combo", "normalized"])
@pytest.mark.parametrize("lifetime", [OMITTED, 1, 604800], ids=["default", "one-second", "seven-days"])
def test_ss_configuration_reaches_on_demand_output(clock, path, lifetime):
    entity = construct(path, lifetime, endpoint_name="fetch")
    entity.server.subordinate[SUBJECT] = {"jwks": {"keys": []}}
    expected = defaults.DEFAULT_SUBORDINATE_STATEMENT_LIFETIME if lifetime is OMITTED else lifetime
    assert defaults.DEFAULT_SUBORDINATE_STATEMENT_LIFETIME == 86400
    for now in (clock[0], clock[0] + 10):
        clock[0] = now
        claims = issued_ss(entity)
        assert claims["iat"] == now
        assert claims["exp"] - claims["iat"] == expected


@pytest.mark.parametrize("source", ["init_kwargs", "item_args", "spec", "normalized"])
@pytest.mark.parametrize("value", INVALID)
def test_invalid_ss_node_settings_fail_construction(source, value):
    with pytest.raises(ValueError) as error:
        if source == "normalized":
            construct("normalized", value, endpoint_name="fetch")
        else:
            construct(**source_options(source, value, "fetch"))
    assert "fetch.lifetime" in str(error.value)
    assert repr(value) in str(error.value)


@pytest.mark.parametrize("sources", [
    ("init_kwargs", "item_args"), ("spec", "init_kwargs"), ("spec", "item_args"),
])
@pytest.mark.parametrize("second", [604800, 3600, True])
def test_ss_duplicate_sources_must_be_valid_and_agree(clock, sources, second):
    options = source_options(sources[0], 604800, "fetch")
    options.update(source_options(sources[1], second, "fetch"))
    before = deepcopy(options)
    if second == 604800:
        entity = construct(**options)
        entity.server.subordinate[SUBJECT] = {"jwks": {"keys": []}}
        claims = issued_ss(entity)
        assert claims["exp"] - claims["iat"] == 604800
    else:
        with pytest.raises(ValueError, match="fetch.lifetime"):
            construct(**options)
    assert options == before


@pytest.fixture(params=["dictionary", "filesystem"])
def ss_issuer(request, tmp_path):
    options = {"init_kwargs": {"endpoint": {
        "entity_configuration": {"lifetime": 3600}, "fetch": {"lifetime": 604800}}}}
    before = deepcopy(options)
    entity = construct(**options)
    assert options == before
    if request.param == "filesystem":
        entity.server.subordinate = AbstractFileSystem(
            str(tmp_path / "subordinates"), key_conv="idpyoidc.util.Base64",
            value_conv="idpyoidc.util.JSON")
    return entity


@pytest.mark.parametrize("override", [OMITTED, 7200], ids=["inherit", "override"])
@pytest.mark.parametrize("policy_lifetime", [OMITTED, 15, None], ids=["absent", "ignored", "invalid-ignored"])
def test_record_precedence_is_independent_of_policy_and_subject(clock, ss_issuer, override, policy_lifetime):
    entity = ss_issuer
    other = "https://other.example.org"
    records = {subject: {"jwks": {"keys": []}, "entity_types": ["federation_entity"]}
               for subject in (SUBJECT, other)}
    if override is not OMITTED:
        records[SUBJECT]["lifetime"] = override
    policy = {"metadata": {"federation_entity": {
        "organization_name": "Subject", "extension": {"lifetime": "preserved"}}},
        "metadata_policy": {"federation_entity": {"organization_name": {"value": "Policy"}}},
        "registration_policy": []}
    if policy_lifetime is not OMITTED:
        policy["lifetime"] = policy_lifetime
    before = deepcopy((records, policy, defaults.FEDERATION_ENDPOINTS))
    entity.server.policy[SUBJECT] = policy
    for subject, record in records.items():
        entity.server.subordinate[subject] = record
    for subject in (SUBJECT, other, SUBJECT):
        claims = issued_ss(entity, subject)
        expected = override if subject == SUBJECT and override is not OMITTED else 604800
        assert claims["exp"] - claims["iat"] == expected
        if subject == SUBJECT:
            assert claims["metadata"] == policy["metadata"]
            assert claims["metadata_policy"] == policy["metadata_policy"]
            assert claims["registration_policy"] == ()
    assert {subject: entity.server.subordinate.get(subject) for subject in records} == before[0]
    assert (records, policy, defaults.FEDERATION_ENDPOINTS) == before
    ec = issued_ec(entity)
    assert ec["exp"] - ec["iat"] == 3600
    default_entity = construct()
    default_entity.server.subordinate[SUBJECT] = {"jwks": {"keys": []}}
    claims = issued_ss(default_entity)
    assert claims["exp"] - claims["iat"] == 86400


@pytest.mark.parametrize("value", INVALID)
def test_bad_record_lifetime_never_signs_or_falls_back(clock, ss_issuer, monkeypatch, value):
    entity = ss_issuer
    record = {"jwks": entity.keyjar.export_jwks(), "lifetime": value}
    before = deepcopy(record)
    entity.server.subordinate[SUBJECT] = record
    entity.server.policy[SUBJECT] = {"lifetime": 604800}
    signer = Mock(wraps=create_subordinate_statement)
    monkeypatch.setattr("fedservice.entity.server.fetch.create_subordinate_statement", signer)
    with pytest.raises(ValueError) as error:
        entity.get_endpoint("fetch").process_request({"sub": SUBJECT})
    assert "lifetime" in str(error.value) and SUBJECT in str(error.value)
    assert "jwks" not in str(error.value)
    signer.assert_not_called()
    assert entity.server.subordinate.get(SUBJECT) == record == before


def test_standalone_ss_helper_retains_default_and_explicit_durations(clock):
    entity = construct(lifetime=604800, endpoint_name="fetch")
    for kwargs, expected in (({}, 86400), ({"lifetime": 60}, 60),
                             ({"lifetime": 0, "exp": clock[0] + 120}, 120)):
        token = create_subordinate_statement(
            OWNER, SUBJECT, entity.keyjar, signing_alg="ES256", **kwargs)
        claims = verify_federation_jwt(SUBORDINATE_STATEMENT, token, entity.keyjar).claims()
        assert claims["exp"] - claims["iat"] == expected
