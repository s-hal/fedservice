"""Issuance lifetime configuration through real construction and signed output."""

from copy import deepcopy
from types import SimpleNamespace

from cryptojwt.jwt import utc_time_sans_frac
import pytest

from fedservice import defaults
from fedservice.build_entity import FederationEntityBuilder
from fedservice.entity import FederationEntity
from fedservice.entity.context import FederationContext
from fedservice.entity_statement.create import create_entity_configuration
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import EXPLICIT_REGISTRATION_RESPONSE
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


def construct(path="entity", lifetime=OMITTED, **kwargs):
    """Use public helpers or pass a normalized component spec directly."""
    options = {"entity_id": OWNER, "key_config": deepcopy(KEYS), "signing_alg": "ES256",
               "endpoints": ["entity_configuration", "fetch"],
               "preference": {"organization_name": "Lifetime test"}}
    options.update(kwargs)
    if path == "normalized":
        config = build_entity_config(**options)
        if lifetime is not OMITTED:
            config["server"]["kwargs"]["endpoint"]["entity_configuration"]["kwargs"]["lifetime"] = lifetime
        return FederationEntity(**config)
    if lifetime is not OMITTED:
        options["init_kwargs"] = {"endpoint": {"entity_configuration": {"lifetime": lifetime}}}
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


def source_options(source, value):
    """Select one supported endpoint-setting source without premerging it."""
    if source == "spec":
        specs = deepcopy(defaults.federation_endpoints("entity_configuration"))
        specs["entity_configuration"]["kwargs"]["lifetime"] = value
        return {"endpoints": specs}
    return {source: {"endpoint": {"entity_configuration": {"lifetime": value}}}}


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
