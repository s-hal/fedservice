"""Pure payload checks and schema-owned original-input hooks."""

from copy import deepcopy

from idpyoidc.message import Message
import pytest

from fedservice.message import _validate_entity_identifier
from fedservice.message import _validate_metadata
from fedservice.message import FederationPayloadMessage
from fedservice.message import EntityConfiguration
from fedservice.message import SubordinateStatement
from fedservice.message import ExplicitRegistrationResponse
from idpyoidc.exception import MissingRequiredAttribute
from fedservice import payload_validation
from fedservice.federation_jwt.registry import ALL_PROFILES


@pytest.mark.parametrize("value,error", [
    (None, "metadata must be a JSON object"),
    ({"extension": []}, "metadata extension must be a JSON object"),
    ({"extension": {"name": None}}, "metadata extension parameter name must not be null"),
])
def test_metadata_predicate_diagnostics(value, error):
    before = deepcopy(value)
    with pytest.raises(ValueError) as exc:
        _validate_metadata(value)
    assert str(exc.value) == error
    assert value == before


@pytest.mark.parametrize("value", ["http://example.org", "https://example.org?", "https://a@@b"])
def test_identifier_predicate_diagnostics(value):
    with pytest.raises(ValueError) as exc:
        _validate_entity_identifier(value, "sub")
    assert str(exc.value) == "sub must be an HTTPS Entity Identifier without query or fragment"


def test_predicates_accept_existing_local_representations():
    metadata = {"extension": {"object": {"nested": None}, "empty": [], "name": ""}}
    before = deepcopy(metadata)
    assert _validate_metadata(metadata) is None
    assert _validate_metadata(Message(extension=Message(**metadata["extension"]))) is None
    assert _validate_entity_identifier("https://example.org/a%2Fb", "iss") is None
    assert metadata == before


def test_old_imports_reexport_the_single_predicate_implementations():
    assert _validate_metadata is payload_validation._validate_metadata
    assert _validate_entity_identifier is payload_validation._validate_entity_identifier


@pytest.mark.parametrize("value", [None, [], [None], "{}", 0, False, Message()])
def test_input_hook_rejects_nonobjects(value):
    with pytest.raises(ValueError, match="payload must be a JSON object"):
        FederationPayloadMessage.validate_input(value)


def test_input_hook_cooperative_extension_is_read_only():
    calls = []

    class LocalPayload(FederationPayloadMessage):
        def __init__(self, **kwargs):
            raise AssertionError("input checks must not construct messages")

        def verify(self, **kwargs):
            raise AssertionError("input checks must not verify objects")

        @classmethod
        def validate_input(cls, payload, *, source_json=None):
            super().validate_input(payload, source_json=source_json)
            calls.append(source_json)
            if "extension" not in payload:
                raise ValueError("extension required locally")

    value = {"extension": {"nested": [None, False, 0, [], {}]}}
    before = deepcopy(value)
    assert LocalPayload.validate_input(value, source_json=b"source") is None
    assert value == before
    assert calls == [b"source"]
    with pytest.raises(ValueError, match="extension required locally"):
        LocalPayload.validate_input({})


@pytest.mark.parametrize("schema", [profile.message_cls for profile in ALL_PROFILES],
                         ids=[profile.name for profile in ALL_PROFILES])
def test_registered_roots_inherit_common_hook(schema):
    assert issubclass(schema, FederationPayloadMessage)
    assert schema.validate_input(statement_input()) is None
    with pytest.raises(ValueError, match="JSON object"):
        schema.validate_input([])


def statement_input(**claims):
    payload = {"iss": "https://entity.example.org", "sub": "https://entity.example.org",
               "iat": 0, "exp": 1.5, "jwks": {"keys": []}}
    payload.update(claims)
    return payload


@pytest.mark.parametrize("schema", [EntityConfiguration, SubordinateStatement])
@pytest.mark.parametrize("claim", ["iss", "sub", "iat", "exp", "jwks"])
def test_statement_input_requires_common_claim_presence(schema, claim):
    value = statement_input()
    del value[claim]
    with pytest.raises(MissingRequiredAttribute, match=claim):
        schema.validate_input(value)


@pytest.mark.parametrize("schema", [EntityConfiguration, SubordinateStatement])
@pytest.mark.parametrize("claims", [
    {"iss": None}, {"sub": "http://example.org"}, {"iat": False}, {"exp": "1"},
    {"iat": float("inf")}, {"exp": None}, {"jwks": None}, {"jwks": {}},
    {"jwks": {"keys": [None]}}, {"jwks": {"keys": ""}},
    {"crit": []}, {"crit": "extension", "extension": 0},
    {"crit": ["extension", "extension"], "extension": 0},
    {"crit": ["iss"]}, {"crit": ["absent"]},
])
def test_statement_input_rejects_original_common_values(schema, claims):
    with pytest.raises(ValueError):
        schema.validate_input(statement_input(**claims))


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints"])
@pytest.mark.parametrize("value", [None, [], "https://example.org", ["http://example.org"]])
def test_ec_input_checks_hints(claim, value):
    with pytest.raises(ValueError, match=claim):
        EntityConfiguration.validate_input(statement_input(**{claim: value}))


@pytest.mark.parametrize("schema,claims", [
    (EntityConfiguration, {"metadata_policy": {}}),
    (EntityConfiguration, {"metadata_policy_crit": []}),
    (EntityConfiguration, {"constraints": None}),
    (EntityConfiguration, {"source_endpoint": ""}),
    (SubordinateStatement, {"authority_hints": []}),
    (SubordinateStatement, {"trust_anchor_hints": None}),
    (SubordinateStatement, {"trust_marks": False}),
    (SubordinateStatement, {"trust_mark_issuers": {}}),
    (SubordinateStatement, {"trust_mark_owners": ""}),
])
def test_original_claim_placement(schema, claims):
    with pytest.raises(ValueError, match=next(iter(claims))):
        schema.validate_input(statement_input(**claims))


def test_statement_input_controls_and_cooperative_subclass():
    seen = []

    class LocalConfiguration(EntityConfiguration):
        @classmethod
        def validate_input(cls, payload, *, source_json=None):
            super().validate_input(payload, source_json=source_json)
            seen.append(source_json)

    payload = statement_input(crit=["extension"], extension={"nested": [None, False, 0]},
                              authority_hints=["https://superior.example.org"])
    before = deepcopy(payload)
    assert LocalConfiguration.validate_input(payload, source_json=b"source") is None
    assert payload == before
    assert seen == [b"source"]
    with pytest.raises(ValueError, match="Wrong issuer"):
        LocalConfiguration.validate_input(dict(payload, sub="https://other.example.org"))
    assert ExplicitRegistrationResponse.validate_input({}) is None
    assert ExplicitRegistrationResponse.validate_input({"iat": 0, "exp": 1.5}) is None
    assert EntityConfiguration().to_dict() == {}
