import pytest
from copy import deepcopy
from cryptojwt.jwt import utc_time_sans_frac

from fedservice.entity_statement.constraints import meets_restrictions
from fedservice.exception import ConstraintError
from fedservice.exception import UnknownCriticalExtension
from fedservice.message import Constraints
from fedservice.message import EntityStatement
from fedservice.message import NamingConstraints
from fedservice.message import SubordinateStatement
from fedservice.federation_jwt.verified import deep_freeze


POLICY_A = "urn:example:registration-policy:approved"
POLICY_B = "urn:example:registration-policy:verified"


def registration_policy_chain(claims, declarations, leaf_types=("openid_provider",)):
    """Build an anchor-to-leaf constraint input without invoking metadata processing."""
    ids = ["https://entity{}.example.org".format(i) for i in range(len(claims) + 1)]
    chain = []
    for index, policies in enumerate(claims):
        statement = {"iss": ids[index], "sub": ids[index + 1]}
        if policies is not None:
            statement["registration_policy"] = policies
        if index in declarations:
            statement["constraints"] = {"registration_policy": declarations[index]}
        chain.append(statement)
    chain.append({"iss": ids[-1], "sub": ids[-1],
                  "metadata": {entity_type: {} for entity_type in leaf_types}})
    return chain


@pytest.mark.parametrize("rules,policies,accepted", [
    ([{"policy": [POLICY_A, POLICY_B]}], [POLICY_B], True),
    ([{"policy": [POLICY_A]}], None, False),
    ([{"policy": [POLICY_A]}], [], False),
    ([{"policy": [POLICY_A]}], [POLICY_B], False),
    ([{"policy": [POLICY_A]}, {"policy": [POLICY_B]}], [POLICY_A], False),
    ([{"policy": [POLICY_A]}, {"policy": [POLICY_B]}], [POLICY_A, POLICY_B], True),
    ([{"policy": [POLICY_A], "entity_types": ["custom"]}], None, True),
    ([{"policy": [POLICY_A], "entity_types": ["openid_provider", "custom"]}], None, False),
    ([], None, True),
    ([{"policy": ["https://example.org/p"]}], ["https://EXAMPLE.org/p"], False),
    ([{"policy": ["https://example.org/%70"]}], ["https://example.org/p"], False),
])
@pytest.mark.parametrize("immutable", [False, True])
def test_registration_policy_rule_semantics(rules, policies, accepted, immutable):
    chain = registration_policy_chain([None, policies], {0: rules})
    before = deepcopy(chain)
    assert meets_restrictions(deep_freeze(chain) if immutable else chain) is accepted
    assert chain == before


@pytest.mark.parametrize("claims,declarations,accepted", [
    ([None, [POLICY_A], [POLICY_A]], {0: [{"policy": [POLICY_A]}]}, True),
    ([None, None, [POLICY_A]], {0: [{"policy": [POLICY_A]}]}, False),
    ([None, [POLICY_A], None], {0: [{"policy": [POLICY_A]}]}, False),
    ([None], {0: [{"policy": [POLICY_A]}]}, True),
    ([None, [POLICY_A], [POLICY_A]],
     {0: [{"policy": [POLICY_A]}], 2: [{"policy": [POLICY_B]}]}, True),
    ([None, [POLICY_A], [POLICY_A]],
     {0: [{"policy": [POLICY_A]}], 1: [{"policy": [POLICY_B]}]}, False),
    ([None, [POLICY_A], [POLICY_B]],
     {0: [{"policy": [POLICY_A]}], 1: [{"policy": [POLICY_B]}]}, False),
    ([None, [POLICY_A], [POLICY_A, POLICY_B]],
     {0: [{"policy": [POLICY_A]}], 1: [{"policy": [POLICY_B]}]}, True),
])
def test_registration_policy_strict_descendants_and_independent_declarations(claims, declarations, accepted):
    chain = registration_policy_chain(claims, declarations)
    before = deepcopy(chain)
    assert meets_restrictions(chain) is accepted
    assert chain == before


@pytest.mark.parametrize("intermediate_policy,leaf_policy,accepted", [
    ([POLICY_A], [POLICY_B], True),
    (None, [POLICY_A, POLICY_B], False),
    ([POLICY_A], [POLICY_A], False),
])
def test_registration_policy_intermediate_and_multitype_leaf(intermediate_policy, leaf_policy, accepted):
    chain = registration_policy_chain([None, intermediate_policy, leaf_policy], {0: [
        {"policy": [POLICY_A], "entity_types": ["federation_entity"]},
        {"policy": [POLICY_B], "entity_types": ["openid_relying_party"]},
        {"policy": [POLICY_A, POLICY_B], "entity_types": ["openid_provider"]},
    ]}, leaf_types=("openid_provider", "openid_relying_party"))
    # SS metadata must not substitute for the verified final EC's declared types.
    chain[-2]["metadata"] = {"federation_entity": {}}
    assert meets_restrictions(chain) is accepted


@pytest.mark.parametrize("constraints", [{}, {"unknown_constraint": [{"policy": [POLICY_A]}]}])
def test_registration_policy_absent_and_unknown_constraints(constraints):
    chain = registration_policy_chain([None, None], {})
    chain[0]["constraints"] = constraints
    assert meets_restrictions(chain)


@pytest.mark.parametrize(
    "limits, accepted",
    [
        ([0], True),
        ([0, None], False),
        ([1, None], True),
        ([2, 1, None], True),
        ([None, None, 0], True),
        ([1, None, None], False),
        ([3, 0, None], False),
        ([2, 5, 0], True),
        ([None, None, None], True),
    ]
)
@pytest.mark.parametrize("omitted", [None, {}, {"unknown": True}, {
    "naming_constraints": {"permitted": [".example.org"], "excluded": []},
}])
def test_max_path_length(limits, accepted, omitted):
    chain = []
    for index, limit in enumerate(limits):
        statement = {"sub": "https://entity{}.example.org".format(index)}
        constraints = {"max_path_length": limit} if limit is not None else omitted
        if constraints is not None:
            statement["constraints"] = constraints
        chain.append(statement)
    chain.append({"sub": chain[-1]["sub"]})
    assert meets_restrictions(chain) is accepted


def test_negative_max_path_length_schema():
    with pytest.raises(ConstraintError, match="max_path_length"):
        Constraints(max_path_length=-1).verify()
    now = utc_time_sans_frac()
    statement = SubordinateStatement(
        iss="https://ta.example.org", sub="https://leaf.example.org",
        iat=now, exp=now + 3600, constraints={"max_path_length": -1},
        jwks={"keys": []},
    )
    with pytest.raises(ConstraintError, match="max_path_length"):
        statement.verify()


@pytest.mark.parametrize("subject, name, accepted", [
    ("https://host.example.com", "host.example.com", True),
    ("https://other.example.com", "host.example.com", False),
    ("https://my.host.example.com", "host.example.com", False),
    ("https://host.example.com", ".example.com", True),
    ("https://my.host.example.com", ".example.com", True),
    ("https://example.com", ".example.com", False),
    ("https://badexample.com", ".example.com", False),
    ("https://HOST.EXAMPLE.COM:8443/path.example.net?a=b", "host.example.com", True),
    ("https://other.example.net/host.example.com", ".example.com", False),
])
@pytest.mark.parametrize("kind", ["permitted", "excluded"])
def test_naming_host_matching(subject, name, accepted, kind):
    chain = [
        {"sub": subject, "constraints": {"naming_constraints": {kind: [name]}}},
        {"sub": subject},
    ]
    assert meets_restrictions(chain) is (accepted if kind == "permitted" else not accepted)


@pytest.mark.parametrize("naming", [
    {"permitted": ["https://.example.com"]},
    {"excluded": ["https://host.example.com"]},
    {"permitted": ["example.com/path"]},
    {"permitted": ["*.example.com"]},
    {"permitted": ["host..example.com"]},
    {"permitted": ["-host.example.com"]},
    {"permitted": [""]},
    {"permitted": [None]},
    {"permitted": ".example.com"},
    {"excluded": None},
    [],
])
def test_malformed_naming_fails_candidate(naming):
    chain = [
        {"sub": "https://host.example.com", "constraints": {"naming_constraints": naming}},
        {"sub": "https://host.example.com"},
    ]
    assert not meets_restrictions(chain)


@pytest.mark.parametrize("kind,value", [
    ("permitted", "example.com"),
    ("excluded", None),
    ("permitted", [None]),
    ("excluded", ["https://host.example.com"]),
    ("permitted", ["*.example.com"]),
])
def test_naming_schema_rejects_malformed_original_values(kind, value):
    naming = NamingConstraints(**{kind: value})
    assert naming[kind] == value
    with pytest.raises(ConstraintError, match=kind):
        naming.verify()


@pytest.mark.parametrize("upper, lower, accepted", [
    ({"permitted": [".example.com"]}, {"permitted": ["leaf.example.com"]}, True),
    ({"permitted": [".example.com"]}, {"permitted": [".example.net"]}, False),
    ({"excluded": ["leaf.example.com"]}, {"permitted": [".example.com"]}, False),
    ({"excluded": [".example.com"]}, {"excluded": ["other.example.com"]}, False),
    ({"permitted": [".example.com"]}, {"excluded": ["leaf.example.com"]}, False),
    ({"permitted": ["leaf.example.com"]}, {}, False),
])
def test_inherited_naming_constraints(upper, lower, accepted):
    chain = [
        {"sub": "https://ie.example.com", "constraints": {"naming_constraints": upper}},
        {"sub": "https://leaf.example.com", "constraints": {"naming_constraints": lower}},
        {"sub": "https://leaf.example.com"},
    ]
    assert meets_restrictions(chain) is accepted


def test_naming_exclusion_wins():
    naming = {"permitted": [".example.com"], "excluded": ["host.example.com"]}
    chain = [
        {"sub": "https://host.example.com", "constraints": {"naming_constraints": naming}},
        {"sub": "https://host.example.com"},
    ]
    assert not meets_restrictions(chain)


def test_crit_known_unknown():
    entity_id = "https://ent.example.org"
    _now = utc_time_sans_frac()
    _statement = EntityStatement(sub=entity_id, iss=entity_id, iat=_now, exp=_now + 3600,
                                 jwks={"keys": []},
                                 foo="bar", crit=["foo"])

    _statement.verify(known_extensions=["foo"])
    _statement.verify(known_extensions=["foo", "xyz"])

    with pytest.raises(UnknownCriticalExtension):
        _statement.verify()


def test_crit_known_unknown_not_critical():
    entity_id = "https://ent.example.org"
    _now = utc_time_sans_frac()
    _statement = EntityStatement(sub=entity_id, iss=entity_id, iat=_now, exp=_now + 3600,
                                 jwks={"keys": []},
                                 foo="bar")

    _statement.verify(known_extensions=["foo"])
    _statement.verify(known_extensions=["foo", "xyz"])
    _statement.verify()


def test_crit_critical_not_supported():
    entity_id = "https://ent.example.org"
    _now = utc_time_sans_frac()
    _statement = SubordinateStatement(sub=entity_id, iss=entity_id, iat=_now, exp=_now + 3600,
                                      jwks={"keys": []},
                                      foo="bar", crit=["foo"])

    with pytest.raises(UnknownCriticalExtension):
        _statement.verify(known_extensions=["xyz"])
    with pytest.raises(UnknownCriticalExtension):
        _statement.verify()


MSG = {
    "iss": "https://edugain.geant.org",
    "jwks": {
        "keys": [
            {
                "e": "AQAB",
                "kid": "N1pQTzFxUXZ1RXVsUkVuMG5uMnVDSURGRVdhUzdO...",
                "kty": "RSA",
                "n": "3EQc6cR_GSBq9km9-WCHY_lWJZWkcn0M05TGtH6D9S..."
            }
        ]
    },
    "metadata_policy_crit": ["regexp"],
    "metadata_policy": {
        "openid_provider": {
            "contacts": {
                "add": "ops@edugain.geant.org",
                "regexp": "@its.umu.se$"
            }
        }
    },
    "sub": "https://swamid.se"
}


def test_metadata_policy_crit_not_supported():
    _now = utc_time_sans_frac()
    _statement = SubordinateStatement(iat=_now, exp=_now + 3600, **MSG)
    with pytest.raises(UnknownCriticalExtension):
        _statement.verify(known_policy_extensions=["regexp"])

    with pytest.raises(UnknownCriticalExtension):
        _statement.verify()
