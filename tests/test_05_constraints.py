import pytest
from cryptojwt.jwt import utc_time_sans_frac

from fedservice.entity_statement.constraints import meets_restrictions
from fedservice.exception import UnknownCriticalExtension
from fedservice.message import Constraints
from fedservice.message import EntityStatement
from fedservice.message import SubordinateStatement


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
    with pytest.raises(ValueError, match="max_path_length"):
        Constraints(max_path_length=-1).verify()
    now = utc_time_sans_frac()
    statement = SubordinateStatement(
        iss="https://ta.example.org", sub="https://leaf.example.org",
        iat=now, exp=now + 3600, constraints={"max_path_length": -1},
    )
    with pytest.raises(ValueError, match="max_path_length"):
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
                                 foo="bar", crit=["foo"])

    _statement.verify(known_extensions=["foo"])
    _statement.verify(known_extensions=["foo", "xyz"])

    with pytest.raises(UnknownCriticalExtension):
        _statement.verify()


def test_crit_known_unknown_not_critical():
    entity_id = "https://ent.example.org"
    _now = utc_time_sans_frac()
    _statement = EntityStatement(sub=entity_id, iss=entity_id, iat=_now, exp=_now + 3600,
                                 foo="bar")

    _statement.verify(known_extensions=["foo"])
    _statement.verify(known_extensions=["foo", "xyz"])
    _statement.verify()


def test_crit_critical_not_supported():
    entity_id = "https://ent.example.org"
    _now = utc_time_sans_frac()
    _statement = SubordinateStatement(sub=entity_id, iss=entity_id, iat=_now, exp=_now + 3600,
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
