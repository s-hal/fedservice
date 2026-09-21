import pytest
from cryptojwt.jwt import utc_time_sans_frac

from fedservice.entity_statement.constraints import meets_restrictions
from fedservice.entity_statement.constraints import excluded
from fedservice.entity_statement.constraints import permitted
from fedservice.entity_statement.constraints import update_naming_constraints
from fedservice.exception import UnknownCriticalExtension
from fedservice.message import Constraints
from fedservice.message import EntityStatement
from fedservice.message import NamingConstraints
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
    "naming_constraints": {"permitted": ["https://.example.org"], "excluded": []},
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


def test_naming_constr_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(permitted=["https://.example.com"],
                                            excluded=["https://east.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.com"]
    assert naming_constraints["excluded"] == ["https://east.example.com"]


def test_naming_constr_perm_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(permitted=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.com"]
    assert naming_constraints["excluded"] == []

    # host more specific then domain
    _naming_constraints = NamingConstraints(permitted=["https://foo.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://foo.example.com"]
    assert naming_constraints["excluded"] == []


def test_naming_constr_perm_2():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(permitted=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.com"]
    assert naming_constraints["excluded"] == []

    # adding other domain - not permitted
    _naming_constraints = NamingConstraints(permitted=["https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.com"]
    assert naming_constraints["excluded"] == []


def test_naming_permitted_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }

    # permitted domain
    _naming_constraints = NamingConstraints(permitted=["https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.org"]
    assert naming_constraints["excluded"] == []

    assert permitted('https://foo.example.org', naming_constraints['permitted']) == True


def test_naming_constr_excl_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(excluded=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com"]
    assert naming_constraints["permitted"] == []

    # host more specific than domain
    _naming_constraints = NamingConstraints(excluded=["https://foo.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://foo.example.com"]
    assert naming_constraints["permitted"] == []


def test_naming_constr_excl_list():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(
        excluded=["https://.example.com", "https://bar.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com", "https://bar.example.org"]
    assert naming_constraints["permitted"] == []

    # host more specific then domain
    _naming_constraints = NamingConstraints(excluded=["https://foo.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://foo.example.com", "https://bar.example.org"]
    assert naming_constraints["permitted"] == []


def test_naming_constr_excl_list_2():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(excluded=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com"]
    assert naming_constraints["permitted"] == []

    # host more specific then domain
    _naming_constraints = NamingConstraints(excluded=["https://foo.example.com",
                                                      "https://bar.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://foo.example.com", "https://bar.example.com"]
    assert naming_constraints["permitted"] == []


def test_naming_constr_excl_list_3():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(excluded=["https://.example.com",
                                                      "https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com", "https://.example.org"]
    assert naming_constraints["permitted"] == []

    # host more specific then domain
    _naming_constraints = NamingConstraints(excluded=["https://foo.example.com",
                                                      "https://bar.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://foo.example.com", "https://bar.example.org"]
    assert naming_constraints["permitted"] == []


def test_naming_constr_excl_2():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(excluded=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com"]
    assert naming_constraints["permitted"] == []

    # adding other domain - not permitted
    _naming_constraints = NamingConstraints(excluded=["https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com"]
    assert naming_constraints["permitted"] == []


def test_naming_excluded_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }

    # permitted domain
    _naming_constraints = NamingConstraints(excluded=["https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.org"]
    assert naming_constraints["permitted"] == []

    assert excluded('https://foo.example.org', naming_constraints['excluded']) == True


def test_meets_restriction():
    pass


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
    "policy_language_crit": ["regexp"],
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


def test_policy_language_crit_not_supported():
    _now = utc_time_sans_frac()
    _statement = SubordinateStatement(iat=_now, exp=_now + 3600, **MSG)
    _statement.verify(known_policy_extensions=["regexp"])

    with pytest.raises(UnknownCriticalExtension):
        _statement.verify()
