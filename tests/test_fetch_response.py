"""Fetch publication isolation through initialized endpoints and storage."""

from copy import deepcopy
import json
from pathlib import Path
import sys

from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import factory
import pytest

from edu_federation.entity import init_app
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.utils import make_federation_combo


SUBJECT_A = "https://a.example.org"
SUBJECT_B = "https://b.example.org"
EC_ONLY_CLAIMS = ("authority_hints", "trust_anchor_hints", "trust_marks",
                  "trust_mark_issuers", "trust_mark_owners")


@pytest.fixture(params=["mapping", "configured"])
def publisher(request, tmp_path, monkeypatch):
    policies = {
        SUBJECT_A: {
            **{claim: None for claim in EC_ONLY_CLAIMS},
            "entity_types": ["federation_entity"],
            "metadata": {"federation_entity": {"organization_name": "Specific A"}},
            "metadata_policy": {"federation_entity": {
                "organization_name": {"value": "Policy A"},
            }},
        },
        "federation_entity": {
            "metadata": {"organization_name": "Default B"},
            "metadata_policy": {"organization_name": {"value": "Policy B"}},
        },
    }
    if request.param == "mapping":
        return make_federation_combo("https://ta.example.org", endpoints=["fetch"],
                                     metadata_policy=deepcopy(policies))

    source = Path(__file__).resolve().parents[1] / "edu_federation/trust_anchor/conf.json"
    config = json.loads(source.read_text())
    config["entity"]["metadata_policy"] = deepcopy(policies)
    directory = tmp_path / "trust_anchor"
    directory.mkdir()
    (directory / "conf.json").write_text(json.dumps(config))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "path", list(sys.path))
    app = init_app("trust_anchor", root_path=str(directory))
    entity = app.federation_entity
    assert Path(entity.server.subordinate.fdir).resolve() == directory / "subordinates"
    assert app.cnf["entity"]["metadata_policy"] == policies
    assert dict(entity.server.policy.items()) == policies
    assert json.loads((directory / "conf.json").read_text()) == config
    return entity


@pytest.mark.parametrize("sequence", [
    [SUBJECT_A, SUBJECT_B, SUBJECT_A],
    [SUBJECT_A, SUBJECT_A],
    [SUBJECT_B, SUBJECT_B, SUBJECT_A, SUBJECT_B],
])
def test_fetch_signed_publication_is_isolated(publisher, sequence):
    server = publisher.server
    keys = {
        subject: {"keys": [new_ec_key(crv="P-256").serialize(private=False)]}
        for subject in (SUBJECT_A, SUBJECT_B)
    }
    for subject in (SUBJECT_A, SUBJECT_B):
        server.subordinate[subject] = {
            "jwks": keys[subject],
            "entity_types": ["federation_entity"],
            "authority_hints": [publisher.entity_id],
            "trust_anchor_hints": [publisher.entity_id],
            "trust_marks": [],
            "trust_mark_issuers": {},
            "trust_mark_owners": {},
            "custom_extension": {"subject": subject},
            "metadata": {"federation_entity": {"organization_name": "Stored " + subject}},
            "constraints": {"max_path_length": 1 if subject == SUBJECT_A else 0},
            "source_endpoint": publisher.entity_id + "/fetch",
        }
    subordinates_before = deepcopy(dict(server.subordinate.items()))
    policies_before = deepcopy(dict(server.policy.items()))
    expected_names = {SUBJECT_A: ("Specific A", "Policy A"),
                      SUBJECT_B: ("Default B", "Policy B")}
    observed = {}
    endpoint = publisher.get_endpoint("fetch")
    for subject in sequence:
        result = endpoint.process_request({"sub": subject})
        envelope = endpoint.do_response(**result)
        assert ("Content-type", SUBORDINATE_STATEMENT.content_type) in envelope["http_headers"]
        verified = verify_federation_jwt(
            profile=SUBORDINATE_STATEMENT, token=envelope["response"],
            key_jar=publisher.keyjar,
        )
        claims = dict(verified.claims())
        assert not set(EC_ONLY_CLAIMS).intersection(claims)
        issued_at = claims.pop("iat")
        expires_at = claims.pop("exp")
        assert expires_at > issued_at
        name, policy_name = expected_names[subject]
        assert claims == deep_freeze({
            "iss": publisher.entity_id, "sub": subject, "jwks": keys[subject],
            "custom_extension": {"subject": subject},
            "constraints": {"max_path_length": 1 if subject == SUBJECT_A else 0},
            "source_endpoint": publisher.entity_id + "/fetch",
            "metadata": {"federation_entity": {"organization_name": name}},
            "metadata_policy": {"federation_entity": {
                "organization_name": {"value": policy_name},
            }},
        })
        assert claims == observed.setdefault(subject, claims)
        assert dict(server.subordinate.items()) == subordinates_before
        assert dict(server.policy.items()) == policies_before


@pytest.mark.parametrize("with_policy", [False, True])
def test_fetch_type_direct_metadata_omits_only_generated_policy(publisher, with_policy):
    server = publisher.server
    rule = {"metadata": {"organization_name": "Direct name"}}
    if with_policy:
        rule["metadata_policy"] = {"organization_name": {"value": "Policy name"}}
    server.policy["federation_entity"] = rule
    server.subordinate[SUBJECT_B] = {
        "jwks": {"keys": [new_ec_key(crv="P-256").serialize(private=False)]},
        "entity_types": ["federation_entity"],
    }
    subordinates_before = deepcopy(dict(server.subordinate.items()))
    policies_before = deepcopy(dict(server.policy.items()))
    endpoint = publisher.get_endpoint("fetch")
    for _ in range(2):
        envelope = endpoint.do_response(**endpoint.process_request({"sub": SUBJECT_B}))
        verified = verify_federation_jwt(SUBORDINATE_STATEMENT, envelope["response"], publisher.keyjar)
        claims = verified.claims()
        assert claims["metadata"] == {"federation_entity": rule["metadata"]}
        if with_policy:
            assert claims["metadata_policy"] == {"federation_entity": rule["metadata_policy"]}
        else:
            assert "metadata_policy" not in claims
        assert dict(server.subordinate.items()) == subordinates_before
        assert dict(server.policy.items()) == policies_before


@pytest.mark.parametrize("location", ["subject", "type"])
def test_fetch_does_not_prune_explicit_empty_policy(publisher, location):
    server = publisher.server
    key = SUBJECT_B if location == "subject" else "federation_entity"
    server.policy[key] = {"metadata_policy": {}}
    server.subordinate[SUBJECT_B] = {"jwks": {"keys": []}, "entity_types": ["federation_entity"]}
    policies_before = deepcopy(dict(server.policy.items()))
    subordinates_before = deepcopy(dict(server.subordinate.items()))
    endpoint = publisher.get_endpoint("fetch")
    result = endpoint.process_request({"sub": SUBJECT_B})
    token = endpoint.do_response(**result)["response"]
    expected = {} if location == "subject" else {"federation_entity": {}}
    assert factory(token).jwt.payload()["metadata_policy"] == expected
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(SUBORDINATE_STATEMENT, token, publisher.keyjar)
    assert type(error.value.__cause__) is ValueError
    assert "metadata_policy" in str(error.value.__cause__)
    assert dict(server.policy.items()) == policies_before
    assert dict(server.subordinate.items()) == subordinates_before
