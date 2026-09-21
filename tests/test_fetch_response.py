"""Fetch publication isolation through initialized endpoints and storage."""

from copy import deepcopy
import json
from pathlib import Path
import sys

from cryptojwt.jwk.ec import new_ec_key
import pytest

from edu_federation.entity import init_app
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.utils import make_federation_combo


SUBJECT_A = "https://a.example.org"
SUBJECT_B = "https://b.example.org"


@pytest.fixture(params=["mapping", "configured"])
def publisher(request, tmp_path, monkeypatch):
    if request.param == "mapping":
        return make_federation_combo("https://ta.example.org", endpoints=["fetch"])

    source = Path(__file__).resolve().parents[1] / "edu_federation/trust_anchor/conf.json"
    config = json.loads(source.read_text())
    directory = tmp_path / "trust_anchor"
    directory.mkdir()
    (directory / "conf.json").write_text(json.dumps(config))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "path", list(sys.path))
    app = init_app("trust_anchor", root_path=str(directory))
    entity = app.federation_entity
    assert Path(entity.server.subordinate.fdir).resolve() == directory / "subordinates"
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
            "constraints": {"max_path_length": 1},
            "metadata_policy_crit": ["value"],
            "source_endpoint": publisher.entity_id + "/fetch",
        }
    server.policy[SUBJECT_A] = {
        "metadata": {"federation_entity": {"organization_name": "Specific A"}},
        "metadata_policy": {"federation_entity": {
            "organization_name": {"value": "Policy A"},
        }},
    }
    server.policy["federation_entity"] = {
        "metadata": {"organization_name": "Default B"},
        "metadata_policy": {"organization_name": {"value": "Policy B"}},
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
        issued_at = claims.pop("iat")
        expires_at = claims.pop("exp")
        assert expires_at > issued_at
        name, policy_name = expected_names[subject]
        assert claims == deep_freeze({
            "iss": publisher.entity_id, "sub": subject, "jwks": keys[subject],
            "authority_hints": [publisher.entity_id],
            "constraints": {"max_path_length": 1},
            "metadata_policy_crit": ["value"],
            "source_endpoint": publisher.entity_id + "/fetch",
            "metadata": {"federation_entity": {"organization_name": name}},
            "metadata_policy": {"federation_entity": {
                "organization_name": {"value": policy_name},
            }},
        })
        assert claims == observed.setdefault(subject, claims)
        assert dict(server.subordinate.items()) == subordinates_before
        assert dict(server.policy.items()) == policies_before
