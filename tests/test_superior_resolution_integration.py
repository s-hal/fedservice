"""Configured Superior publication through collection and signed Resolve output."""

from copy import deepcopy

import pytest
import responses

from fedservice.entity.server import resolve as resolve_module
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.utils import make_federation_combo
from tests.entities.openid_relying_party import main as make_relying_party


ANCHOR = "https://anchor.example.org"
GOOD = "https://good.example.org"
BAD = "https://bad.example.org"
RESOLVER = "https://resolver.example.org"
SUBJECTS = ["https://subject-a.example.org", "https://subject-b.example.org"]
NAMES = {SUBJECTS[0]: "Immediate A", SUBJECTS[1]: "Immediate B"}
DIRECT_CONTACT = "direct@example.org"
POLICY_CONTACT = "policy@example.org"


@pytest.fixture(params=[False, True], ids=["invalid-first", "valid-first"])
def superior_network(request):
    order = [GOOD, BAD] if request.param else [BAD, GOOD]
    inputs = {}
    entities = {}
    for subject in SUBJECTS:
        inputs[subject] = {
            "entity_id": subject, "authority_hints": order[:],
            "endpoints": ["entity_configuration"],
            "preference": {"organization_name": "Leaf name", "homepage_uri": subject + "/",
                           "contacts": ["leaf@example.org"]},
        }
        entities[subject] = make_relying_party(**deepcopy(inputs[subject]))
    for issuer in (BAD, GOOD):
        records, policies = {}, {}
        for subject in SUBJECTS:
            leaf = entities[subject]["federation_entity"]
            records[subject] = {
                "jwks": leaf.keyjar.export_jwks(), "authority_hints": order[:],
                "entity_types": ["federation_entity", "openid_relying_party"],
                "constraints": {"max_path_length": 0, "allowed_entity_types": ["openid_relying_party"]},
            }
            policies[subject] = {
                "metadata": {
                    "federation_entity": {
                        "organization_name": NAMES[subject] if issuer == GOOD else "Rejected name",
                        "contacts": [DIRECT_CONTACT, "drop@example.org"],
                    },
                    "openid_relying_party": {"client_name": "Direct client"},
                },
                "metadata_policy": {
                    "federation_entity": {
                        "organization_name": {"one_of": [NAMES[subject]]},
                        "contacts": {"subset_of": [DIRECT_CONTACT, POLICY_CONTACT]},
                    },
                    # This valid rule would reject the candidate if applied before filtering.
                    "openid_relying_party": {"client_name": {"one_of": ["Not the direct client"]}},
                },
            }
        inputs[issuer] = {
            "entity_id": issuer, "authority_hints": [ANCHOR],
            "endpoints": ["entity_configuration", "fetch"],
            "subordinate": records, "metadata_policy": policies,
        }
        entities[issuer] = make_federation_combo(**deepcopy(inputs[issuer]))
    inputs[ANCHOR] = {
        "entity_id": ANCHOR, "endpoints": ["entity_configuration", "fetch"],
        "subordinate": {
            issuer: {"jwks": entities[issuer].keyjar.export_jwks(), "authority_hints": [ANCHOR],
                     "entity_types": ["federation_entity"],
                     "constraints": {"max_path_length": 1, "allowed_entity_types": []}}
            for issuer in (BAD, GOOD)
        },
        "metadata_policy": {
            issuer: {
                "metadata": {"federation_entity": {
                    "organization_name": "Ancestor describes intermediary",
                    "homepage_uri": "https://ancestor.example.org/", "contacts": ["ancestor@example.org"],
                }},
                "metadata_policy": {"federation_entity": {
                    "organization_name": {"one_of": ["Immediate A", "Immediate B"]},
                    "contacts": {"add": [POLICY_CONTACT],
                                 "subset_of": [DIRECT_CONTACT, POLICY_CONTACT, "upper-only@example.org"]},
                }},
            } for issuer in (BAD, GOOD)
        },
    }
    entities[ANCHOR] = make_federation_combo(**deepcopy(inputs[ANCHOR]))
    inputs[RESOLVER] = {
        "entity_id": RESOLVER, "endpoints": ["entity_configuration", "resolve"],
        "trust_anchors": {ANCHOR: entities[ANCHOR].keyjar.export_jwks()},
    }
    entities[RESOLVER] = make_federation_combo(**deepcopy(inputs[RESOLVER]))
    return entities, inputs, order


def _publish_network(rsps, entities, inputs):
    """Publish real endpoint output and verify each configured Fetch payload."""
    fetch_tokens = {}
    leaf_tokens = {}
    for entity_id, entity in entities.items():
        if entity_id == RESOLVER:
            continue
        federation = entity["federation_entity"] if entity_id in SUBJECTS else entity
        endpoint = federation.get_endpoint("entity_configuration")
        token = endpoint.process_request({})["response"]
        verified = verify_federation_jwt(profile=ENTITY_CONFIGURATION, token=token,
                                         key_jar=federation.keyjar)
        if entity_id in SUBJECTS:
            assert set(verified.claims()["metadata"]) == {"federation_entity", "openid_relying_party"}
            leaf_tokens[entity_id] = token
        rsps.add("GET", endpoint.full_path, body=token, status=200,
                 content_type=ENTITY_CONFIGURATION.content_type)
        if entity_id in SUBJECTS:
            continue
        endpoint = federation.get_endpoint("fetch")
        for subject, record in inputs[entity_id]["subordinate"].items():
            policy = inputs[entity_id]["metadata_policy"][subject]
            envelope = endpoint.do_response(**endpoint.process_request(endpoint.parse_request({"sub": subject})))
            assert ("Content-type", SUBORDINATE_STATEMENT.content_type) in envelope["http_headers"]
            token = envelope["response"]
            verified = verify_federation_jwt(profile=SUBORDINATE_STATEMENT, token=token,
                                             key_jar=federation.keyjar)
            claims = dict(verified.claims())
            assert claims.pop("exp") > claims.pop("iat")
            assert claims == deep_freeze({
                "iss": entity_id, "sub": subject, "jwks": record["jwks"],
                "authority_hints": record["authority_hints"], "constraints": record["constraints"],
                "metadata": policy["metadata"], "metadata_policy": policy["metadata_policy"],
            })
            assert "entity_types" not in claims
            fetch_tokens[entity_id, subject] = token
            rsps.add("GET", endpoint.full_path, body=token, status=200,
                     content_type=SUBORDINATE_STATEMENT.content_type,
                     match=[responses.matchers.query_param_matcher({"sub": subject})])
    return leaf_tokens, fetch_tokens


@pytest.mark.parametrize("sequence", [[0, 1, 0, 1], [1, 0, 1, 0]])
def test_configured_superior_controls_resolve(superior_network, monkeypatch, sequence):
    entities, inputs, order = superior_network
    inputs_before = deepcopy(inputs)
    stores = {issuer: (entities[issuer].server.subordinate, entities[issuer].server.policy)
              for issuer in (ANCHOR, BAD, GOOD)}
    stores_before = deepcopy({issuer: (dict(sub.items()), dict(policy.items()))
                              for issuer, (sub, policy) in stores.items()})
    metadata_before = deepcopy({subject: entities[subject].get_metadata() for subject in SUBJECTS})
    observed = []
    original = resolve_module.verify_trust_chains

    def observe_verified(*args, **kwargs):
        candidates = original(*args, **kwargs)
        before = deepcopy([candidate.verified_chain for candidate in candidates])
        for candidate in candidates:
            # Exercise clearing of stale policy-owned errors on real verified candidates.
            candidate.err["metadata_policy"] = {"error": "stale"}
        observed.append((candidates, before))
        return candidates

    monkeypatch.setattr(resolve_module, "verify_trust_chains", observe_verified)
    resolver = entities[RESOLVER]
    endpoint = resolver.get_endpoint("resolve")
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        leaf_tokens, fetch_tokens = _publish_network(rsps, entities, inputs)
        for index in sequence:
            subject = SUBJECTS[index]
            query = endpoint.parse_request({"sub": subject, "trust_anchor": [ANCHOR]})
            result = endpoint.process_request(query)
            envelope = endpoint.do_response(**result)
            assert ("Content-type", RESOLVE_RESPONSE.content_type) in envelope["http_headers"]
            verified = verify_federation_jwt(profile=RESOLVE_RESPONSE, token=envelope["response"],
                                             key_jar=resolver.keyjar)
            expected_metadata = {"federation_entity": {
                "organization_name": NAMES[subject], "homepage_uri": subject + "/",
                "contacts": [DIRECT_CONTACT, POLICY_CONTACT],
            }}
            assert verified.claims()["metadata"] == deep_freeze(expected_metadata)
            assert verified.claims()["iss"] == RESOLVER
            assert verified.claims()["sub"] == subject
            assert verified.claims()["trust_chain"] == (
                leaf_tokens[subject], fetch_tokens[GOOD, subject], fetch_tokens[ANCHOR, GOOD],
            )
            candidates, before = observed[-1]
            assert len(candidates) == 2
            assert [candidate.verified_chain[-2]["iss"] for candidate in candidates] == order
            assert [candidate.verified_chain for candidate in candidates] == before
            rejected = next(candidate for candidate in candidates if candidate.err)
            accepted = next(candidate for candidate in candidates if not candidate.err)
            assert rejected.verified_chain[-2]["iss"] == BAD
            assert rejected.err == {"metadata_policy": {
                "error": "invalid_metadata", "stage": "metadata_policy", "subject": subject,
                "trust_anchor": ANCHOR,
            }}
            assert rejected.metadata == rejected.combined_policy == {}
            assert accepted.anchor == ANCHOR
            assert accepted.metadata == expected_metadata
            expected_policy = {
                "organization_name": {"one_of": [NAMES[subject]]},
                "contacts": {"add": [POLICY_CONTACT], "subset_of": sorted([DIRECT_CONTACT, POLICY_CONTACT])},
            }
            combined = deepcopy(accepted.combined_policy)
            combined["federation_entity"]["metadata_policy"]["contacts"]["subset_of"].sort()
            assert combined == {"federation_entity": {
                "metadata": {"organization_name": NAMES[subject],
                             "contacts": [DIRECT_CONTACT, "drop@example.org"]},
                "metadata_policy": expected_policy,
            }}
            assert inputs == inputs_before
            assert {issuer: (dict(sub.items()), dict(policy.items()))
                    for issuer, (sub, policy) in stores.items()} == stores_before
            assert {subject: entities[subject].get_metadata() for subject in SUBJECTS} == metadata_before
