"""Endpoint-level regression tests for Federation JWT producers."""

import json
from types import SimpleNamespace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwt import utc_time_sans_frac

from fedservice.entity.server import entity_configuration as entity_configuration_endpoint
from fedservice.entity.server import resolve as resolve_endpoint
from fedservice.entity.server.entity_configuration import EntityConfiguration
from fedservice.entity.server.fetch import Fetch
from fedservice.entity.server.resolve import Resolve
from fedservice.federation_jwt.jose import decode_protected_header
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.key_resolver import KeyJarResolver
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.registry import TRUST_MARK_STATUS_RESPONSE
from fedservice.trust_mark_entity.server.trust_mark_status import TrustMarkStatus


ISSUER = "https://issuer.example.org"
SUBJECT = "https://subject.example.org"
TRUST_ANCHOR = "https://trust-anchor.example.org"
TRUST_MARK = "original.compact.trust-mark"


def keyjar_with_signing_key():
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [new_rsa_key(kid="key-1")])
    return key_jar


def metadata():
    return {"federation_entity": {"contacts": ["ops@example.org"]}}


def content_type(response):
    return dict(response["http_headers"])["Content-type"]


def assert_profile_response(response, profile):
    body = response["response"]

    assert isinstance(body, str)
    assert body.count(".") == 2
    assert decode_protected_header(body)["typ"] == profile.typ
    assert content_type(response) == profile.content_type
    return body


def test_entity_configuration_endpoint_produces_profile_backed_jwt(monkeypatch):
    key_jar = keyjar_with_signing_key()
    context = SimpleNamespace(
        trust_marks=None,
        trust_mark_issuers=None,
        trust_mark_owners=None,
    )
    federation_entity = SimpleNamespace(
        context=context,
        upstream_get=None,
        get_attribute=lambda name: ISSUER if name == "entity_id" else key_jar,
        get_metadata=metadata,
    )
    unit = SimpleNamespace(upstream_get=lambda name: None)
    endpoint = object.__new__(EntityConfiguration)
    endpoint.upstream_get = lambda item: unit
    monkeypatch.setattr(
        entity_configuration_endpoint,
        "get_federation_entity",
        lambda value: federation_entity,
    )

    result = endpoint.process_request({})
    response = endpoint.do_response(**result)

    assert_profile_response(response, ENTITY_CONFIGURATION)


def test_fetch_endpoint_produces_subordinate_statement_jwt():
    key_jar = keyjar_with_signing_key()
    unit = SimpleNamespace(
        subordinate={SUBJECT: {"metadata": metadata()}},
        policy={},
    )

    def upstream_get(item, name=None):
        if item == "unit":
            return unit
        if item == "context":
            return SimpleNamespace()
        if (item, name) == ("attribute", "entity_id"):
            return ISSUER
        if (item, name) == ("attribute", "keyjar"):
            return key_jar
        raise AssertionError("Unexpected upstream lookup")

    endpoint = object.__new__(Fetch)
    endpoint.upstream_get = upstream_get

    result = endpoint.process_request({"sub": SUBJECT})
    response = endpoint.do_response(**result)

    assert_profile_response(response, SUBORDINATE_STATEMENT)


def test_resolve_endpoint_produces_bounded_profile_backed_jwt(monkeypatch):
    key_jar = keyjar_with_signing_key()
    now = utc_time_sans_frac()
    chain_exp = now + 3600
    trust_mark_exp = now + 1800
    chosen_chain = SimpleNamespace(
        anchor=TRUST_ANCHOR,
        exp=chain_exp,
        iss_path=[SUBJECT, TRUST_ANCHOR],
        metadata=metadata(),
        verified_chain=[
            {
                "trust_marks": [
                    {
                        "trust_mark_type": "https://example.org/trust-mark",
                        "trust_mark": TRUST_MARK,
                    }
                ]
            }
        ],
    )
    collector = SimpleNamespace(
        get_chain=lambda *args: ["leaf.jwt", "anchor.jwt"]
    )
    functions = SimpleNamespace(
        trust_mark_verifier=lambda **kwargs: {
            "trust_mark_type": "https://example.org/trust-mark",
            "exp": trust_mark_exp,
        },
        trust_chain_collector=collector,
    )
    federation_entity = SimpleNamespace(
        entity_id=ISSUER,
        function=functions,
        get_attribute=lambda name: key_jar,
    )
    endpoint = object.__new__(Resolve)

    monkeypatch.setattr(
        resolve_endpoint,
        "get_federation_entity",
        lambda value: federation_entity,
    )
    monkeypatch.setattr(
        resolve_endpoint,
        "collect_trust_chains",
        lambda *args, **kwargs: ([], None),
    )
    monkeypatch.setattr(
        resolve_endpoint,
        "verify_trust_chains",
        lambda *args, **kwargs: [chosen_chain],
    )
    monkeypatch.setattr(
        resolve_endpoint,
        "apply_policies",
        lambda entity, chains: chains,
    )

    result = endpoint.process_request(
        {"sub": SUBJECT, "trust_anchor": TRUST_ANCHOR}
    )
    response = endpoint.do_response(**result)
    body = assert_profile_response(response, RESOLVE_RESPONSE)
    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=body,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["exp"] == trust_mark_exp
    assert verified.claims()["trust_marks"][0]["trust_mark"] == TRUST_MARK


class TrustMarkIssuer:
    def __init__(self, active=True):
        self.active = active
        self.entity_id = ISSUER
        self.keyjar = keyjar_with_signing_key()

    def unpack_trust_mark(self, value):
        return {
            "trust_mark_type": "https://example.org/trust-mark",
            "sub": SUBJECT,
        }

    def find(self, trust_mark_type, subject):
        return self.active

    def upstream_get(self, item, name):
        assert (item, name) == ("attribute", "keyjar")
        return self.keyjar


def trust_mark_status_endpoint(active=True):
    issuer = TrustMarkIssuer(active=active)
    endpoint = object.__new__(TrustMarkStatus)
    endpoint.upstream_get = lambda item: issuer
    return endpoint


def test_trust_mark_status_endpoint_produces_profile_backed_jwt():
    endpoint = trust_mark_status_endpoint()

    result = endpoint.process_request({"trust_mark": TRUST_MARK})
    response = endpoint.do_response(**result)

    assert_profile_response(response, TRUST_MARK_STATUS_RESPONSE)


def assert_json_error(endpoint, result, expected_error):
    response = endpoint.do_response(response_args=result)

    assert content_type(response) == "application/json"
    assert json.loads(response["response"])["error"] == expected_error


def test_trust_mark_status_subject_and_type_error_is_json():
    endpoint = trust_mark_status_endpoint()

    result = endpoint.process_request(
        {
            "sub": SUBJECT,
            "trust_mark_type": "https://example.org/trust-mark",
        }
    )

    assert_json_error(endpoint, result, "invalid_request")


def test_trust_mark_status_inactive_compact_mark_error_is_json():
    endpoint = trust_mark_status_endpoint(active=False)

    result = endpoint.process_request({"trust_mark": TRUST_MARK})

    assert_json_error(endpoint, result, "not_found")
