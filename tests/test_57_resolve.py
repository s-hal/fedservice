from copy import deepcopy
from importlib import import_module
import json
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from flask import Flask
import pytest
import responses
from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.jwt import JWT
from requests import Response
from edu_federation.trust_anchor.views import do_response as example_do_response
from fedservice.entity.server import resolve as resolve_module
from fedservice.entity.server.response import do_response
from fedservice.entity.function import collect_trust_chains

from fedservice.entity.function import apply_policies
from fedservice.entity.function import verify_trust_chains
from fedservice.entity_statement.create import create_resolve_response
from fedservice.exception import ResolveResponseExpired
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.message import ResolveResponse
from fedservice.message import ResolveRequest
from fedservice.message import Policy
from fedservice.message import MetadataPolicy
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
IM_ID = "https://intermediate.example.org"
TMI_ID = "https://tmi.example.org"

SIRTIFI_TRUST_MARK_TYPE = "https://refeds.org/sirtfi"
RESOLVER_ID = "https://resolver.example.org"
SUBJECT_ID = "https://subject.example.org"

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [IM_ID, TMI_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
            "trust_mark_issuers": {
                SIRTIFI_TRUST_MARK_TYPE: [TMI_ID],
            },
        }
    },
    IM_ID: {
        "entity_type": "intermediate",
        "trust_anchors": [TA_ID],
        "subordinates": [RP_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
        }
    },
    RP_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [IM_ID],
            "preference": {
                "organization_name": "The example federation RP operator",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        }
    },
    TMI_ID: {
        "entity_type": "trust_mark_issuer",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
            "trust_mark_entity": {
                "class": "fedservice.trust_mark_entity.entity.TrustMarkEntity",
                "kwargs": {
                    "trust_mark_specification": {
                        SIRTIFI_TRUST_MARK_TYPE: {"lifetime": 2592000},
                    },
                    "endpoint": {
                        "trust_mark": {
                            "path": "trust_mark",
                            "class": "fedservice.trust_mark_entity.server.trust_mark.TrustMark",
                            "kwargs": {
                                "client_authn_method": [
                                    "private_key_jwt"
                                ],
                                "auth_signing_alg_values": [
                                    "ES256"
                                ]
                            }
                        },
                        "trust_mark_list": {
                            "path": "trust_mark_list",
                            "class":
                                "fedservice.trust_mark_entity.server.trust_mark_list.TrustMarkList",
                            "kwargs": {}
                        },
                        "trust_mark_status": {
                            "path": "trust_mark_status",
                            "class":
                                "fedservice.trust_mark_entity.server.trust_mark_status.TrustMarkStatus",
                            "kwargs": {}
                        }
                    }
                }
            }
        }
    }
}


def resolve_signing_keyjar():
    key = new_rsa_key(kid="key-1")
    key_jar = KeyJar()
    key_jar.add_keys(RESOLVER_ID, [key])
    return key_jar


def resolve_metadata():
    return {"federation_entity": {"contacts": ["ops@example.org"]}}


def compact_trust_chain():
    return ["leaf.jwt", "intermediate.jwt", "anchor.jwt"]


def future_expiration():
    return utc_time_sans_frac() + 3600


def test_create_resolve_response_emits_resolve_response_typ():
    token = create_resolve_response(
        RESOLVER_ID,
        sub=SUBJECT_ID,
        key_jar=resolve_signing_keyjar(),
        metadata=resolve_metadata(),
        trust_chain=compact_trust_chain(),
        expires_at=future_expiration(),
    )

    assert factory(token).jwt.headers["typ"] == "resolve-response+jwt"


def test_create_resolve_response_verifies_with_resolve_profile():
    key_jar = resolve_signing_keyjar()
    token = create_resolve_response(
        RESOLVER_ID,
        sub=SUBJECT_ID,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=compact_trust_chain(),
        expires_at=future_expiration(),
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
    )

    assert verified.profile is RESOLVE_RESPONSE
    assert isinstance(verified.message(), ResolveResponse)


def test_create_resolve_response_payload_uses_requested_subject():
    key_jar = resolve_signing_keyjar()
    token = create_resolve_response(
        RESOLVER_ID,
        sub=SUBJECT_ID,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=compact_trust_chain(),
        expires_at=future_expiration(),
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
    )

    assert verified.claims()["iss"] == RESOLVER_ID
    assert verified.claims()["sub"] == SUBJECT_ID


def test_create_resolve_response_preserves_trust_marks():
    key_jar = resolve_signing_keyjar()
    trust_marks = [
        {
            "trust_mark_type": "https://trust.example.org/mark",
            "trust_mark": "compact.trust.mark",
        }
    ]
    token = create_resolve_response(
        RESOLVER_ID,
        sub=SUBJECT_ID,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=compact_trust_chain(),
        expires_at=future_expiration(),
        trust_marks=trust_marks,
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
    )

    assert verified.claims()["trust_marks"] == tuple(
        {
            "trust_mark_type": item["trust_mark_type"],
            "trust_mark": item["trust_mark"],
        }
        for item in trust_marks
    )


def test_create_resolve_response_uses_absolute_expiration_exactly():
    key_jar = resolve_signing_keyjar()
    expires_at = future_expiration()
    token = create_resolve_response(
        RESOLVER_ID,
        sub=SUBJECT_ID,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=compact_trust_chain(),
        expires_at=expires_at,
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
    )

    assert verified.claims()["exp"] == expires_at


def test_create_resolve_response_passes_explicit_iat_with_zero_lifetime(
    monkeypatch,
):
    issued_at = utc_time_sans_frac()
    expires_at = issued_at + 3600
    monkeypatch.setattr(
        "fedservice.entity_statement.create.utc_time_sans_frac",
        lambda: issued_at,
    )
    key_jar = resolve_signing_keyjar()

    token = create_resolve_response(
        RESOLVER_ID,
        sub=SUBJECT_ID,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=compact_trust_chain(),
        expires_at=expires_at,
    )
    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
    )

    assert verified.claims()["iss"] == RESOLVER_ID
    assert verified.claims()["iat"] == issued_at
    assert verified.claims()["exp"] == expires_at


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #     Federation tree
        #
        #    TA/RESOLVER
        #        |
        #        IM
        #        |
        #        RP

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.im = federation[IM_ID]
        self.rp = federation[RP_ID]
        self.tmi = federation[TMI_ID]

    def _set_trust_mark(self, exp="default"):
        trust_mark_entity = self.tmi.server.trust_mark_entity
        if exp is None:
            trust_mark_entity.tm_lifetime.pop(SIRTIFI_TRUST_MARK_TYPE, None)
            trust_mark = trust_mark_entity.create_trust_mark(
                SIRTIFI_TRUST_MARK_TYPE,
                RP_ID,
            )
        elif exp == "default":
            trust_mark = trust_mark_entity.create_trust_mark(
                SIRTIFI_TRUST_MARK_TYPE,
                RP_ID,
            )
        else:
            trust_mark = trust_mark_entity.create_trust_mark(
                SIRTIFI_TRUST_MARK_TYPE,
                RP_ID,
                exp=exp,
            )

        self.rp["federation_entity"].context.trust_marks = [
            {
                "trust_mark_type": SIRTIFI_TRUST_MARK_TYPE,
                "trust_mark": trust_mark,
            }
        ]
        return trust_mark

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {IM_ID, TMI_ID}

    def _perform_resolve(self, entity_types=None):
        resolver = self.ta.server.endpoint["resolve"]

        # Split trust chain collection into two parts
        where_and_what = create_trust_chain_messages(self.rp, self.im, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": ENTITY_CONFIGURATION.content_type}, status=200)

            chains, entity_configuration = collect_trust_chains(
                resolver,
                self.rp.entity_id,
            )

        verified_chains = verify_trust_chains(
            resolver,
            chains,
            entity_configuration,
        )
        verified_chains = apply_policies(resolver, verified_chains)
        selected_chain = next(
            chain for chain in verified_chains if chain.anchor == self.ta.entity_id
        )

        extra = create_trust_chain_messages(self.tmi, self.ta)
        request_args = {'sub': self.rp.entity_id,
                        'trust_anchor': [self.ta.entity_id]}
        if entity_types is not None:
            request_args['entity_type'] = entity_types
        resolver_query = resolver.parse_request(request_args)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in extra.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": ENTITY_CONFIGURATION.content_type}, status=200)

            response = resolver.process_request(resolver_query)

        return resolver, resolver_query, response, selected_chain

    @pytest.mark.parametrize("entity_types", [
        None, ["federation_entity"],
        ["openid_relying_party", "federation_entity", "missing_type"],
    ])
    def test_resolve_filters_requested_entity_types(self, entity_types):
        self._set_trust_mark()
        _, _, response, chain = self._perform_resolve(entity_types)
        claims = verify_federation_jwt(
            profile=RESOLVE_RESPONSE, token=response["response_args"], key_jar=self.ta.keyjar,
        ).claims()
        expected = chain.metadata if entity_types is None else {
            name: chain.metadata[name] for name in entity_types if name in chain.metadata
        }
        assert claims["metadata"] == deep_freeze(expected)

    def test_resolver(self):
        self._set_trust_mark()
        resolver, resolver_query, response, _selected_chain = self._perform_resolve()

        assert response
        token = response["response_args"]
        verified = verify_federation_jwt(
            profile=RESOLVE_RESPONSE,
            token=token,
            key_jar=self.ta.keyjar,
        )
        assert verified.profile is RESOLVE_RESPONSE
        assert verified.claims()["iss"] == self.ta.entity_id
        assert verified.claims()["sub"] == self.rp.entity_id
        assert "metadata" in verified.claims()
        assert "trust_chain" in verified.claims()

        _jws = factory(token)
        assert _jws.jwt.headers.get("typ") == "resolve-response+jwt"
        payload = _jws.jwt.payload()
        assert set(payload.keys()) == {
            'metadata', 'sub', 'exp', 'iat', 'iss', 'trust_marks', 'trust_chain'
        }
        assert set(payload['metadata'].keys()) == {'federation_entity', 'openid_relying_party'}
        assert len(payload['trust_chain']) == 3

        # verify that I get the same result using the returned trust chain
        # Since what I got was EC+[ES]* where the last ES is from the Trust Anchor I have to
        # reverse the order.
        payload['trust_chain'].reverse()
        _trust_chains = verify_trust_chains(self.rp, [payload['trust_chain']])
        assert len(_trust_chains) == 1
        assert _trust_chains[0].anchor == self.ta.entity_id
        assert _trust_chains[0].iss_path == [self.rp.entity_id, self.im.entity_id,
                                             self.ta.entity_id]

        _trust_chains = apply_policies(self.rp, _trust_chains)
        assert _trust_chains[0].metadata == payload['metadata']

        assert len(payload["trust_marks"]) == 1
        assert payload["trust_marks"][0]["trust_mark_type"] == SIRTIFI_TRUST_MARK_TYPE

        http_info = resolver.do_response(response_args=response["response_args"],
                                         request=resolver_query)
        assert ("Content-type", "application/resolve-response+jwt") in http_info["http_headers"]

    def test_client_verifies_resolve_response_profile(self):
        self._set_trust_mark()
        resolver, resolver_query, response, _selected_chain = self._perform_resolve()
        http_info = resolver.do_response(
            response_args=response["response_args"],
            request=resolver_query,
        )
        http_response = Response()
        http_response.status_code = 200
        http_response._content = http_info["response"].encode("utf-8")
        http_response.headers.update(dict(http_info["http_headers"]))
        http_response.url = resolver.full_path

        client = self.rp["federation_entity"].client
        service = client.get_service("resolve")
        parsed = client.parse_request_response(
            service,
            http_response,
            response_body_type=service.response_body_type,
        )

        assert isinstance(parsed, ResolveResponse)
        assert parsed["iss"] == self.ta.entity_id
        assert parsed["sub"] == self.rp.entity_id
        assert "metadata" in parsed
        assert "trust_chain" in parsed

    def test_client_rejects_sibling_profile_as_resolve_response(self):
        endpoint = self.ta.get_endpoint("entity_configuration")
        token = endpoint.process_request({})["response"]
        http_response = Response()
        http_response.status_code = 200
        http_response._content = token.encode("utf-8")
        http_response.headers["Content-Type"] = RESOLVE_RESPONSE.content_type
        http_response.url = endpoint.full_path

        client = self.rp["federation_entity"].client
        service = client.get_service("resolve")
        with pytest.raises(FederationJwtHeaderError):
            client.parse_request_response(
                service,
                http_response,
                response_body_type=service.response_body_type,
            )

    def test_trust_mark_without_exp_does_not_shorten_response(self):
        trust_mark = self._set_trust_mark(exp=None)
        _, _, response, selected_chain = self._perform_resolve()
        verified = verify_federation_jwt(
            profile=RESOLVE_RESPONSE,
            token=response["response_args"],
            key_jar=self.ta.keyjar,
        )

        assert verified.claims()["exp"] == selected_chain.exp
        assert verified.claims()["trust_marks"][0]["trust_mark"] == trust_mark

    def test_earlier_trust_mark_exp_shortens_response(self):
        trust_mark_exp = utc_time_sans_frac() + 300
        trust_mark = self._set_trust_mark(exp=trust_mark_exp)
        _, _, response, selected_chain = self._perform_resolve()
        verified = verify_federation_jwt(
            profile=RESOLVE_RESPONSE,
            token=response["response_args"],
            key_jar=self.ta.keyjar,
        )

        assert trust_mark_exp < selected_chain.exp
        assert verified.claims()["exp"] == trust_mark_exp
        assert verified.claims()["trust_marks"][0]["trust_mark"] == trust_mark

    def test_later_trust_mark_exp_does_not_extend_response(self):
        trust_mark_exp = utc_time_sans_frac() + 172800
        trust_mark = self._set_trust_mark(exp=trust_mark_exp)
        _, _, response, selected_chain = self._perform_resolve()
        verified = verify_federation_jwt(
            profile=RESOLVE_RESPONSE,
            token=response["response_args"],
            key_jar=self.ta.keyjar,
        )

        assert trust_mark_exp > selected_chain.exp
        assert verified.claims()["exp"] == selected_chain.exp
        assert verified.claims()["trust_marks"][0]["trust_mark"] == trust_mark

    @pytest.mark.parametrize("reverse", [False, True])
    def test_multiple_trust_marks_use_earliest_expiration(self, reverse):
        now = utc_time_sans_frac()
        expirations = [now + 600, None, now + 300, now + 172800]
        entries = []
        issuer = self.tmi.server.trust_mark_entity
        for index, expiration in enumerate(expirations):
            mark_type = "https://marks.example.org/type-{}".format(index)
            issuer.trust_mark_specification[mark_type] = {}
            self.ta.context.trust_mark_issuers[mark_type] = [TMI_ID]
            kwargs = {} if expiration is None else {"exp": expiration}
            mark = issuer.create_trust_mark(mark_type, RP_ID, **kwargs)
            entries.append({"trust_mark_type": mark_type, "trust_mark": mark})
        if reverse:
            entries.reverse()
        self.rp["federation_entity"].context.trust_marks = entries
        _, _, response, chain = self._perform_resolve()
        claims = verify_federation_jwt(
            profile=RESOLVE_RESPONSE, token=response["response_args"], key_jar=self.ta.keyjar,
        ).claims()
        assert claims["trust_marks"] == deep_freeze(entries)
        assert claims["exp"] == min(chain.exp, now + 300)

    def test_unverifiable_trust_mark_is_omitted_without_shortening_response(self):
        trust_mark = self._set_trust_mark(exp=utc_time_sans_frac() + 300)
        parts = trust_mark.split(".")
        replacement = "A" if parts[2][0] != "A" else "B"
        parts[2] = replacement + parts[2][1:]
        self.rp["federation_entity"].context.trust_marks[0]["trust_mark"] = (
            ".".join(parts)
        )

        _, _, response, selected_chain = self._perform_resolve()
        verified = verify_federation_jwt(
            profile=RESOLVE_RESPONSE,
            token=response["response_args"],
            key_jar=self.ta.keyjar,
        )

        assert verified.claims()["exp"] == selected_chain.exp
        assert "trust_marks" not in verified.claims()


POLICY_IE_BAD = "https://bad-ie.example.org"
POLICY_IE_GOOD = "https://good-ie.example.org"
POLICY_SUBJECT = "https://subject.example.org"
POLICY_OTHER_SUBJECT = "https://other-subject.example.org"
POLICY_OTHER_TA = "https://other-ta.example.org"


@pytest.fixture
def policy_federation():
    config = {
        TA_ID: {
            "entity_type": "trust_anchor",
            "subordinates": [POLICY_IE_BAD, POLICY_IE_GOOD],
            "trust_anchors": [TA_ID, POLICY_OTHER_TA],
            "kwargs": {"endpoints": ["entity_configuration", "fetch", "resolve"]},
        },
        POLICY_OTHER_TA: {
            "entity_type": "trust_anchor",
            "kwargs": {"endpoints": ["entity_configuration", "fetch"]},
        },
    }
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        config[issuer] = {
            "entity_type": "intermediate",
            "subordinates": [POLICY_SUBJECT, POLICY_OTHER_SUBJECT],
            "trust_anchors": [TA_ID],
            "kwargs": {"authority_hints": [TA_ID]},
        }
    for subject in (POLICY_SUBJECT, POLICY_OTHER_SUBJECT):
        config[subject] = {
            "entity_type": "federation_entity",
            "trust_anchors": [TA_ID],
            "kwargs": {
                "authority_hints": [POLICY_IE_BAD, POLICY_IE_GOOD],
                "endpoints": ["entity_configuration"],
                "preference": {
                    "organization_name": "Subject name",
                    "homepage_uri": subject + "/",
                    "contacts": ["ops@subject.example.org"],
                },
                "services": ["entity_configuration", "entity_statement", "resolve"],
            },
        }
    federation = build_federation(config)
    ta = federation[TA_ID]
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        ta.server.subordinate[issuer].pop("entity_types", None)
        ta.server.policy[issuer] = {
            "metadata": {"federation_entity": {"organization_name": "Ancestor describes IE"}},
        }
        for subject in (POLICY_SUBJECT, POLICY_OTHER_SUBJECT):
            federation[issuer].server.subordinate[subject].pop("entity_types", None)
            federation[issuer].server.policy[subject] = {
                "metadata": {"federation_entity": {
                    "organization_name": ("Verified subject name" if issuer == POLICY_IE_GOOD
                                          else "Rejected private name"),
                }},
                "metadata_policy": {"federation_entity": {
                    "organization_name": {"one_of": ["Verified subject name"]},
                }},
            }
    return federation


def register_policy_paths(rsps, federation, subject):
    """Serve real endpoint-issued statements with subject-specific Fetch matches."""
    ta = federation[TA_ID]
    for issuer_id in (POLICY_IE_BAD, POLICY_IE_GOOD):
        issuer = federation[issuer_id]
        messages = create_trust_chain_messages(federation[subject], issuer, ta)
        for url, statement in messages.items():
            matches = []
            if url == ta.get_endpoint("fetch").full_path:
                matches = [responses.matchers.query_param_matcher({"sub": issuer_id})]
            elif url == issuer.get_endpoint("fetch").full_path:
                matches = [responses.matchers.query_param_matcher({"sub": subject})]
            rsps.add("GET", url, body=statement, match=matches, status=200,
                     content_type=ENTITY_CONFIGURATION.content_type)


def observe_verified_candidates(monkeypatch):
    """Retain independent snapshots of the actual verifier's output."""
    observed = []
    original = resolve_module.verify_trust_chains

    def verify(*args, **kwargs):
        candidates = original(*args, **kwargs)
        observed.append((candidates, deepcopy([c.verified_chain for c in candidates])))
        return candidates

    monkeypatch.setattr(resolve_module, "verify_trust_chains", verify)
    return observed


def assert_policy_success(federation, subject, result):
    endpoint = federation[TA_ID].get_endpoint("resolve")
    token = result["response_args"]
    expected = {"federation_entity": {
        "organization_name": "Verified subject name",
        "homepage_uri": subject + "/",
        "contacts": ("ops@subject.example.org",),
    }}
    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE, token=token, key_jar=federation[TA_ID].keyjar,
    )
    assert verified.claims()["metadata"] == expected
    assert verified.claims()["sub"] == subject
    chain = verified.claims()["trust_chain"]
    assert len(chain) == 3
    assert factory(chain[1]).jwt.payload()["iss"] == POLICY_IE_GOOD

    envelope = do_response(endpoint, **result)
    assert envelope["response"] == token
    assert ("Content-type", RESOLVE_RESPONSE.content_type) in envelope["http_headers"]
    response = Response()
    response.status_code = 200
    response._content = envelope["response"].encode("utf-8")
    response.headers.update(dict(envelope["http_headers"]))
    response.url = endpoint.full_path
    client = federation[subject].client
    service = client.get_service("resolve")
    parsed = client.parse_request_response(service, response,
                                          response_body_type=service.response_body_type)
    assert isinstance(parsed, ResolveResponse)
    assert parsed.to_dict()["metadata"] == {"federation_entity": {
        "organization_name": "Verified subject name",
        "homepage_uri": subject + "/",
        "contacts": ["ops@subject.example.org"],
    }}
    return token


def test_resolve_add_contacts_flat_and_stable(policy_federation):
    federation = policy_federation
    policy = federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT]
    policy["metadata_policy"]["federation_entity"]["contacts"] = {
        "add": ["ops@subject.example.org", "new@example.org", "new@example.org"],
    }
    before = deepcopy(policy)
    expected = {"federation_entity": {
        "organization_name": "Verified subject name", "homepage_uri": POLICY_SUBJECT + "/",
        "contacts": ("ops@subject.example.org", "new@example.org"),
    }}
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            result = endpoint.process_request(query)
            verified = verify_federation_jwt(profile=RESOLVE_RESPONSE,
                token=result["response_args"], key_jar=federation[TA_ID].keyjar)
            assert verified.claims()["metadata"] == expected
    assert policy == before


def test_resolve_schema_value_default_policy(policy_federation):
    federation = policy_federation
    policy = MetadataPolicy(federation_entity={
        "organization_name": Policy(value="Verified subject name").to_dict(),
        "homepage_uri": Policy(default="https://fallback.example.org/").to_dict(),
    })
    policy.verify()
    federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT]["metadata_policy"] = policy.to_dict()
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            assert_policy_success(federation, POLICY_SUBJECT, endpoint.process_request(query))


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("position", ["superior", "immediate"])
@pytest.mark.parametrize("critical", [[], ["value"], ["regexp"]])
@pytest.mark.parametrize("all_invalid", [False, True])
def test_resolve_critical_policy_failures(
        policy_federation, monkeypatch, reverse, position, critical, all_invalid):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    # Both paths otherwise satisfy ordinary policy. The additional operator
    # alone is ignorable; only a critical declaration makes the path invalid.
    federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT] = deepcopy(
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        policy = (federation[TA_ID].server.policy[issuer] if position == "superior"
                  else federation[issuer].server.policy[POLICY_SUBJECT])
        policy.setdefault("metadata_policy", {})["oauth_client"] = {
            "client_name": {"regexp": "private-critical-expression"},
        }
        if issuer == POLICY_IE_BAD or all_invalid:
            policy["metadata_policy_crit"] = critical
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    signer = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            result = endpoint.process_request(query)
            if all_invalid:
                assert result["error"] == "invalid_trust_chain"
                assert result["response_code"] == 400
                assert "response_args" not in result
                with Flask(__name__).test_request_context("/resolve"):
                    response = example_do_response(endpoint, query, **result)
                assert response.status_code == 400
                assert response.mimetype == "application/json"
                assert response.get_json() == {
                    "error": "invalid_trust_chain",
                    "error_description": "Resolve found no acceptable chain for the requested trust anchor.",
                }
                assert "private-critical-expression" not in response.get_data(as_text=True)
            else:
                assert_policy_success(federation, POLICY_SUBJECT, result)
    if all_invalid:
        signer.assert_not_called()
    else:
        assert signer.call_count == 2
    assert all(len(candidates) == (0 if all_invalid else 1) for candidates, _ in observed)


@pytest.mark.parametrize("reverse", [False, True])
def test_resolve_invalid_entity_type_constraint_alternative(policy_federation, monkeypatch, reverse):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT] = deepcopy(
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
    federation[TA_ID].server.policy[POLICY_IE_BAD]["constraints"] = {
        "allowed_entity_types": ["federation_entity"],
    }
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            assert_policy_success(federation, POLICY_SUBJECT, endpoint.process_request(query))
    assert all(len(candidates) == 1 for candidates, _ in observed)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("upper, lower, expected_types", [
    (None, None, {"federation_entity", "openid_relying_party", "oauth_client"}),
    ([], None, {"federation_entity"}),
    (None, ["oauth_client"], {"federation_entity", "oauth_client"}),
    (["oauth_client"], ["oauth_client", "openid_relying_party"],
     {"federation_entity", "oauth_client"}),
    (["oauth_client"], ["openid_relying_party"], {"federation_entity"}),
])
def test_resolve_allowed_entity_types_signed_and_client(
        policy_federation, monkeypatch, reverse, upper, lower, expected_types):
    federation = policy_federation
    subject = federation[POLICY_SUBJECT]
    if reverse:
        subject.context.authority_hints.reverse()
    metadata = {
        "federation_entity": {"organization_name": "Subject name",
                              "homepage_uri": POLICY_SUBJECT + "/",
                              "contacts": ["ops@subject.example.org"]},
        "openid_relying_party": {"redirect_uris": [POLICY_SUBJECT + "/cb"],
                                 "application_type": "web", "response_types": ["code"]},
        "oauth_client": {"client_name": "Subject client"},
    }
    monkeypatch.setattr(subject, "get_metadata", lambda: deepcopy(metadata))
    good = federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT]
    good["metadata"].update({"oauth_client": {"client_name": "Direct client"},
                            "openid_provider": {"issuer": "https://undeclared.example.org"}})
    good["metadata_policy"]["oauth_client"] = {"client_name": {"one_of": ["Direct client"]}}
    good["metadata_policy"]["openid_provider"] = {"issuer": {"value": "https://undeclared.example.org"}}
    for policy, allowed in ((federation[TA_ID].server.policy[POLICY_IE_GOOD], upper), (good, lower)):
        if allowed is not None:
            policy["constraints"] = {"allowed_entity_types": allowed}
    expected_all = deepcopy(metadata)
    expected_all["federation_entity"]["organization_name"] = "Verified subject name"
    expected_all["oauth_client"]["client_name"] = "Direct client"
    expected = {typ: expected_all[typ] for typ in expected_types}
    before = deepcopy((metadata, good, federation[TA_ID].server.policy))
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            result = endpoint.process_request(query)
            verified = verify_federation_jwt(
                profile=RESOLVE_RESPONSE, token=result["response_args"], key_jar=federation[TA_ID].keyjar)
            assert verified.claims()["metadata"] == deep_freeze(expected)
            envelope = do_response(endpoint, **result)
            response = Response()
            response.status_code = 200
            response._content = envelope["response"].encode("utf-8")
            response.headers.update(dict(envelope["http_headers"]))
            response.url = endpoint.full_path
            service = subject.client.get_service("resolve")
            parsed = subject.client.parse_request_response(
                service, response, response_body_type=service.response_body_type)
            assert parsed.to_dict()["metadata"] == expected
    assert (metadata, good, federation[TA_ID].server.policy) == before
    for candidates, original in observed:
        assert [c.verified_chain for c in candidates] == original
        accepted = next(c for c in candidates if c.metadata)
        for statement, allowed in zip(accepted.verified_chain[:-1], (upper, lower)):
            if allowed is not None:
                assert statement["constraints"]["allowed_entity_types"] == allowed


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("bad_name", [".example.net", "https://.example.org"])
def test_resolve_naming_alternative(policy_federation, monkeypatch, reverse, bad_name):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT] = deepcopy(
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
    for issuer, name in ((POLICY_IE_BAD, bad_name), (POLICY_IE_GOOD, ".example.org")):
        federation[TA_ID].server.policy[issuer]["constraints"] = {
            "naming_constraints": {"permitted": [name]},
        }
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            result = endpoint.process_request(query)
            assert_policy_success(federation, POLICY_SUBJECT, result)
    for candidates, before in observed:
        assert len(candidates) == 1
        assert candidates[0].verified_chain[-2]["iss"] == POLICY_IE_GOOD
        assert [c.verified_chain for c in candidates] == before


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("bad_limit", [0, -1])
def test_resolve_path_length_alternative(policy_federation, monkeypatch, reverse, bad_limit):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    # Both candidates satisfy policy; only the first path's TA limit fails.
    federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT] = deepcopy(
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
    for issuer, limit in ((POLICY_IE_BAD, bad_limit), (POLICY_IE_GOOD, 1)):
        federation[TA_ID].server.policy[issuer]["constraints"] = {"max_path_length": limit}
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        result = endpoint.process_request(query)
    assert_policy_success(federation, POLICY_SUBJECT, result)
    assert len(observed[0][0]) == 1
    assert observed[0][0][0].verified_chain[-2]["iss"] == POLICY_IE_GOOD


def test_resolve_all_negative_path_lengths_never_signs(policy_federation, monkeypatch):
    federation = policy_federation
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        federation[TA_ID].server.policy[issuer]["constraints"] = {"max_path_length": -1}
    signer = Mock(side_effect=AssertionError("invalid candidates must not be signed"))
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        result = endpoint.process_request(query)
    with Flask(__name__).test_request_context("/resolve"):
        response = example_do_response(endpoint, query, **result)
    assert response.status_code == 400
    assert response.mimetype == "application/json"
    assert response.get_json() == {
        "error": "invalid_trust_chain",
        "error_description": "Resolve found no acceptable chain for the requested trust anchor.",
    }
    signer.assert_not_called()


@pytest.mark.parametrize("reverse", [False, True])
def test_resolve_policy_alternatives_signed_composition(
        policy_federation, monkeypatch, reverse):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            result = endpoint.process_request(query)
            assert_policy_success(federation, POLICY_SUBJECT, result)
    for candidates, before in observed:
        assert [c.verified_chain for c in candidates] == before
        assert len(candidates) == 2
        expected_order = [POLICY_IE_GOOD, POLICY_IE_BAD] if reverse else [
            POLICY_IE_BAD, POLICY_IE_GOOD]
        assert [c.verified_chain[-2]["iss"] for c in candidates] == expected_order
        rejected = next(c for c in candidates if c.err.get("metadata_policy"))
        assert rejected.metadata == rejected.combined_policy == {}


@pytest.mark.parametrize("outcome", ["invalid_metadata", "invalid_trust_chain"])
def test_resolve_expected_errors_are_json_and_never_signed(
        policy_federation, monkeypatch, outcome):
    federation = policy_federation
    endpoint = federation[TA_ID].get_endpoint("resolve")
    requested_anchor = TA_ID
    if outcome == "invalid_metadata":
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT]["metadata"][
            "federation_entity"]["organization_name"] = "Rejected private name"
    else:
        requested_anchor = POLICY_OTHER_TA
        policy = Mock(side_effect=AssertionError("irrelevant policy must not run"))
        monkeypatch.setattr(federation[TA_ID].function, "policy", policy)
    signer = Mock(side_effect=AssertionError("error must not be signed"))
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [requested_anchor]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        result = endpoint.process_request(query)
    assert result["error"] == outcome
    assert result["response_code"] == 400
    assert result["error_description"]
    envelope = do_response(endpoint, **result)
    expected = {"error": outcome, "error_description": result["error_description"]}
    assert json.loads(envelope["response"]) == expected
    assert envelope["response_code"] == 400
    assert ("Content-type", "application/json") in envelope["http_headers"]
    assert "Rejected private name" not in envelope["response"]
    assert "error" in result
    app = Flask(__name__)
    with app.test_request_context("/resolve"):
        response = example_do_response(endpoint, query, **result)
    assert response.status_code == 400
    assert response.mimetype == "application/json"
    assert response.get_json() == expected
    signer.assert_not_called()
    if outcome == "invalid_trust_chain":
        policy.assert_not_called()
    assert endpoint.response_format == "jose"
    assert endpoint.response_content_type == RESOLVE_RESPONSE.content_type


@pytest.mark.parametrize("query", [
    "", "sub=https%3A%2F%2Fsubject.example.org",
    "trust_anchor=https%3A%2F%2Fta.example.org",
    "sub=https%3A%2F%2Fsubject.example.org&trust_anchor=",
])
def test_resolve_rejects_missing_required_query_parameters(policy_federation, query):
    endpoint = policy_federation[TA_ID].get_endpoint("resolve")
    parsed = endpoint.parse_request(query)
    assert parsed["error"] == "invalid_request"


@pytest.mark.parametrize("multiple", [False, True])
def test_resolve_client_repeated_query_wire_format(policy_federation, multiple):
    service = policy_federation[POLICY_SUBJECT].get_service("resolve")
    anchors = [POLICY_OTHER_TA, TA_ID] if multiple else TA_ID
    types = ["federation_entity", "openid_provider"] if multiple else "federation_entity"
    args = {"sub": POLICY_SUBJECT, "trust_anchor": anchors, "entity_type": types}
    before = deepcopy(args)
    result = service.get_request_parameters(request_args=args, endpoint=TA_ID + "/resolve")
    query = urlsplit(result["url"]).query
    assert result["method"] == "GET"
    assert parse_qs(query) == {
        "sub": [POLICY_SUBJECT],
        "trust_anchor": anchors if multiple else [anchors],
        "entity_type": types if multiple else [types],
    }
    assert args == before
    parsed = policy_federation[TA_ID].get_endpoint("resolve").parse_request(query)
    assert isinstance(parsed, ResolveRequest)
    assert parsed["trust_anchor"] == (anchors if multiple else [anchors])
    assert parsed["entity_type"] == (types if multiple else [types])
    assert "type" not in parsed.c_param


@pytest.mark.parametrize("module", ["dc4eu_federation", "edu_federation", "setup_federation"])
def test_resolve_flask_repeated_parameters_select_requested_anchor(policy_federation, monkeypatch, module):
    federation = policy_federation
    endpoint = federation[TA_ID].get_endpoint("resolve")
    process = Mock(wraps=endpoint.process_request)
    monkeypatch.setattr(endpoint, "process_request", process)
    app = Flask(__name__)
    app.federation_entity = federation[TA_ID]
    app.register_blueprint(import_module(module + ".trust_anchor.views").entity)
    service = federation[POLICY_SUBJECT].get_service("resolve")
    url = service.get_request_parameters(request_args={
        "sub": POLICY_SUBJECT, "trust_anchor": [POLICY_OTHER_TA, TA_ID],
        "entity_type": ["federation_entity", "missing_type"],
    }, endpoint="/resolve")["url"]
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        response = app.test_client().get(url)
    assert response.status_code == 200
    assert response.mimetype == RESOLVE_RESPONSE.content_type
    parsed = process.call_args[0][0]
    assert isinstance(parsed, ResolveRequest)
    assert parsed["trust_anchor"] == [POLICY_OTHER_TA, TA_ID]
    assert parsed["entity_type"] == ["federation_entity", "missing_type"]
    assert_policy_success(federation, POLICY_SUBJECT, {"response_args": response.get_data(as_text=True)})


def test_resolve_multiple_unrequested_anchors_cannot_succeed(policy_federation):
    endpoint = policy_federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({
        "sub": POLICY_SUBJECT,
        "trust_anchor": [POLICY_OTHER_TA, "https://unusable.example.org"],
    })
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, policy_federation, POLICY_SUBJECT)
        result = endpoint.process_request(query)
    assert result["error"] == "invalid_trust_chain"
    assert result["response_code"] == 400


def test_resolve_success_failure_success_and_subject_isolation(policy_federation, monkeypatch):
    federation = policy_federation
    endpoint = federation[TA_ID].get_endpoint("resolve")
    observed = observe_verified_candidates(monkeypatch)
    # The second subject has no acceptable policy path; the first remains valid.
    federation[POLICY_IE_GOOD].server.policy[POLICY_OTHER_SUBJECT]["metadata"][
        "federation_entity"]["organization_name"] = "Rejected private name"
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for subject in (POLICY_SUBJECT, POLICY_OTHER_SUBJECT):
            register_policy_paths(rsps, federation, subject)
        for subject in (POLICY_SUBJECT, POLICY_OTHER_SUBJECT, POLICY_SUBJECT):
            query = endpoint.parse_request({"sub": subject, "trust_anchor": [TA_ID]})
            result = endpoint.process_request(query)
            with Flask(__name__).test_request_context("/resolve"):
                response = example_do_response(endpoint, query, **result)
            if subject == POLICY_OTHER_SUBJECT:
                assert result["error"] == "invalid_metadata"
                assert do_response(endpoint, **result)["response_code"] == 400
                assert response.status_code == 400
                assert response.mimetype == "application/json"
                assert response.get_json() == {
                    "error": result["error"],
                    "error_description": result["error_description"],
                }
            else:
                token = assert_policy_success(federation, subject, result)
                assert response.status_code == 200
                assert response.mimetype == RESOLVE_RESPONSE.content_type
                assert response.get_data(as_text=True) == token
    for candidates, before in observed:
        assert [c.verified_chain for c in candidates] == before
    assert endpoint.response_format == "jose"
    assert endpoint.response_content_type == RESOLVE_RESPONSE.content_type


def test_resolve_unexpected_policy_failure_propagates(policy_federation, monkeypatch):
    federation = policy_federation
    endpoint = federation[TA_ID].get_endpoint("resolve")
    monkeypatch.setattr(federation[TA_ID].function.policy, "apply_policy",
                        Mock(side_effect=TypeError("internal failure")))
    signer = Mock()
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        with pytest.raises(TypeError, match="internal failure"):
            endpoint.process_request(endpoint.parse_request(
                {"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]}))
    signer.assert_not_called()


@pytest.mark.parametrize("offset", [-1, 0])
def test_create_resolve_response_rejects_expiration_at_or_before_issuance(monkeypatch, offset):
    now = utc_time_sans_frac()
    monkeypatch.setattr("fedservice.entity_statement.create.utc_time_sans_frac", lambda: now)
    signer = Mock(side_effect=AssertionError("expired response must not be signed"))
    monkeypatch.setattr("fedservice.entity_statement.create.sign_federation_jwt", signer)
    with pytest.raises(ResolveResponseExpired, match="Resolve Response must expire after issuance"):
        create_resolve_response(
            RESOLVER_ID, sub=SUBJECT_ID, key_jar=resolve_signing_keyjar(),
            metadata=resolve_metadata(), trust_chain=compact_trust_chain(), expires_at=now + offset,
        )
    signer.assert_not_called()


@pytest.mark.parametrize("elapsed", [0, 1])
@pytest.mark.parametrize("at_creation", [False, True])
def test_resolve_expiration_during_processing_is_json_error(
        policy_federation, monkeypatch, elapsed, at_creation):
    federation = policy_federation
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    original = resolve_module.apply_policies

    def advance_clock(*args, **kwargs):
        chains = original(*args, **kwargs)
        expiration = chains[0].exp
        monkeypatch.setattr(resolve_module, "utc_time_sans_frac",
                            lambda: expiration - 1 if at_creation else expiration + elapsed)
        monkeypatch.setattr("fedservice.entity_statement.create.utc_time_sans_frac",
                            lambda: expiration + elapsed)
        return chains

    monkeypatch.setattr(resolve_module, "apply_policies", advance_clock)
    creator = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", creator)
    signer = Mock(side_effect=AssertionError("expired response must not be signed"))
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        monkeypatch.setattr("fedservice.entity_statement.create.sign_federation_jwt", signer)
        result = endpoint.process_request(query)
    assert creator.call_count == (1 if at_creation else 0)
    signer.assert_not_called()
    assert result["error"] == "invalid_trust_chain"
    with Flask(__name__).test_request_context("/resolve"):
        response = example_do_response(endpoint, query, **result)
    assert response.status_code == 400
    assert response.mimetype == "application/json"
    assert response.get_json() == {
        "error": "invalid_trust_chain", "error_description": "Resolve result has expired.",
    }


@pytest.mark.parametrize("error_cls", [
    FederationJwtSignatureError, FederationJwtKeyResolutionError, ValueError,
])
@pytest.mark.parametrize("elapsed", [0, 1])
def test_resolve_creation_failure_propagates_when_clock_crosses_expiration(
        policy_federation, monkeypatch, error_cls, elapsed):
    endpoint = policy_federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    original = resolve_module.apply_policies
    clock = {}
    failure = error_cls("Unrelated response creation failure")

    def set_clock_before_expiration(*args, **kwargs):
        chains = original(*args, **kwargs)
        clock["expiration"] = chains[0].exp
        clock["now"] = chains[0].exp - 1
        return chains

    def fail_during_signing(**kwargs):
        assert kwargs["iat"] == clock["now"] < kwargs["payload"]["exp"]
        clock["now"] = clock["expiration"] + elapsed
        raise failure

    monkeypatch.setattr(resolve_module, "apply_policies", set_clock_before_expiration)
    monkeypatch.setattr(resolve_module, "utc_time_sans_frac", lambda: clock["now"])
    signer = Mock(side_effect=fail_during_signing)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, policy_federation, POLICY_SUBJECT)
        monkeypatch.setattr("fedservice.entity_statement.create.utc_time_sans_frac",
                            lambda: clock["now"])
        monkeypatch.setattr("fedservice.entity_statement.create.sign_federation_jwt", signer)
        with pytest.raises(error_cls) as caught:
            endpoint.process_request(query)
    assert caught.value is failure
    assert clock["now"] >= clock["expiration"]
    signer.assert_called_once()


def test_resolve_client_revalidates_response_after_expiration(policy_federation, monkeypatch):
    federation = policy_federation
    now = utc_time_sans_frac()
    expiration = now + 60
    token = create_resolve_response(
        TA_ID, sub=POLICY_SUBJECT, key_jar=federation[TA_ID].keyjar,
        metadata=resolve_metadata(), trust_chain=compact_trust_chain(), expires_at=expiration,
    )
    client = federation[POLICY_SUBJECT].client
    request_args = {"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]}
    url = TA_ID + "/resolve"
    with responses.RequestsMock() as rsps:
        rsps.add("GET", url, body=token, status=200, content_type=RESOLVE_RESPONSE.content_type)
        monkeypatch.setattr("cryptojwt.jwt.utc_time_sans_frac", lambda: now)
        parsed = client.do_request("resolve", request_args=request_args, endpoint=url)
        assert isinstance(parsed, ResolveResponse)
        assert parsed["exp"] == expiration
        verification_expiration = expiration + JWT().skew
        for timestamp in (verification_expiration, verification_expiration + 1):
            monkeypatch.setattr("cryptojwt.jwt.utc_time_sans_frac", lambda: timestamp)
            with pytest.raises(FederationJwtPayloadError):
                client.do_request("resolve", request_args=request_args, endpoint=url)
        assert len(rsps.calls) == 3
