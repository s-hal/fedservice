from copy import deepcopy
from importlib import import_module
import json
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit, urlencode

from flask import Flask
import pytest
import responses
from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.jwt import JWT
from idpyoidc.client.exception import WrongContentType
from idpyoidc.exception import MissingPage
from idpyoidc.storage.abfile import AbstractFileSystem
from requests import Response
from requests.exceptions import ConnectionError
from requests.exceptions import ConnectTimeout
from requests.exceptions import ReadTimeout
from requests.exceptions import Timeout
from edu_federation.trust_anchor.views import do_response as example_do_response
from fedservice.entity.server import resolve as resolve_module
from fedservice.entity.server.response import do_response
from fedservice.entity.function import collect_trust_chains

from fedservice.entity.function import apply_policies
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function import verifier as verifier_module
from fedservice.entity_statement.create import create_resolve_response
from fedservice.entity_statement.create import create_entity_configuration
from fedservice.exception import FailedConfigurationRetrieval
from fedservice.exception import ResolveResponseExpired
from fedservice.exception import WrongSubject
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.message import ResolveResponse
from fedservice.message import ResolveRequest
from fedservice.message import Policy
from fedservice.message import MetadataPolicy
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages
from tests.build_federation import build_federation
from tests.build_federation import make_entity
from tests.test_41_federation_entity import corrupt_signature

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
        "trust_anchors": [TA_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": ["operations@ta.example.org"]
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
                "contacts": ["operations@rp.example.com"]
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
            expected_resolver=self.ta.entity_id, expected_subject=self.rp.entity_id,
            expected_trust_anchors=(self.ta.entity_id,), expected_audience=self.rp.entity_id,
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
                expected_resolver=self.ta.entity_id, expected_subject=self.rp.entity_id,
                expected_trust_anchors=(self.ta.entity_id,), expected_audience=self.rp.entity_id,
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

    @pytest.mark.parametrize("mark_lifetime", [1800, 7200])
    def test_resolve_anchor_expiry_trust_mark_minimum(self, anchor_expiry_clock, mark_lifetime):
        now = anchor_expiry_clock[0]
        mark = self._set_trust_mark(exp=now + mark_lifetime)
        resolver = _anchor_subject_resolver({TA_ID: self.ta.keyjar.export_jwks()})
        messages = create_trust_chain_messages(self.rp, self.im, self.ta)
        issuer_messages = create_trust_chain_messages(self.tmi, self.ta)
        fetch_url = self.ta.get_endpoint("fetch").full_path
        messages[fetch_url + "?" + urlencode({"sub": IM_ID})] = messages.pop(fetch_url)
        messages[fetch_url + "?" + urlencode({"sub": TMI_ID})] = issuer_messages.pop(fetch_url)
        messages.update(issuer_messages)
        _anchor_expiry_reissue(messages, self.ta, now + 3600)
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            _register_anchor_expiry_paths(rsps, messages)
            result = _anchor_subject_request(resolver, RP_ID, [TA_ID])
        verified = verify_federation_jwt(RESOLVE_RESPONSE, result["response_args"], resolver.keyjar)
        assert verified.claims()["iss"] == RESOLVER_ID
        assert verified.claims()["sub"] == RP_ID
        assert verified.claims()["exp"] == now + min(3600, mark_lifetime)
        assert verified.claims()["trust_marks"][0]["trust_mark"] == mark

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
                                          response_body_type=service.response_body_type,
                                          expected_resolver=TA_ID, expected_subject=subject,
                                          expected_trust_anchors=(TA_ID,), expected_audience=subject)
    assert isinstance(parsed, ResolveResponse)
    assert parsed.to_dict()["metadata"] == {"federation_entity": {
        "organization_name": "Verified subject name",
        "homepage_uri": subject + "/",
        "contacts": ["ops@subject.example.org"],
    }}
    return token


@pytest.mark.parametrize("mode", ["one", "all", "shared"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("adapter", [None, "dc4eu_federation", "edu_federation", "setup_federation"])
def test_resolve_signature_failure_is_candidate_local(
        policy_federation, monkeypatch, mode, reverse, adapter):
    federation = policy_federation
    ta, bad, good, leaf = [federation[key] for key in
                          (TA_ID, POLICY_IE_BAD, POLICY_IE_GOOD, POLICY_SUBJECT)]
    bad.server.policy[leaf.entity_id] = deepcopy(good.server.policy[leaf.entity_id])
    if mode == "shared":
        bad.server.subordinate[good.entity_id] = {
            "jwks": good.keyjar.export_jwks(), "entity_type": ["federation_entity"],
        }
        bad.server.policy[good.entity_id] = {}
        good.context.authority_hints = [bad.entity_id, ta.entity_id]
    if reverse:
        leaf.context.authority_hints.reverse()
        good.context.authority_hints.reverse()

    def register(rsps):
        register_policy_paths(rsps, federation, leaf.entity_id)
        if mode == "shared":
            fetch = bad.get_endpoint("fetch")
            token = fetch.process_request(fetch.parse_request({"sub": good.entity_id}))[
                "response_msg"]
            rsps.add("GET", fetch.full_path, body=token, status=200,
                     content_type=SUBORDINATE_STATEMENT.content_type,
                     match=[responses.matchers.query_param_matcher({"sub": good.entity_id})])

    endpoint = ta.get_endpoint("resolve")
    query = {"sub": leaf.entity_id, "trust_anchor": [ta.entity_id]}
    observed = observe_verified_candidates(monkeypatch)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register(rsps)
        control = endpoint.process_request(endpoint.parse_request(query))
    verified_control = verify_federation_jwt(
        profile=RESOLVE_RESPONSE, token=control["response_args"], key_jar=ta.keyjar)
    assert verified_control.claims()["sub"] == leaf.entity_id
    assert len(observed[0][0]) == (3 if mode == "shared" else 2)
    assert all(not candidate.err for candidate in observed[0][0])
    observed.clear()
    collector = ta.function.trust_chain_collector
    collector.config_cache._db.clear()
    collector.entity_statement_cache._db.clear()

    collected = []
    original_collect = resolve_module.collect_trust_chains

    def record_collection(*args, **kwargs):
        chains, ec = original_collect(*args, **kwargs)
        collected.append([chain[:] + [ec] for chain in chains])
        return chains, ec

    monkeypatch.setattr(resolve_module, "collect_trust_chains", record_collection)
    signer = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    if adapter:
        app = Flask(__name__)
        app.federation_entity = ta
        app.register_blueprint(import_module(adapter + ".trust_anchor.views").entity)
        client = app.test_client()

    corrupted = set()
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register(rsps)
        for response in rsps.registered():
            payload = factory(response.body).jwt.payload()
            if mode == "shared":
                reject = payload["iss"] == ta.entity_id and payload["sub"] == bad.entity_id
            else:
                reject = (payload["sub"] == leaf.entity_id and
                          payload["iss"] in ([bad.entity_id, good.entity_id]
                                             if mode == "all" else [bad.entity_id]))
            if reject:
                original = response.body
                response.body = corrupt_signature(original)
                assert response.body.split(".")[:2] == original.split(".")[:2]
                with pytest.raises(FederationJwtSignatureError) as error:
                    verify_federation_jwt(profile=SUBORDINATE_STATEMENT,
                        token=response.body, key_jar=federation[payload["iss"]].keyjar)
                assert type(error.value) is FederationJwtSignatureError
                corrupted.add(response.body)
        assert len(corrupted) == (2 if mode == "all" else 1)
        for _ in range(2):
            if adapter:
                response = client.get("/resolve", query_string=query)
                if mode == "all":
                    assert response.status_code == 400
                    assert response.mimetype == "application/json"
                    result = response.get_json()
                else:
                    assert response.status_code == 200
                    assert response.mimetype == RESOLVE_RESPONSE.content_type
                    result = {"response_args": response.get_data(as_text=True)}
            else:
                result = endpoint.process_request(endpoint.parse_request(query))
                if mode == "all":
                    assert result["response_code"] == 400
            if mode == "all":
                assert result["error"] == "invalid_trust_chain"
                assert result["error_description"]
                assert "response_args" not in result
                signer.assert_not_called()
            else:
                token = assert_policy_success(federation, leaf.entity_id, result)
                verified = verify_federation_jwt(
                    profile=RESOLVE_RESPONSE, token=token, key_jar=ta.keyjar)
                independent = [chain for chain in collected[-1]
                               if not corrupted.intersection(chain)]
                assert len(independent) == 1
                assert verified.claims()["trust_chain"] == tuple(reversed(independent[0]))
                assert not corrupted.intersection(verified.claims()["trust_chain"])
            if mode == "shared":
                assert len(collected[-1]) == 3
                shared = next(iter(corrupted))
                dependent = [chain for chain in collected[-1] if shared in chain]
                assert len(dependent) == 2
                assert dependent[0] != dependent[1]

    assert len(observed) == 2
    for candidates, before in observed:
        assert [candidate.verified_chain for candidate in candidates] == before
        assert len(candidates) == (0 if mode == "all" else 1)
        assert all(candidate.verified_chain[-2]["iss"] == good.entity_id
                   for candidate in candidates)
    if mode != "all":
        assert signer.call_count == 2


def test_signature_failure_does_not_install_unverified_keys(policy_federation, monkeypatch):
    ta, bad, leaf = [policy_federation[key] for key in (TA_ID, POLICY_IE_BAD, POLICY_SUBJECT)]
    messages = create_trust_chain_messages(leaf, bad, ta)
    first = messages[ta.get_endpoint("fetch").full_path]
    failing = corrupt_signature(messages[bad.get_endpoint("fetch").full_path])
    ec = messages[leaf.get_endpoint("entity_configuration").full_path]
    assert bad.entity_id not in ta.keyjar
    assert leaf.entity_id not in ta.keyjar
    original_ta_keys = ta.keyjar.export_jwks(issuer_id=ta.entity_id)
    install = Mock(wraps=ta.keyjar.add_kb)
    monkeypatch.setattr(ta.keyjar, "add_kb", install)

    assert ta.function.verifier._verify_trust_chain([first, failing, ec]) == []

    assert ta.keyjar.export_jwks(issuer_id=bad.entity_id) == bad.keyjar.export_jwks()
    assert ta.keyjar.export_jwks(issuer_id=ta.entity_id) == original_ta_keys
    assert leaf.entity_id not in ta.keyjar
    assert [call[0][0] for call in install.call_args_list] == [bad.entity_id]


@pytest.mark.parametrize("error_cls", [RuntimeError, ValueError,
                                      FederationJwtHeaderError, FederationJwtKeyResolutionError])
def test_resolve_unclassified_verification_errors_propagate(
        policy_federation, monkeypatch, error_cls):
    endpoint = policy_federation[TA_ID].get_endpoint("resolve")
    failure = error_cls("unclassified verification failure")
    monkeypatch.setattr(verifier_module, "verify_federation_jwt", Mock(side_effect=failure))
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, policy_federation, POLICY_SUBJECT)
        with pytest.raises(error_cls) as error:
            endpoint.process_request(endpoint.parse_request({
                "sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]}))
    assert error.value is failure


@pytest.mark.parametrize(
    "claim,value",
    [("metadata", []), ("metadata_policy", {}),
     ("metadata", {"openid_relying_party": {"response_types": None}}),
     ("metadata", {"federation_entity": {"contacts": "ops@example.org"}})],
)
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("all_invalid", [False, True])
def test_resolve_payload_invalid_candidate_is_local(
        policy_federation, monkeypatch, claim, value, reverse, all_invalid):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    invalid_issuers = (
        (POLICY_IE_BAD, POLICY_IE_GOOD) if all_invalid else (POLICY_IE_BAD,)
    )
    for issuer_id in invalid_issuers:
        federation[issuer_id].server.policy[POLICY_SUBJECT][claim] = deepcopy(value)
        fetch = federation[issuer_id].get_endpoint("fetch")
        statement = fetch.process_request(fetch.parse_request({"sub": POLICY_SUBJECT}))[
            "response_msg"
        ]
        assert factory(statement).jwt.payload()[claim] == value
        with pytest.raises(FederationJwtPayloadError) as error:
            verify_federation_jwt(
                profile=SUBORDINATE_STATEMENT,
                token=statement,
                key_jar=federation[issuer_id].keyjar,
            )
        assert isinstance(error.value.__cause__, ValueError)
        assert claim in str(error.value.__cause__)

    sources = [(federation[issuer].server.subordinate, federation[issuer].server.policy)
               for issuer in (TA_ID, POLICY_IE_BAD, POLICY_IE_GOOD)]
    sources_before = deepcopy(sources)
    collector = federation[TA_ID].function.trust_chain_collector
    caches = (collector.config_cache, collector.entity_statement_cache)
    cache_contents = None
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
                assert result == {
                    "error": "invalid_trust_chain",
                    "error_description": (
                        "Resolve found no acceptable chain for the requested trust anchor."
                    ),
                    "response_code": 400,
                }
                with Flask(__name__).test_request_context("/resolve"):
                    response = example_do_response(endpoint, query, **result)
                assert response.status_code == 400
                assert response.mimetype == "application/json"
                assert response.get_json() == {
                    "error": "invalid_trust_chain",
                    "error_description": result["error_description"],
                }
            else:
                assert_policy_success(federation, POLICY_SUBJECT, result)
            assert sources == sources_before
            if cache_contents is None:
                cache_contents = deepcopy([cache._db for cache in caches])
            else:
                assert [cache._db for cache in caches] == cache_contents
            assert caches == (collector.config_cache, collector.entity_statement_cache)

    if all_invalid:
        signer.assert_not_called()
    else:
        assert signer.call_count == 2
    for candidates, before in observed:
        assert [candidate.verified_chain for candidate in candidates] == before
        assert len(candidates) == (0 if all_invalid else 1)
        if candidates:
            assert candidates[0].verified_chain[-2]["iss"] == POLICY_IE_GOOD
            assert candidates[0].metadata["federation_entity"][
                "organization_name"
            ] == "Verified subject name"


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("failure", ["merge", "application"])
def test_resolve_one_of_overlap_and_candidate_isolation(policy_federation, monkeypatch, reverse, failure):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        federation[TA_ID].server.policy[issuer]["metadata_policy"] = {
            "federation_entity": {"organization_name": {
                "one_of": ["Verified subject name", "Upper only"],
            }},
        }
        rule = federation[issuer].server.policy[POLICY_SUBJECT]["metadata_policy"]
        rule["federation_entity"]["organization_name"] = {
            "one_of": (["Disjoint"] if issuer == POLICY_IE_BAD and failure == "merge"
                       else ["Verified subject name", "Lower only"]),
        }
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        assert_policy_success(federation, POLICY_SUBJECT, endpoint.process_request(query))
    candidates, before = observed[0]
    assert [c.verified_chain for c in candidates] == before
    rejected = [c for c in candidates if "metadata_policy" in c.err]
    assert len(rejected) == 1
    assert rejected[0].err["metadata_policy"]["error"] == "invalid_metadata"
    assert rejected[0].metadata == rejected[0].combined_policy == {}


@pytest.mark.parametrize("operator", ["value", "default"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("all_invalid", [False, True])
def test_resolve_value_default_metadata_types_are_candidate_local(
        policy_federation, monkeypatch, operator, reverse, all_invalid):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    invalid_issuers = ((POLICY_IE_BAD, POLICY_IE_GOOD) if all_invalid else (POLICY_IE_BAD,))
    verified_statements = []
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        record = deepcopy(federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
        record["metadata"]["federation_entity"]["probe"] = (
            {"nested": "object"} if issuer in invalid_issuers else "good"
        )
        record["metadata_policy"]["federation_entity"]["probe"] = {operator: "good"}
        federation[issuer].server.policy[POLICY_SUBJECT] = record
        fetch = federation[issuer].get_endpoint("fetch")
        token = fetch.process_request(fetch.parse_request({"sub": POLICY_SUBJECT}))["response_msg"]
        verified = verify_federation_jwt(
            profile=SUBORDINATE_STATEMENT, token=token, key_jar=federation[issuer].keyjar,
        )
        original = deep_freeze(factory(token).jwt.payload())
        assert verified.claims() == original
        verified_statements.append((verified, original, token))

    sources = [federation[issuer].server.policy for issuer in
               (TA_ID, POLICY_IE_BAD, POLICY_IE_GOOD)]
    before_sources = deepcopy(sources)
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
                assert result == {
                    "error": "invalid_metadata",
                    "error_description": "Resolve metadata policy rejected all candidate chains.",
                    "response_code": 400,
                }
                with Flask(__name__).test_request_context("/resolve"):
                    response = example_do_response(endpoint, query, **result)
                assert response.status_code == 400
                assert response.mimetype == "application/json"
                assert response.get_json()["error"] == "invalid_metadata"
            else:
                token = result["response_args"]
                accepted = verify_federation_jwt(
                    profile=RESOLVE_RESPONSE, token=token, key_jar=federation[TA_ID].keyjar,
                )
                assert accepted.claims()["metadata"] == deep_freeze({"federation_entity": {
                    "organization_name": "Verified subject name", "probe": "good",
                    "homepage_uri": POLICY_SUBJECT + "/", "contacts": ["ops@subject.example.org"],
                }})
                assert accepted.claims()["sub"] == POLICY_SUBJECT
                chain = accepted.claims()["trust_chain"]
                assert len(chain) == 3
                assert factory(chain[1]).jwt.payload()["iss"] == POLICY_IE_GOOD
                envelope = do_response(endpoint, **result)
                assert envelope["response"] == token
                assert ("Content-type", RESOLVE_RESPONSE.content_type) in envelope["http_headers"]
            assert sources == before_sources
            for verified, original, token in verified_statements:
                assert verified.claims() == original
                assert verified.raw_token() == token

    assert len(observed) == 2
    for candidates, original in observed:
        assert len(candidates) == 2
        assert [candidate.verified_chain for candidate in candidates] == original
        rejected = [candidate for candidate in candidates if "metadata_policy" in candidate.err]
        assert len(rejected) == len(invalid_issuers)
        assert all(candidate.metadata == candidate.combined_policy == {} for candidate in rejected)
        assert all(candidate.err["metadata_policy"]["error"] == "invalid_metadata"
                   for candidate in rejected)
    if all_invalid:
        signer.assert_not_called()
    else:
        assert signer.call_count == 2


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("position", ["initial", "copied"])
def test_resolve_complete_policy_validation(policy_federation, monkeypatch, reverse, position):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        federation[TA_ID].server.policy[issuer]["metadata_policy"] = {"federation_entity": {
            "organization_name": {"value": "Verified subject name"},
            "contacts": {"value": ["ops@subject.example.org"]},
        }}
        federation[issuer].server.policy[POLICY_SUBJECT]["metadata_policy"]["federation_entity"]["contacts"] = {
            "add": ["ops@subject.example.org"],
        }
    invalid = (federation[TA_ID].server.policy[POLICY_IE_BAD] if position == "initial"
               else federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT])
    invalid["metadata_policy"]["federation_entity"]["logo_uri"] = {
        "one_of": ["https://logo.example.org"], "subset_of": ["https://logo.example.org"],
    }
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        assert_policy_success(federation, POLICY_SUBJECT, endpoint.process_request(query))
    candidates, before = observed[0]
    assert [c.verified_chain for c in candidates] == before
    rejected = [c for c in candidates if "metadata_policy" in c.err]
    assert len(rejected) == 1
    assert rejected[0].err["metadata_policy"]["error"] == "invalid_metadata"
    assert rejected[0].metadata == rejected[0].combined_policy == {}
    accepted = [c for c in candidates if c not in rejected]
    assert len(accepted) == 1
    assert accepted[0].combined_policy["federation_entity"]["metadata_policy"] == {
        "organization_name": {"value": "Verified subject name", "one_of": ["Verified subject name"]},
        "contacts": {"value": ["ops@subject.example.org"], "add": ["ops@subject.example.org"]},
    }


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("all_invalid", [False, True])
def test_resolve_unselected_policy_conflict_is_candidate_local(
        policy_federation, monkeypatch, reverse, all_invalid):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT] = deepcopy(
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
    invalid_issuers = ((POLICY_IE_BAD, POLICY_IE_GOOD) if all_invalid
                       else (POLICY_IE_BAD,))
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        federation[TA_ID].server.policy[issuer]["metadata_policy"] = {
            "oauth_client": {"client_name": {"value": "upper"}},
        }
        federation[issuer].server.policy[POLICY_SUBJECT]["metadata_policy"][
            "oauth_client"
        ] = {"client_name": {
            "value": "lower" if issuer in invalid_issuers else "upper",
        }}
    sources = [federation[issuer].server.policy for issuer in
               (TA_ID, POLICY_IE_BAD, POLICY_IE_GOOD)]
    before_sources = deepcopy(sources)
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
                assert result == {
                    "error": "invalid_metadata",
                    "error_description": "Resolve metadata policy rejected all candidate chains.",
                    "response_code": 400,
                }
                envelope = do_response(endpoint, **result)
                assert json.loads(envelope["response"]) == {
                    "error": "invalid_metadata",
                    "error_description": result["error_description"],
                }
                assert ("Content-type", "application/json") in envelope["http_headers"]
            else:
                token = assert_policy_success(federation, POLICY_SUBJECT, result)
                verified = verify_federation_jwt(
                    profile=RESOLVE_RESPONSE, token=token, key_jar=federation[TA_ID].keyjar)
                assert set(verified.claims()["metadata"]) == {"federation_entity"}
    assert sources == before_sources
    assert len(observed) == 2
    for candidates, original in observed:
        assert [candidate.verified_chain for candidate in candidates] == original
        rejected = [candidate for candidate in candidates if "metadata_policy" in candidate.err]
        assert len(rejected) == len(invalid_issuers)
        assert all(candidate.metadata == candidate.combined_policy == {}
                   for candidate in rejected)
        accepted = [candidate for candidate in candidates if candidate not in rejected]
        assert len(accepted) == (0 if all_invalid else 1)
        if accepted:
            assert accepted[0].verified_chain[-2]["iss"] == POLICY_IE_GOOD
            assert set(accepted[0].metadata) == {"federation_entity"}
            assert "oauth_client" in accepted[0].combined_policy
    if all_invalid:
        signer.assert_not_called()
    else:
        assert signer.call_count == 2


@pytest.mark.parametrize("reverse", [False, True])
def test_resolve_malformed_signed_policy_candidate_is_isolated(
        policy_federation, monkeypatch, reverse):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT] = deepcopy(
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
    bad_policy = federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT]
    bad_policy["metadata_policy"]["federation_entity"]["organization_name"] = {
        "add": "not-an-array", "essential": False,
    }
    sources = [federation[issuer].server.policy for issuer in
               (TA_ID, POLICY_IE_BAD, POLICY_IE_GOOD)]
    before_sources = deepcopy(sources)
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        assert_policy_success(federation, POLICY_SUBJECT, endpoint.process_request(query))
    assert sources == before_sources
    assert len(observed) == 1
    candidates, original = observed[0]
    assert [candidate.verified_chain for candidate in candidates] == original
    assert len(candidates) == 1
    assert candidates[0].verified_chain[-2]["iss"] == POLICY_IE_GOOD


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("all_invalid", [False, True])
def test_resolve_duplicate_signed_policy_is_candidate_local(
        policy_federation, monkeypatch, reverse, all_invalid):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    invalid_issuers = (POLICY_IE_BAD, POLICY_IE_GOOD) if all_invalid else (POLICY_IE_BAD,)
    for issuer_id in invalid_issuers:
        issuer = federation[issuer_id]
        issuer.server.policy[POLICY_SUBJECT] = deepcopy(
            federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
        fetch = issuer.get_endpoint("fetch")

        def duplicate_response(*args, _original=fetch.process_request, _issuer=issuer, **kwargs):
            response = _original(*args, **kwargs)
            parsed = factory(response["response_msg"])
            payload = parsed.jwt.payload()
            payload.pop("metadata_policy", None)
            source = (json.dumps(payload)[:-1] + ''', "metadata_policy": {
                "federation_entity": {"organization_name": {
                    "value": "Conflicting value", "value": "Verified subject name"
                }} }}''').encode("utf-8")
            headers = parsed.jwt.headers
            keys = _issuer.keyjar.get_signing_key(issuer_id=_issuer.entity_id, kid=headers["kid"])
            token = JWS(source, alg=headers["alg"]).sign_compact(keys, protected=headers)
            assert factory(token).jwt.part[1] == source
            response["response_msg"] = token
            return response

        monkeypatch.setattr(fetch, "process_request", duplicate_response)

    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    signer = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        result = endpoint.process_request(query)
        if all_invalid:
            assert result == {
                "error": "invalid_trust_chain",
                "error_description": "Resolve found no acceptable chain for the requested trust anchor.",
                "response_code": 400,
            }
            signer.assert_not_called()
        else:
            assert_policy_success(federation, POLICY_SUBJECT, result)
            signer.assert_called_once()
    assert len(observed) == 1
    candidates, before = observed[0]
    assert [candidate.verified_chain for candidate in candidates] == before
    assert len(candidates) == (0 if all_invalid else 1)
    if candidates:
        assert candidates[0].verified_chain[-2]["iss"] == POLICY_IE_GOOD


@pytest.mark.parametrize("reverse", [False, True])
def test_resolve_boolean_number_policy_conflict_is_candidate_local(
        policy_federation, monkeypatch, reverse):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT] = deepcopy(
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        federation[TA_ID].server.policy[issuer]["metadata_policy"] = {
            "federation_entity": {"extension_flag": {"value": False}},
        }
        rule = federation[issuer].server.policy[POLICY_SUBJECT]["metadata_policy"]
        rule["federation_entity"]["extension_flag"] = {
            "value": 0 if issuer == POLICY_IE_BAD else False,
        }
    sources = [federation[issuer].server.policy for issuer in
               (TA_ID, POLICY_IE_BAD, POLICY_IE_GOOD)]
    before_sources = deepcopy(sources)
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            result = endpoint.process_request(query)
            verified = verify_federation_jwt(
                profile=RESOLVE_RESPONSE,
                token=result["response_args"],
                key_jar=federation[TA_ID].keyjar,
            )
            assert verified.claims()["metadata"]["federation_entity"][
                "extension_flag"
            ] is False
            assert factory(verified.claims()["trust_chain"][1]).jwt.payload()[
                "iss"
            ] == POLICY_IE_GOOD
    assert sources == before_sources
    assert len(observed) == 2
    for candidates, original in observed:
        assert [candidate.verified_chain for candidate in candidates] == original
        rejected = [candidate for candidate in candidates if "metadata_policy" in candidate.err]
        assert len(rejected) == 1
        assert rejected[0].verified_chain[-2]["iss"] == POLICY_IE_BAD
        assert rejected[0].err["metadata_policy"]["error"] == "invalid_metadata"
        assert rejected[0].metadata == rejected[0].combined_policy == {}
        accepted = [candidate for candidate in candidates if candidate not in rejected]
        assert len(accepted) == 1
        assert accepted[0].verified_chain[-2]["iss"] == POLICY_IE_GOOD
        assert accepted[0].metadata["federation_entity"]["extension_flag"] is False


@pytest.mark.parametrize("reverse", [False, True])
def test_resolve_structured_value_policy_failure_is_candidate_local(
        policy_federation, monkeypatch, reverse):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT] = deepcopy(
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        federation[TA_ID].server.policy[issuer]["metadata_policy"] = {
            "federation_entity": {
                "extension_data": {"value": [{"name": "structured"}]},
            },
        }
    bad_rule = federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT][
        "metadata_policy"
    ]["federation_entity"]
    bad_rule["extension_data"] = {"subset_of": ["structured"]}
    sources = [federation[issuer].server.policy for issuer in
               (TA_ID, POLICY_IE_BAD, POLICY_IE_GOOD)]
    before_sources = deepcopy(sources)
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            result = endpoint.process_request(query)
            verified = verify_federation_jwt(
                profile=RESOLVE_RESPONSE,
                token=result["response_args"],
                key_jar=federation[TA_ID].keyjar,
            )
            extension = verified.claims()["metadata"]["federation_entity"][
                "extension_data"
            ]
            assert isinstance(extension, tuple)
            assert len(extension) == 1
            assert dict(extension[0]) == {"name": "structured"}
            assert factory(verified.claims()["trust_chain"][1]).jwt.payload()[
                "iss"
            ] == POLICY_IE_GOOD
    assert sources == before_sources
    assert len(observed) == 2
    for candidates, original in observed:
        assert [candidate.verified_chain for candidate in candidates] == original
        rejected = [candidate for candidate in candidates if "metadata_policy" in candidate.err]
        assert len(rejected) == 1
        assert rejected[0].verified_chain[-2]["iss"] == POLICY_IE_BAD
        assert rejected[0].err["metadata_policy"]["error"] == "invalid_metadata"
        assert rejected[0].metadata == rejected[0].combined_policy == {}
        accepted = [candidate for candidate in candidates if candidate not in rejected]
        assert len(accepted) == 1
        assert accepted[0].verified_chain[-2]["iss"] == POLICY_IE_GOOD
        assert accepted[0].metadata["federation_entity"]["extension_data"] == [
            {"name": "structured"},
        ]


@pytest.mark.parametrize("reverse", [False, True])
def test_resolve_superset_union_and_candidate_isolation(policy_federation, monkeypatch, reverse):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    contacts = ["ops@subject.example.org", "security@subject.example.org"]
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        federation[TA_ID].server.policy[issuer]["metadata_policy"] = {
            "federation_entity": {"contacts": {"superset_of": contacts[:1]}},
        }
        policy = federation[issuer].server.policy[POLICY_SUBJECT]
        policy["metadata"]["federation_entity"] = {
            "organization_name": "Verified subject name",
            "contacts": contacts[:1] if issuer == POLICY_IE_BAD else contacts[:],
        }
        policy["metadata_policy"]["federation_entity"]["contacts"] = {
            "superset_of": contacts[1:],
        }
    expected = {"federation_entity": {
        "organization_name": "Verified subject name", "homepage_uri": POLICY_SUBJECT + "/",
        "contacts": tuple(contacts),
    }}
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            result = endpoint.process_request(query)
            verified = verify_federation_jwt(profile=RESOLVE_RESPONSE,
                token=result["response_args"], key_jar=federation[TA_ID].keyjar)
            assert verified.claims()["metadata"] == expected
            assert factory(verified.claims()["trust_chain"][1]).jwt.payload()["iss"] == POLICY_IE_GOOD
    for candidates, before in observed:
        assert [c.verified_chain for c in candidates] == before
        rejected = [c for c in candidates if "metadata_policy" in c.err]
        assert len(rejected) == 1
        assert rejected[0].err["metadata_policy"]["error"] == "invalid_metadata"
        assert rejected[0].metadata == rejected[0].combined_policy == {}


@pytest.mark.parametrize("reverse", [False, True])
def test_resolve_essential_or_and_candidate_isolation(policy_federation, monkeypatch, reverse):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        federation[TA_ID].server.policy[issuer]["metadata_policy"] = {
            "federation_entity": {
                "organization_name": {"essential": True},
                "logo_uri": {"essential": True},
            },
        }
        policy = federation[issuer].server.policy[POLICY_SUBJECT]
        policy["metadata"]["federation_entity"]["organization_name"] = "Verified subject name"
        policy["metadata_policy"]["federation_entity"] = {
            "organization_name": {"value": "Verified subject name", "essential": False},
            "logo_uri": {"essential": False},
        }
        if issuer == POLICY_IE_GOOD:
            policy["metadata_policy"]["federation_entity"]["logo_uri"]["default"] = POLICY_SUBJECT + "/logo"
    sources = [federation[issuer].server.policy for issuer in (TA_ID, POLICY_IE_BAD, POLICY_IE_GOOD)]
    before_sources = deepcopy(sources)
    expected = {"federation_entity": {
        "organization_name": "Verified subject name", "homepage_uri": POLICY_SUBJECT + "/",
        "contacts": ("ops@subject.example.org",), "logo_uri": POLICY_SUBJECT + "/logo",
    }}
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        for _ in range(2):
            result = endpoint.process_request(query)
            verified = verify_federation_jwt(profile=RESOLVE_RESPONSE,
                token=result["response_args"], key_jar=federation[TA_ID].keyjar)
            assert verified.claims()["metadata"] == expected
            assert factory(verified.claims()["trust_chain"][1]).jwt.payload()["iss"] == POLICY_IE_GOOD
    assert sources == before_sources
    for candidates, before in observed:
        assert [c.verified_chain for c in candidates] == before
        rejected = [c for c in candidates if "metadata_policy" in c.err]
        assert len(rejected) == 1
        assert rejected[0].err["metadata_policy"]["error"] == "invalid_metadata"
        assert rejected[0].metadata == rejected[0].combined_policy == {}


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


def test_resolve_preserves_empty_contacts_through_signed_client_path(policy_federation):
    federation = policy_federation
    policy = federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT]
    policy["metadata_policy"]["federation_entity"]["contacts"] = {
        "subset_of": [], "essential": True,
    }
    before = deepcopy(policy)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        result = endpoint.process_request(query)
    token = result["response_args"]
    wire_payload = factory(token).jwt.payload()
    wire_metadata = wire_payload["metadata"]["federation_entity"]
    assert "contacts" in wire_metadata
    assert wire_metadata["contacts"] == []

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE, token=token, key_jar=federation[TA_ID].keyjar)
    authoritative = verified.claims()["metadata"]["federation_entity"]
    assert "contacts" in authoritative
    assert authoritative["contacts"] == ()
    assert verified.message().to_dict()["metadata"]["federation_entity"]["contacts"] == []

    envelope = do_response(endpoint, **result)
    response = Response()
    response.status_code = 200
    response._content = envelope["response"].encode("utf-8")
    response.headers.update(dict(envelope["http_headers"]))
    response.url = endpoint.full_path
    service = federation[POLICY_SUBJECT].client.get_service("resolve")
    parsed = federation[POLICY_SUBJECT].client.parse_request_response(
        service, response, response_body_type=service.response_body_type,
        expected_resolver=TA_ID, expected_subject=POLICY_SUBJECT,
        expected_trust_anchors=(TA_ID,), expected_audience=POLICY_SUBJECT)
    client_metadata = parsed.to_dict()["metadata"]["federation_entity"]
    assert "contacts" in client_metadata
    assert client_metadata["contacts"] == []
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
                service, response, response_body_type=service.response_body_type,
                expected_resolver=TA_ID, expected_subject=POLICY_SUBJECT,
                expected_trust_anchors=(TA_ID,), expected_audience=POLICY_SUBJECT)
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


@pytest.mark.parametrize("reverse", [False, True])
def test_resolve_malformed_signed_constraint_candidate_is_isolated(
        policy_federation, monkeypatch, reverse):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    federation[POLICY_IE_BAD].server.policy[POLICY_SUBJECT] = deepcopy(
        federation[POLICY_IE_GOOD].server.policy[POLICY_SUBJECT])
    federation[TA_ID].server.policy[POLICY_IE_BAD]["constraints"] = {
        "naming_constraints": {"permitted": ".example.org"},
        "max_path_length": 1,
    }
    sources = [federation[issuer].server.policy for issuer in
               (TA_ID, POLICY_IE_BAD, POLICY_IE_GOOD)]
    before_sources = deepcopy(sources)
    observed = observe_verified_candidates(monkeypatch)
    endpoint = federation[TA_ID].get_endpoint("resolve")
    query = endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        assert_policy_success(federation, POLICY_SUBJECT, endpoint.process_request(query))
    assert sources == before_sources
    assert len(observed) == 1
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


@pytest.mark.parametrize("query", [
    {"sub": "http://subject.example.org", "trust_anchor": [TA_ID]},
    {"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID, "https://ta.example.org#fragment"]},
    {"sub": [POLICY_SUBJECT, POLICY_SUBJECT], "trust_anchor": [TA_ID]},
    {"sub": True, "trust_anchor": [TA_ID]},
    {"sub": POLICY_SUBJECT, "trust_anchor": None},
    "sub=&sub=https%3A%2F%2Fsubject.example.org&trust_anchor=https%3A%2F%2Fta.example.org",
    "sub=https%3A%2F%2Fsubject.example.org&sub=&trust_anchor=https%3A%2F%2Fta.example.org",
    "sub=https%3A%2F%2Fsubject.example.org&sub=https%3A%2F%2Fsubject.example.org&trust_anchor=https%3A%2F%2Fta.example.org",
    "sub=https%3A%2F%2Fsubject.example.org&trust_anchor=&trust_anchor=https%3A%2F%2Fta.example.org",
    "sub=https%3A%2F%2Fsubject.example.org&trust_anchor=https%3A%2F%2Fta.example.org&trust_anchor=",
])
def test_resolve_admission_stops_invalid_input(policy_federation, monkeypatch, query):
    spies = []
    for name in ("collect_trust_chains", "verify_trust_chains", "apply_policies", "create_resolve_response"):
        spy = Mock(side_effect=AssertionError("invalid input reached " + name))
        spies.append(spy)
        monkeypatch.setattr(resolve_module, name, spy)
    endpoint = policy_federation[TA_ID].get_endpoint("resolve")
    parsed = endpoint.parse_request(query)
    assert parsed["error"] == "invalid_request"
    for spy in spies:
        spy.assert_not_called()


def test_resolve_request_subtype_and_unknown_anchor_are_preserved(policy_federation):
    calls = []

    class LocalRequest(ResolveRequest):
        def verify(self, **kwargs):
            calls.append(self["sub"])
            return super().verify(**kwargs)

    endpoint = policy_federation[TA_ID].get_endpoint("resolve")
    endpoint.request_cls = LocalRequest
    query = urlencode({"sub": POLICY_SUBJECT, "trust_anchor": ["https://unknown.example.org"],
                       "entity_type": ["custom", "federation_entity"]}, doseq=True)
    parsed = endpoint.parse_request(query)
    assert isinstance(parsed, LocalRequest)
    assert calls == [POLICY_SUBJECT]
    assert parsed["entity_type"] == ["custom", "federation_entity"]
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, policy_federation, POLICY_SUBJECT)
        result = endpoint.process_request(parsed)
    assert result["error"] == "invalid_trust_chain"


def test_resolve_does_not_map_post_parse_runtime_failure(policy_federation, monkeypatch):
    endpoint = policy_federation[TA_ID].get_endpoint("resolve")
    failure = ValueError("unrelated post-parse failure")
    monkeypatch.setattr(endpoint, "do_post_parse_request", Mock(side_effect=failure))
    with pytest.raises(ValueError) as error:
        endpoint.parse_request(ResolveRequest(sub=POLICY_SUBJECT, trust_anchor=[TA_ID]))
    assert error.value is failure


@pytest.mark.parametrize("multiple", [False, True])
def test_resolve_client_repeated_query_wire_format(policy_federation, multiple):
    service = policy_federation[POLICY_SUBJECT].get_service("resolve")
    anchors = [POLICY_OTHER_TA, TA_ID] if multiple else TA_ID
    types = ["federation_entity", "openid_provider"] if multiple else "federation_entity"
    args = {"sub": POLICY_SUBJECT, "trust_anchor": anchors, "entity_type": types}
    before = deepcopy(args)
    result = service.get_request_parameters(request_args=args, endpoint=TA_ID + "/resolve", entity_id=TA_ID)
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
    }, endpoint="/resolve", entity_id=TA_ID)["url"]
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        client = app.test_client()
        for accept in (None, "application/json", "invalid, ; header"):
            headers = {} if accept is None else {"Accept": accept}
            response = client.get(url, headers=headers)
            assert response.status_code == 200
            assert response.mimetype == RESOLVE_RESPONSE.content_type
            assert_policy_success(federation, POLICY_SUBJECT,
                                  {"response_args": response.get_data(as_text=True)})
            count = process.call_count
            rejected = client.get("/resolve?sub=&sub=" + POLICY_SUBJECT + "&trust_anchor=" + TA_ID,
                                  headers=headers)
            assert rejected.status_code == 400
            assert rejected.mimetype == "application/json"
            assert rejected.get_json()["error"] == "invalid_request"
            assert process.call_count == count
        response = client.get(url)
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
    clock = {"now": utc_time_sans_frac()}
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
    subject = federation[POLICY_SUBJECT]
    intermediate = federation[POLICY_IE_GOOD]
    anchor = federation[TA_ID]
    statements = create_trust_chain_messages(subject, intermediate, anchor)
    chain = [statements[subject.get_endpoint("entity_configuration").full_path],
             statements[intermediate.get_endpoint("fetch").full_path],
             statements[anchor.get_endpoint("fetch").full_path],
             statements[anchor.get_endpoint("entity_configuration").full_path]]
    token = create_resolve_response(
        TA_ID, sub=POLICY_SUBJECT, key_jar=federation[TA_ID].keyjar,
        metadata=resolve_metadata(), trust_chain=chain, expires_at=expiration,
    )
    client = federation[POLICY_SUBJECT].client
    request_args = {"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]}
    url = TA_ID + "/resolve"
    with responses.RequestsMock() as rsps:
        rsps.add("GET", url, body=token, status=200, content_type=RESOLVE_RESPONSE.content_type)
        monkeypatch.setattr("cryptojwt.jwt.utc_time_sans_frac", lambda: now)
        parsed = client.do_request("resolve", request_args=request_args, endpoint=url, entity_id=TA_ID)
        assert isinstance(parsed, ResolveResponse)
        assert parsed["exp"] == expiration
        verification_expiration = expiration + JWT().skew
        for timestamp in (verification_expiration, verification_expiration + 1):
            monkeypatch.setattr("cryptojwt.jwt.utc_time_sans_frac", lambda: timestamp)
            with pytest.raises(FederationJwtPayloadError):
                client.do_request("resolve", request_args=request_args, endpoint=url, entity_id=TA_ID)
        assert len(rsps.calls) == 3


INITIAL_EC_PEER_DETAIL = "synthetic-private-peer-detail"


@pytest.fixture(params=[
    ("not_found", MissingPage, "not_found", 404),
    ("unavailable", FailedConfigurationRetrieval, "server_error", 502),
    ("connection", ConnectionError, "server_error", 502),
    ("timeout", Timeout, "server_error", 504),
    ("read_timeout", ReadTimeout, "server_error", 504),
    ("connect_timeout", ConnectTimeout, "server_error", 504),
    ("missing_media_type", WrongContentType, "server_error", 502),
    ("wrong_media_type", WrongContentType, "server_error", 502),
], ids=lambda case: case[0])
def initial_ec_failure(request):
    return request.param


def _initial_ec_urls(federation, subject):
    service = federation[TA_ID].get_service("entity_configuration")
    return tuple(service.get_request_parameters(
        request_args={"entity_id": subject}, tenant=tenant)["url"]
        for tenant in (False, True))


def _register_initial_ec_failure(rsps, url, kind, token=""):
    exceptions = {"connection": ConnectionError, "timeout": Timeout,
                  "read_timeout": ReadTimeout, "connect_timeout": ConnectTimeout}
    if kind in exceptions:
        rsps.add("GET", url, body=exceptions[kind](INITIAL_EC_PEER_DETAIL))
    elif kind in ("missing_media_type", "wrong_media_type"):
        content_type = None if kind == "missing_media_type" else "application/json"
        rsps.add("GET", url, body=token, status=200, content_type=content_type)
    else:
        rsps.add("GET", url, status=404 if kind == "not_found" else 503,
                 json={"error": "temporarily_unavailable",
                       "error_description": INITIAL_EC_PEER_DETAIL},
                 headers={"X-Peer-Detail": INITIAL_EC_PEER_DETAIL, "Retry-After": "7777"})


def _initial_ec_client(federation, module="edu_federation"):
    app = Flask(__name__)
    app.federation_entity = federation[TA_ID]
    app.register_blueprint(import_module(module + ".trust_anchor.views").entity)
    return app.test_client()


def _assert_initial_ec_error(response, error, status):
    body = json.loads(response.get_data(as_text=True))
    observed = (response.status_code, response.mimetype, body)
    assert response.status_code == status, observed
    assert response.mimetype == "application/json", observed
    assert set(body) == {"error", "error_description"}
    assert body["error"] == error
    assert isinstance(body["error_description"], str) and body["error_description"]
    assert INITIAL_EC_PEER_DETAIL not in response.get_data(as_text=True)
    assert "X-Peer-Detail" not in response.headers
    assert "Retry-After" not in response.headers
    return body


def _assert_initial_ec_success(federation, subject, response):
    assert response.status_code == 200
    assert response.mimetype == RESOLVE_RESPONSE.content_type
    token = assert_policy_success(federation, subject,
                                  {"response_args": response.get_data(as_text=True)})
    # assert_policy_success verifies this exact outer token and its metadata.
    chain = factory(token).jwt.payload()["trust_chain"]
    assert factory(chain[-1]).jwt.payload()["iss"] == TA_ID


@pytest.mark.parametrize("module", ["dc4eu_federation", "edu_federation", "setup_federation"])
def test_resolve_initial_ec_failure_routes(policy_federation, monkeypatch, initial_ec_failure, module):
    federation = policy_federation
    kind, _, error, status = initial_ec_failure
    url, fallback = _initial_ec_urls(federation, POLICY_SUBJECT)
    assert url == fallback
    token = federation[POLICY_SUBJECT].get_endpoint("entity_configuration").process_request({})[
        "response"]
    signer = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    client = _initial_ec_client(federation, module)
    collector = federation[TA_ID].function.trust_chain_collector
    assert collector.config_cache.get(POLICY_SUBJECT) is None
    with responses.RequestsMock() as rsps:
        _register_initial_ec_failure(rsps, url, kind, token)
        response = client.get("/resolve", query_string={"sub": POLICY_SUBJECT, "trust_anchor": TA_ID})
        assert [call.request.url for call in rsps.calls] == [url]
    signer.assert_not_called()
    body = _assert_initial_ec_error(response, error, status)
    assert token not in json.dumps(body)
    assert url not in body["error_description"]
    assert collector.config_cache.get(POLICY_SUBJECT) is None


def test_resolve_initial_ec_operation_maps_but_collector_preserves_exceptions(
        policy_federation, monkeypatch, initial_ec_failure):
    federation = policy_federation
    kind, exception, error, status = initial_ec_failure
    ta = federation[TA_ID]
    endpoint = ta.get_endpoint("resolve")
    url, _ = _initial_ec_urls(federation, POLICY_SUBJECT)
    token = federation[POLICY_SUBJECT].get_endpoint("entity_configuration").process_request({})[
        "response"]
    signer = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    with responses.RequestsMock() as rsps:
        _register_initial_ec_failure(rsps, url, kind, token)
        with pytest.raises(exception) as failure:
            ta.function.trust_chain_collector(POLICY_SUBJECT, stop_at=TA_ID)
        assert type(failure.value) is exception
        assert [call.request.url for call in rsps.calls] == [url]
        assert ta.function.trust_chain_collector.config_cache.get(POLICY_SUBJECT) is None
        result = endpoint.process_request(endpoint.parse_request(
            {"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]}))
        assert [call.request.url for call in rsps.calls] == [url, url]
    assert set(result) == {"error", "error_description", "response_code"}
    assert result["error"] == error
    assert result["response_code"] == status
    assert isinstance(result["error_description"], str) and result["error_description"]
    assert INITIAL_EC_PEER_DETAIL not in result["error_description"]
    assert url not in result["error_description"]
    signer.assert_not_called()


def test_resolve_initial_ec_valid_signed_control(policy_federation):
    client = _initial_ec_client(policy_federation)
    url, _ = _initial_ec_urls(policy_federation, POLICY_SUBJECT)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, policy_federation, POLICY_SUBJECT)
        response = client.get("/resolve", query_string={"sub": POLICY_SUBJECT, "trust_anchor": TA_ID})
        assert rsps.calls[0].request.url == url
    _assert_initial_ec_success(policy_federation, POLICY_SUBJECT, response)


@pytest.mark.parametrize("outcome", ["success", "not_found", "read_timeout"])
def test_resolve_initial_ec_tenant_fallback(policy_federation, monkeypatch, outcome):
    federation = policy_federation
    subject = POLICY_SUBJECT + "/tenant"
    leaf = make_entity(subject, "federation_entity",
                       authority_hints=[POLICY_IE_GOOD], endpoints=["entity_configuration"],
                       services=["entity_configuration", "entity_statement", "resolve"],
                       preference={"organization_name": "Subject name", "homepage_uri": subject + "/",
                                   "contacts": ["ops@subject.example.org"]})
    leaf.add_trust_anchor(TA_ID, federation[TA_ID].keyjar.export_jwks())
    federation[subject] = leaf
    for issuer in (POLICY_IE_BAD, POLICY_IE_GOOD):
        federation[issuer].server.subordinate[subject] = {"jwks": leaf.keyjar.export_jwks()}
        federation[issuer].server.policy[subject] = deepcopy(
            federation[issuer].server.policy[POLICY_SUBJECT])
    url, fallback = _initial_ec_urls(federation, subject)
    assert url != fallback
    assert fallback == leaf.get_endpoint("entity_configuration").full_path
    client = _initial_ec_client(federation)
    signer = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, subject)
        _register_initial_ec_failure(rsps, url, "not_found")
        if outcome != "success":
            for response in tuple(rsps.registered()):
                if response.url == fallback:
                    rsps.remove(response)
            _register_initial_ec_failure(rsps, fallback, outcome)
        response = client.get("/resolve", query_string={"sub": subject, "trust_anchor": TA_ID})
        assert [call.request.url for call in rsps.calls[:2]] == [url, fallback]
        if outcome != "success":
            assert len(rsps.calls) == 2
    if outcome == "success":
        _assert_initial_ec_success(federation, subject, response)
        signer.assert_called_once()
    else:
        signer.assert_not_called()
        _assert_initial_ec_error(response, "not_found" if outcome == "not_found" else "server_error",
                                 404 if outcome == "not_found" else 504)


def test_resolve_initial_ec_success_failure_success(policy_federation, monkeypatch):
    federation = policy_federation
    ta = federation[TA_ID]
    client = _initial_ec_client(federation)
    query = {"sub": POLICY_SUBJECT, "trust_anchor": TA_ID}
    url, _ = _initial_ec_urls(federation, POLICY_SUBJECT)
    signer = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    for index, fail in enumerate((False, True, False)):
        if index:
            # Only evict this subject's EC; retain independent branch caches.
            ta.function.trust_chain_collector.config_cache._db.pop(POLICY_SUBJECT, None)
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            if fail:
                _register_initial_ec_failure(rsps, url, "unavailable")
            else:
                register_policy_paths(rsps, federation, POLICY_SUBJECT)
            response = client.get("/resolve", query_string=query)
            assert rsps.calls[0].request.url == url
            if fail:
                assert len(rsps.calls) == 1
        assert signer.call_count == (2 if index == 2 else 1)
        if fail:
            _assert_initial_ec_error(response, "server_error", 502)
        else:
            _assert_initial_ec_success(federation, POLICY_SUBJECT, response)
    assert ta.get_endpoint("resolve").response_content_type == RESOLVE_RESPONSE.content_type


@pytest.mark.parametrize("reverse,all_unavailable", [(False, False), (True, False), (False, True)])
def test_resolve_initial_ec_authority_failure_is_branch_local(
        policy_federation, monkeypatch, reverse, all_unavailable):
    federation = policy_federation
    if reverse:
        federation[POLICY_SUBJECT].context.authority_hints.reverse()
    client = _initial_ec_client(federation)
    url, _ = _initial_ec_urls(federation, POLICY_SUBJECT)
    unavailable = [POLICY_IE_BAD, POLICY_IE_GOOD] if all_unavailable else [POLICY_IE_BAD]
    signer = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        register_policy_paths(rsps, federation, POLICY_SUBJECT)
        failed_urls = []
        for issuer in unavailable:
            issuer_url, _ = _initial_ec_urls(federation, issuer)
            failed_urls.append(issuer_url)
            for response in tuple(rsps.registered()):
                if response.url == issuer_url:
                    rsps.remove(response)
            _register_initial_ec_failure(rsps, issuer_url, "unavailable")
        response = client.get("/resolve", query_string={"sub": POLICY_SUBJECT, "trust_anchor": TA_ID})
        called_urls = [call.request.url for call in rsps.calls]
        assert called_urls[0] == url
        assert all(failed_url in called_urls for failed_url in failed_urls)
    assert federation[TA_ID].function.trust_chain_collector.config_cache.get(POLICY_SUBJECT)
    if all_unavailable:
        _assert_initial_ec_error(response, "invalid_trust_chain", 400)
        signer.assert_not_called()
    else:
        _assert_initial_ec_success(federation, POLICY_SUBJECT, response)
        signer.assert_called_once()


def test_resolve_initial_ec_unrelated_collection_error_propagates(policy_federation, monkeypatch):
    endpoint = policy_federation[TA_ID].get_endpoint("resolve")
    failure = ValueError("unrelated collection failure")
    monkeypatch.setattr(resolve_module, "collect_trust_chains", Mock(side_effect=failure))
    signer = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", signer)
    with pytest.raises(ValueError) as error:
        endpoint.process_request(endpoint.parse_request({"sub": POLICY_SUBJECT, "trust_anchor": [TA_ID]}))
    assert error.value is failure
    signer.assert_not_called()


def _anchor_subject_resolver(anchors):
    return make_federation_entity(
        RESOLVER_ID, trust_anchors=anchors, endpoints=["entity_configuration", "resolve"],
    )


@pytest.fixture
def anchor_subject():
    """Issue a real root EC and construct a separate configured resolver."""
    anchor = make_entity(TA_ID, "trust_anchor")
    metadata = {
        "federation_entity": {
            "organization_name": "Root anchor",
            "contacts": ["ops@example.org"],
            "extension": {"nested": ["original"]},
        },
        "oauth_client": {},
    }
    ec = create_entity_configuration(TA_ID, anchor.keyjar, metadata=metadata)
    resolver = _anchor_subject_resolver({TA_ID: anchor.keyjar.export_jwks()})
    return {
        "anchor": anchor, "resolver": resolver, "metadata": metadata, "ec": ec,
        "url": anchor.get_endpoint("entity_configuration").full_path,
    }


def _register_anchor_subject(rsps, fixture, token=None):
    rsps.add("GET", fixture["url"], body=token or fixture["ec"],
             content_type=ENTITY_CONFIGURATION.content_type)


def _anchor_subject_request(resolver, subject=TA_ID, anchors=None, entity_types=None, **kwargs):
    endpoint = resolver.get_endpoint("resolve")
    request = {"sub": subject, "trust_anchor": anchors if anchors is not None else [subject]}
    if entity_types is not None:
        request["entity_type"] = entity_types
    return endpoint.process_request(endpoint.parse_request(request), **kwargs)


def _assert_anchor_subject_response(resolver, result, subject, metadata, chain, expiration):
    verified = verify_federation_jwt(RESOLVE_RESPONSE, result["response_args"], resolver.keyjar)
    assert verified.header()["typ"] == RESOLVE_RESPONSE.typ
    assert verified.header()["kid"] in {
        key.kid for key in resolver.keyjar.get_signing_key(issuer_id=RESOLVER_ID)
    }
    claims = verified.claims()
    assert claims["iss"] == RESOLVER_ID
    assert claims["sub"] == subject
    assert claims["metadata"] == deep_freeze(metadata)
    assert claims["trust_chain"] == tuple(chain)
    assert claims["exp"] == expiration
    return verified


@pytest.mark.parametrize("provider", ["mapping", "filesystem"])
def test_resolve_trust_anchor_subject_construction(anchor_subject, tmp_path, monkeypatch, provider):
    fixture = anchor_subject
    jwks = fixture["anchor"].keyjar.export_jwks()
    anchors = {TA_ID: jwks}
    if provider == "filesystem":
        kwargs = {"fdir": str(tmp_path / "anchors"), "value_conv": "idpyoidc.util.JSON"}
        store = AbstractFileSystem(**kwargs)
        store[TA_ID] = jwks
        anchors = {"class": "idpyoidc.storage.abfile.AbstractFileSystem", "kwargs": kwargs}
    resolver = _anchor_subject_resolver(anchors)
    assert resolver.keyjar.export_jwks(issuer_id=TA_ID) == jwks
    assert resolver.function.trust_chain_collector.trust_anchors[TA_ID] == jwks
    verifier = Mock(wraps=verifier_module.verify_federation_jwt)
    monkeypatch.setattr(verifier_module, "verify_federation_jwt", verifier)
    app = Flask(__name__)
    app.federation_entity = resolver
    app.register_blueprint(import_module("edu_federation.trust_anchor.views").entity)
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, fixture)
        response = app.test_client().get("/resolve", query_string={"sub": TA_ID, "trust_anchor": TA_ID})
    assert response.status_code == 200
    _assert_anchor_subject_response(
        resolver, {"response_args": response.get_data(as_text=True)}, TA_ID,
        fixture["metadata"], [fixture["ec"]], factory(fixture["ec"]).jwt.payload()["exp"],
    )
    verifier.assert_called_once()
    assert verifier.call_args.kwargs["key_jar"] is resolver.keyjar
    assert verifier.call_args.kwargs["token"] == fixture["ec"]


@pytest.mark.parametrize("with_ta_ec", [None, False, True])
def test_resolve_trust_anchor_subject_cache_reconstruction(anchor_subject, with_ta_ec):
    fixture = anchor_subject
    resolver = fixture["resolver"]
    collector = resolver.function.trust_chain_collector
    before = resolver.keyjar.export_jwks(issuer_id=TA_ID)
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, fixture)
        chains, ec = collect_trust_chains(resolver, TA_ID)
        assert chains == [] and ec == fixture["ec"]
        assert resolver.keyjar.export_jwks(issuer_id=TA_ID) == before
        verified = verify_trust_chains(resolver, [[]], ec)
        assert len(verified) == 1
        assert verified[0].iss_path == [TA_ID]
        assert verified[0].verified_chain[0]["sub"] == TA_ID
        kwargs = {} if with_ta_ec is None else {"with_ta_ec": with_ta_ec}
        assert collector.get_chain([TA_ID], TA_ID, **kwargs) == [ec]
        for _ in range(2):
            result = _anchor_subject_request(resolver, **kwargs)
            _assert_anchor_subject_response(
                resolver, result, TA_ID, fixture["metadata"], [ec],
                factory(ec).jwt.payload()["exp"],
            )
        assert len(rsps.calls) == 1


@pytest.mark.parametrize("entity_types", [
    None, ["oauth_client"], ["federation_entity", "oauth_client", "missing"],
])
def test_resolve_trust_anchor_subject_metadata_filter(anchor_subject, entity_types):
    fixture = anchor_subject
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, fixture)
        result = _anchor_subject_request(fixture["resolver"], entity_types=entity_types)
    expected = {typ: value for typ, value in fixture["metadata"].items()
                if entity_types is None or typ in entity_types}
    _assert_anchor_subject_response(
        fixture["resolver"], result, TA_ID, expected, [fixture["ec"]],
        factory(fixture["ec"]).jwt.payload()["exp"],
    )


@pytest.fixture
def nested_anchor_subject():
    """Keep both configured anchor suffixes available to the real verifier."""
    federation = build_federation({
        TA_ID: {"entity_type": "trust_anchor", "subordinates": [IM_ID], "kwargs": {}},
        IM_ID: {"entity_type": "intermediate", "subordinates": [SUBJECT_ID],
                "kwargs": {"authority_hints": [TA_ID]}},
        SUBJECT_ID: {"entity_type": "intermediate", "kwargs": {"authority_hints": [IM_ID]}},
    })
    # Distinct superior metadata makes selected-suffix mistakes observable.
    federation[TA_ID].server.policy[IM_ID] = {
        "metadata": {"federation_entity": {"organization_name": "Root describes inner"}},
    }
    resolver = _anchor_subject_resolver({
        identifier: federation[identifier].keyjar.export_jwks() for identifier in (TA_ID, IM_ID)
    })
    messages = create_trust_chain_messages(
        federation[SUBJECT_ID], federation[IM_ID], federation[TA_ID],
    )
    return federation, resolver, messages


@pytest.mark.parametrize("subject,anchors,expected_anchor", [
    (IM_ID, [IM_ID], IM_ID),
    (IM_ID, [TA_ID], TA_ID),
    (IM_ID, [TA_ID, IM_ID], IM_ID),
    (IM_ID, [IM_ID, TA_ID], IM_ID),
    (SUBJECT_ID, [IM_ID], IM_ID),
    (SUBJECT_ID, [TA_ID], TA_ID),
    (SUBJECT_ID, [TA_ID, IM_ID], IM_ID),
    (SUBJECT_ID, [IM_ID, TA_ID], IM_ID),
])
def test_resolve_trust_anchor_subject_nested_paths(
        nested_anchor_subject, monkeypatch, subject, anchors, expected_anchor):
    federation, resolver, messages = nested_anchor_subject
    observed = observe_verified_candidates(monkeypatch)
    collector = resolver.function.trust_chain_collector
    shared_before = resolver.keyjar.export_jwks(issuer_id=SUBJECT_ID)
    assert not shared_before["keys"]
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for url, token in messages.items():
            rsps.add("GET", url, body=token, content_type=ENTITY_CONFIGURATION.content_type)
        calls = None
        for with_ta_ec in (False, True):
            result = _anchor_subject_request(
                resolver, subject, anchors, with_ta_ec=with_ta_ec,
            )
            selected = next(c for c in observed[-1][0] if c.anchor in anchors)
            assert selected.anchor == expected_anchor
            path = [subject]
            if subject == SUBJECT_ID:
                path.append(IM_ID)
            if expected_anchor == TA_ID:
                path.append(TA_ID)
            assert selected.iss_path == path
            wire_chain = [messages[federation[subject].get_endpoint("entity_configuration").full_path]]
            wire_chain.extend(messages[federation[issuer].get_endpoint("fetch").full_path]
                              for issuer in path[1:])
            if with_ta_ec and len(path) > 1:
                wire_chain.append(messages[federation[expected_anchor].get_endpoint("entity_configuration").full_path])
            assert collector.get_chain(path, expected_anchor, with_ta_ec) == wire_chain
            expected_metadata = factory(wire_chain[0]).jwt.payload()["metadata"]
            if subject == IM_ID and expected_anchor == TA_ID:
                expected_metadata["federation_entity"]["organization_name"] = "Root describes inner"
            _assert_anchor_subject_response(
                resolver, result, subject, expected_metadata, wire_chain, selected.exp,
            )
            if len(anchors) == 2:
                assert [c.anchor for c in observed[-1][0]] == [IM_ID, TA_ID]
                assert len(selected.chain) > len(selected.verified_chain)
            if calls is None:
                calls = len(rsps.calls)
            else:
                assert calls == len(rsps.calls)
    if subject == SUBJECT_ID:
        assert resolver.keyjar.export_jwks(issuer_id=SUBJECT_ID) == federation[SUBJECT_ID].keyjar.export_jwks()


@pytest.mark.parametrize("keys_present", [False, True])
def test_resolve_trust_anchor_subject_unconfigured(anchor_subject, monkeypatch, keys_present):
    fixture = anchor_subject
    resolver = _anchor_subject_resolver({})
    if keys_present:
        resolver.keyjar.import_jwks(fixture["anchor"].keyjar.export_jwks(), TA_ID)
    before = resolver.keyjar.export_jwks(issuer_id=TA_ID)
    creator = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", creator)
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, fixture)
        result = _anchor_subject_request(resolver)
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    creator.assert_not_called()
    assert resolver.keyjar.export_jwks(issuer_id=TA_ID) == before
    assert TA_ID not in resolver.function.trust_chain_collector.trust_anchors


def test_resolve_trust_anchor_subject_unrequested(anchor_subject, monkeypatch):
    creator = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", creator)
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, anchor_subject)
        result = _anchor_subject_request(anchor_subject["resolver"], anchors=[IM_ID])
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    creator.assert_not_called()


@pytest.mark.parametrize("key_kind", ["matching", "wrong_material", "wrong_kid"])
def test_resolve_trust_anchor_subject_established_keys(anchor_subject, monkeypatch, key_kind):
    fixture = anchor_subject
    ec = fixture["ec"]
    jwks = fixture["anchor"].keyjar.export_jwks()
    if key_kind != "matching":
        kid = factory(ec).jwt.headers["kid"] if key_kind == "wrong_material" else "unconfigured-kid"
        jwks = {"keys": [new_rsa_key(kid=kid, use="sig").serialize(private=False)]}
    resolver = _anchor_subject_resolver({TA_ID: jwks})
    before = resolver.keyjar.export_jwks(issuer_id=TA_ID)
    # Bootstrap succeeds independently, but must not replace the established keys.
    assert verify_federation_jwt(ENTITY_CONFIGURATION, ec, fixture["anchor"].keyjar).raw_token() == ec
    creator = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", creator)
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, fixture)
        assert collect_trust_chains(resolver, TA_ID) == ([], ec)
        assert resolver.keyjar.export_jwks(issuer_id=TA_ID) == before
        if key_kind == "wrong_kid":
            with pytest.raises(FederationJwtKeyResolutionError):
                _anchor_subject_request(resolver)
        else:
            result = _anchor_subject_request(resolver)
            if key_kind == "wrong_material":
                with pytest.raises(FederationJwtSignatureError):
                    verify_federation_jwt(ENTITY_CONFIGURATION, ec, resolver.keyjar)
                assert result["error"] == "invalid_trust_chain"
            else:
                _assert_anchor_subject_response(
                    resolver, result, TA_ID, fixture["metadata"], [ec], factory(ec).jwt.payload()["exp"],
                )
    if key_kind != "matching":
        creator.assert_not_called()
        assert resolver.keyjar.export_jwks(issuer_id=TA_ID) == before


@pytest.mark.parametrize("kind,error_cls", [
    ("valid", None), ("signature", FederationJwtSignatureError),
    ("subject", WrongSubject), ("expired", FederationJwtPayloadError),
])
def test_resolve_trust_anchor_subject_invalid_ec(anchor_subject, monkeypatch, kind, error_cls):
    fixture = anchor_subject
    token = fixture["ec"]
    if kind == "signature":
        token = corrupt_signature(token)
    elif kind in ("subject", "expired"):
        payload = factory(token).jwt.payload()
        if kind == "subject":
            payload["sub"] = IM_ID
        else:
            payload.update(iat=utc_time_sans_frac() - 120, exp=utc_time_sans_frac() - 60)
        # Deliberately malformed signed input bypasses the production producer only here.
        token = JWS(json.dumps(payload), alg="RS256", typ=ENTITY_CONFIGURATION.typ).sign_compact(
            keys=fixture["anchor"].keyjar.get_signing_key("RSA"),
        )
    creator = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", creator)
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, fixture, token)
        if error_cls:
            with pytest.raises(error_cls):
                _anchor_subject_request(fixture["resolver"])
            creator.assert_not_called()
        else:
            result = _anchor_subject_request(fixture["resolver"])
            _assert_anchor_subject_response(
                fixture["resolver"], result, TA_ID, fixture["metadata"], [token],
                factory(token).jwt.payload()["exp"],
            )
            creator.assert_called_once()


@pytest.mark.parametrize("module", ["dc4eu_federation", "edu_federation", "setup_federation"])
@pytest.mark.parametrize("configured", [False, True])
def test_resolve_trust_anchor_subject_flask_client(anchor_subject, module, configured):
    fixture = anchor_subject
    resolver = fixture["resolver"] if configured else _anchor_subject_resolver({})
    app = Flask(__name__)
    app.federation_entity = resolver
    app.register_blueprint(import_module(module + ".trust_anchor.views").entity)
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, fixture)
        response = app.test_client().get("/resolve", query_string={"sub": TA_ID, "trust_anchor": TA_ID})
    if not configured:
        _assert_initial_ec_error(response, "invalid_trust_chain", 400)
        return
    assert response.status_code == 200
    assert response.mimetype == RESOLVE_RESPONSE.content_type
    token = response.get_data(as_text=True)
    _assert_anchor_subject_response(
        resolver, {"response_args": token}, TA_ID, fixture["metadata"], [fixture["ec"]],
        factory(fixture["ec"]).jwt.payload()["exp"],
    )
    caller = make_federation_entity(SUBJECT_ID, services=["resolve"])
    caller.keyjar.import_jwks(resolver.keyjar.export_jwks(), RESOLVER_ID)
    with responses.RequestsMock() as rsps:
        rsps.add("GET", resolver.get_endpoint("resolve").full_path,
                 body=token, content_type=response.mimetype)
        parsed = caller.do_request(
            "resolve", entity_id=RESOLVER_ID, endpoint=resolver.get_endpoint("resolve").full_path,
            request_args={"sub": TA_ID, "trust_anchor": [TA_ID]},
        )
    assert isinstance(parsed, ResolveResponse)
    assert parsed["trust_chain"] == [fixture["ec"]]
    assert parsed.to_dict()["metadata"] == fixture["metadata"]


@pytest.mark.parametrize("at_creation", [False, True])
def test_resolve_trust_anchor_subject_expired_result(anchor_subject, monkeypatch, at_creation):
    resolver = anchor_subject["resolver"]
    original = resolve_module.apply_policies

    def advance_clock(*args, **kwargs):
        chains = original(*args, **kwargs)
        expiration = chains[0].exp
        monkeypatch.setattr(resolve_module, "utc_time_sans_frac",
                            lambda: expiration - 1 if at_creation else expiration)
        monkeypatch.setattr("fedservice.entity_statement.create.utc_time_sans_frac", lambda: expiration)
        return chains

    monkeypatch.setattr(resolve_module, "apply_policies", advance_clock)
    signer = Mock(side_effect=AssertionError("expired response must not be signed"))
    monkeypatch.setattr("fedservice.entity_statement.create.sign_federation_jwt", signer)
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, anchor_subject)
        result = _anchor_subject_request(resolver)
    signer.assert_not_called()
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400


@pytest.mark.parametrize("mark_lifetime", [None, 300, 172800])
def test_resolve_trust_anchor_subject_trust_mark_expiration(mark_lifetime):
    federation = build_federation(deepcopy(FEDERATION_CONFIG))
    anchor, issuer = federation[TA_ID], federation[TMI_ID]
    mark_entity = issuer.server.trust_mark_entity
    if mark_lifetime is None:
        mark_entity.tm_lifetime.pop(SIRTIFI_TRUST_MARK_TYPE, None)
        kwargs = {}
    else:
        kwargs = {"exp": utc_time_sans_frac() + mark_lifetime}
    mark = mark_entity.create_trust_mark(SIRTIFI_TRUST_MARK_TYPE, TA_ID, **kwargs)
    anchor.context.trust_marks = [{"trust_mark_type": SIRTIFI_TRUST_MARK_TYPE, "trust_mark": mark}]
    resolver = _anchor_subject_resolver({TA_ID: anchor.keyjar.export_jwks()})
    messages = create_trust_chain_messages(issuer, anchor)
    ec = messages[anchor.get_endpoint("entity_configuration").full_path]
    ec_claims = factory(ec).jwt.payload()
    expected_expiration = min(ec_claims["exp"], kwargs.get("exp", ec_claims["exp"]))
    with responses.RequestsMock() as rsps:
        for url, token in messages.items():
            rsps.add("GET", url, body=token, content_type=ENTITY_CONFIGURATION.content_type)
        result = _anchor_subject_request(resolver)
    verified = _assert_anchor_subject_response(
        resolver, result, TA_ID, ec_claims["metadata"], [ec], expected_expiration,
    )
    assert verified.claims()["trust_marks"] == deep_freeze(anchor.context.trust_marks)


@pytest.fixture
def anchor_expiry_clock(monkeypatch):
    """Advance the relevant clocks explicitly without sleeping or changing skew."""
    clock = [utc_time_sans_frac()]
    for module in (
        "cryptojwt.jwt", "fedservice.federation_jwt.jose",
        "fedservice.entity_statement.create", "fedservice.entity_statement.cache",
        "fedservice.entity.function.trust_chain_collector", "fedservice.entity.server.resolve",
    ):
        monkeypatch.setattr(module + ".utc_time_sans_frac", lambda: clock[0])
    return clock


@pytest.fixture
def anchor_expiry_paths(anchor_expiry_clock, nested_anchor_subject):
    """Issue the existing nested topology under the controlled clock."""
    return nested_anchor_subject


def _anchor_expiry_reissue(messages, entity, expires_at, endpoint="entity_configuration"):
    url = entity.get_endpoint(endpoint).full_path
    payload = factory(messages[url]).jwt.payload()
    payload["exp"] = expires_at
    profile = ENTITY_CONFIGURATION if endpoint == "entity_configuration" else SUBORDINATE_STATEMENT
    token = sign_federation_jwt(
        profile, payload, entity.keyjar, entity.entity_id, "RS256", lifetime=0,
        iat=payload["iat"],
    )
    messages[url] = token
    return token


def _register_anchor_expiry_paths(rsps, messages):
    for url, token in messages.items():
        rsps.add("GET", url, body=token, content_type=ENTITY_CONFIGURATION.content_type)


def _assert_anchor_expiry_result(federation, resolver, messages, result, subject, anchor,
                                expires_at, with_ta_ec=False):
    path = [subject]
    if subject == SUBJECT_ID and IM_ID in federation:
        path.append(IM_ID)
    if path[-1] != anchor:
        path.append(anchor)
    chain = [messages[federation[subject].get_endpoint("entity_configuration").full_path]]
    chain.extend(messages[federation[issuer].get_endpoint("fetch").full_path] for issuer in path[1:])
    if with_ta_ec and len(path) > 1:
        chain.append(messages[federation[anchor].get_endpoint("entity_configuration").full_path])
    metadata = factory(chain[0]).jwt.payload()["metadata"]
    if subject == IM_ID and anchor == TA_ID:
        metadata["federation_entity"]["organization_name"] = "Root describes inner"
    return _assert_anchor_subject_response(resolver, result, subject, metadata, chain, expires_at)


@pytest.mark.parametrize("subject,with_ta_ec,anchor_lifetime", [
    (IM_ID, False, 3600), (IM_ID, True, 3600),
    (SUBJECT_ID, False, 3600), (SUBJECT_ID, True, 3600),
    (IM_ID, False, 172800),
])
def test_resolve_anchor_expiry_short_anchor_and_later_control(
        anchor_expiry_paths, anchor_expiry_clock, subject, with_ta_ec, anchor_lifetime):
    federation, resolver, messages = anchor_expiry_paths
    now = anchor_expiry_clock[0]
    anchor_ec = _anchor_expiry_reissue(messages, federation[TA_ID], now + anchor_lifetime)
    assert factory(anchor_ec).jwt.payload()["exp"] == now + anchor_lifetime
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_anchor_expiry_paths(rsps, messages)
        calls = None
        for _ in range(2):
            result = _anchor_subject_request(resolver, subject, [TA_ID], with_ta_ec=with_ta_ec)
            _assert_anchor_expiry_result(
                federation, resolver, messages, result, subject, TA_ID,
                now + min(anchor_lifetime, 86400), with_ta_ec,
            )
            assert resolver.function.trust_chain_collector.config_cache[TA_ID]["_jws"] == anchor_ec
            if calls is None:
                calls = len(rsps.calls)
            else:
                assert len(rsps.calls) == calls


@pytest.mark.parametrize("anchor_lifetime,subject_lifetime,ss_lifetime", [
    (7200, 3600, 86400), (7200, 86400, 3600), (3600, 3600, 3600),
    (3600, 3601, 86400), (3600, 3599, 86400),
])
def test_resolve_anchor_expiry_independent_minima(
        anchor_expiry_paths, anchor_expiry_clock, anchor_lifetime, subject_lifetime, ss_lifetime):
    federation, resolver, messages = anchor_expiry_paths
    now = anchor_expiry_clock[0]
    _anchor_expiry_reissue(messages, federation[TA_ID], now + anchor_lifetime)
    _anchor_expiry_reissue(messages, federation[IM_ID], now + subject_lifetime)
    _anchor_expiry_reissue(messages, federation[TA_ID], now + ss_lifetime, "fetch")
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_anchor_expiry_paths(rsps, messages)
        result = _anchor_subject_request(resolver, IM_ID, [TA_ID], with_ta_ec=True)
    _assert_anchor_expiry_result(
        federation, resolver, messages, result, IM_ID, TA_ID,
        now + min(anchor_lifetime, subject_lifetime, ss_lifetime), True,
    )


def test_resolve_anchor_expiry_flask_abbreviated_chain(anchor_expiry_paths, anchor_expiry_clock):
    federation, resolver, messages = anchor_expiry_paths
    expiry = anchor_expiry_clock[0] + 3600
    _anchor_expiry_reissue(messages, federation[TA_ID], expiry)
    app = Flask(__name__)
    app.federation_entity = resolver
    app.register_blueprint(import_module("edu_federation.trust_anchor.views").entity)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_anchor_expiry_paths(rsps, messages)
        response = app.test_client().get("/resolve", query_string={"sub": IM_ID, "trust_anchor": TA_ID})
    assert response.status_code == 200
    assert response.mimetype == RESOLVE_RESPONSE.content_type
    _assert_anchor_expiry_result(
        federation, resolver, messages, {"response_args": response.get_data(as_text=True)},
        IM_ID, TA_ID, expiry,
    )


@pytest.mark.parametrize("kind,error_cls", [
    ("valid", None), ("expired", None), ("signature", None),
    ("at_expiry", None), ("within_skew", None),
    ("identity", None), ("replacement_keys", None),
    ("header", FederationJwtHeaderError), ("kid", FederationJwtKeyResolutionError),
])
def test_resolve_anchor_expiry_authenticates_cached_artifact(
        anchor_expiry_paths, anchor_expiry_clock, monkeypatch, kind, error_cls):
    federation, resolver, messages = anchor_expiry_paths
    anchor = federation[TA_ID]
    url = anchor.get_endpoint("entity_configuration").full_path
    original = messages[url]
    payload = factory(original).jwt.payload()
    token = original
    if kind in ("expired", "at_expiry", "within_skew"):
        offset = {"expired": -60, "at_expiry": 0, "within_skew": -1}[kind]
        payload.update(iat=anchor_expiry_clock[0] - 120, exp=anchor_expiry_clock[0] + offset)
        token = sign_federation_jwt(ENTITY_CONFIGURATION, payload, anchor.keyjar, TA_ID,
                                    "RS256", lifetime=0, iat=payload["iat"])
        if kind != "expired":
            assert verify_federation_jwt(ENTITY_CONFIGURATION, token, resolver.keyjar).claims()["exp"] == payload["exp"]
    elif kind == "signature":
        token = corrupt_signature(original)
    elif kind == "identity":
        other = make_entity(POLICY_OTHER_TA, "trust_anchor")
        resolver.keyjar.import_jwks(other.keyjar.export_jwks(), POLICY_OTHER_TA)
        token = create_entity_configuration(POLICY_OTHER_TA, other.keyjar, metadata=payload["metadata"])
        assert verify_federation_jwt(ENTITY_CONFIGURATION, token, resolver.keyjar).claims()["sub"] != TA_ID
    elif kind in ("replacement_keys", "kid"):
        kid = factory(original).jwt.headers["kid"] if kind == "replacement_keys" else "replacement"
        key = new_rsa_key(kid=kid, use="sig")
        jar = KeyJar()
        jar.add_keys(TA_ID, [key])
        payload["jwks"] = {"keys": [key.serialize(private=False)]}
        token = sign_federation_jwt(ENTITY_CONFIGURATION, payload, jar, TA_ID, "RS256", lifetime=0,
                                    iat=payload["iat"])
        assert verify_federation_jwt(ENTITY_CONFIGURATION, token, jar).raw_token() == token
    elif kind == "header":
        token = JWS(json.dumps(payload), alg="RS256", typ=RESOLVE_RESPONSE.typ).sign_compact(
            keys=anchor.keyjar.get_signing_key("RSA"),
        )
    creator = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", creator)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_anchor_expiry_paths(rsps, messages)
        paths, ec = collect_trust_chains(resolver, IM_ID, stop_at=TA_ID)
        assert [chain.anchor for chain in verify_trust_chains(resolver, paths, ec)] == [IM_ID, TA_ID]
        assert verify_federation_jwt(ENTITY_CONFIGURATION, original, resolver.keyjar).raw_token() == original
        # Cached parsed fields are not authoritative for the retained compact token.
        resolver.function.trust_chain_collector.config_cache[TA_ID]["_jws"] = token
        keys_before = resolver.keyjar.export_jwks(issuer_id=TA_ID)
        if error_cls:
            with pytest.raises(error_cls):
                _anchor_subject_request(resolver, IM_ID, [TA_ID])
        else:
            result = _anchor_subject_request(resolver, IM_ID, [TA_ID])
            if kind == "valid":
                _assert_anchor_expiry_result(
                    federation, resolver, messages, result, IM_ID, TA_ID, payload["exp"],
                )
            else:
                assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
        assert resolver.keyjar.export_jwks(issuer_id=TA_ID) == keys_before
    if kind != "valid":
        creator.assert_not_called()


@pytest.mark.parametrize("anchors", [[IM_ID], [TA_ID, IM_ID]])
def test_resolve_anchor_expiry_excludes_above_selected_anchor(
        anchor_expiry_paths, anchor_expiry_clock, anchors):
    federation, resolver, messages = anchor_expiry_paths
    now = anchor_expiry_clock[0]
    _anchor_expiry_reissue(messages, federation[TA_ID], now + 3600)
    _anchor_expiry_reissue(messages, federation[IM_ID], now + 7200)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_anchor_expiry_paths(rsps, messages)
        result = _anchor_subject_request(resolver, SUBJECT_ID, anchors, with_ta_ec=True)
    _assert_anchor_expiry_result(
        federation, resolver, messages, result, SUBJECT_ID, IM_ID, now + 7200, True,
    )


@pytest.fixture
def anchor_expiry_alternatives(anchor_expiry_clock):
    """Build independently configured anchors with distinct signed paths."""
    federation = build_federation({
        TA_ID: {"entity_type": "trust_anchor", "subordinates": [SUBJECT_ID], "kwargs": {}},
        POLICY_OTHER_TA: {"entity_type": "trust_anchor", "subordinates": [SUBJECT_ID], "kwargs": {}},
        SUBJECT_ID: {"entity_type": "intermediate",
                     "kwargs": {"authority_hints": [TA_ID, POLICY_OTHER_TA]}},
    })
    resolver = _anchor_subject_resolver({
        identifier: federation[identifier].keyjar.export_jwks() for identifier in (TA_ID, POLICY_OTHER_TA)
    })
    return federation, resolver


def _prepare_anchor_expiry_alternatives(federation, resolver, rsps, reverse=False):
    if reverse:
        federation[SUBJECT_ID].context.authority_hints.reverse()
    messages = create_trust_chain_messages(federation[SUBJECT_ID], federation[TA_ID])
    messages.update(create_trust_chain_messages(federation[SUBJECT_ID], federation[POLICY_OTHER_TA]))
    _register_anchor_expiry_paths(rsps, messages)
    paths, ec = collect_trust_chains(resolver, SUBJECT_ID)
    assert len(verify_trust_chains(resolver, paths, ec)) == 2
    return messages


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("failure", ["signature", "expired", "within_skew"])
def test_resolve_anchor_expiry_candidate_local_rejection(
        anchor_expiry_alternatives, anchor_expiry_clock, monkeypatch, reverse, failure):
    federation, resolver = anchor_expiry_alternatives
    observed = observe_verified_candidates(monkeypatch)
    with responses.RequestsMock() as rsps:
        messages = _prepare_anchor_expiry_alternatives(federation, resolver, rsps, reverse)
        token = messages[federation[TA_ID].get_endpoint("entity_configuration").full_path]
        if failure == "signature":
            token = corrupt_signature(token)
        else:
            payload = factory(token).jwt.payload()
            offset = -1 if failure == "within_skew" else -60
            payload.update(iat=anchor_expiry_clock[0] - 120, exp=anchor_expiry_clock[0] + offset)
            token = sign_federation_jwt(ENTITY_CONFIGURATION, payload, federation[TA_ID].keyjar,
                                        TA_ID, "RS256", lifetime=0, iat=payload["iat"])
        resolver.function.trust_chain_collector.config_cache[TA_ID]["_jws"] = token
        calls = len(rsps.calls)
        result = _anchor_subject_request(resolver, SUBJECT_ID, [TA_ID, POLICY_OTHER_TA], with_ta_ec=True)
        assert len(rsps.calls) == calls
    assert [c.anchor for c in observed[0][0]] == (
        [POLICY_OTHER_TA, TA_ID] if reverse else [TA_ID, POLICY_OTHER_TA])
    _assert_anchor_expiry_result(
        federation, resolver, messages, result, SUBJECT_ID, POLICY_OTHER_TA, anchor_expiry_clock[0] + 86400, True,
    )


def test_resolve_anchor_expiry_all_candidates_rejected(anchor_expiry_alternatives, monkeypatch):
    federation, resolver = anchor_expiry_alternatives
    creator = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", creator)
    with responses.RequestsMock() as rsps:
        _prepare_anchor_expiry_alternatives(federation, resolver, rsps)
        for anchor in (TA_ID, POLICY_OTHER_TA):
            cached = resolver.function.trust_chain_collector.config_cache[anchor]
            cached["_jws"] = corrupt_signature(cached["_jws"])
        result = _anchor_subject_request(resolver, SUBJECT_ID, [TA_ID, POLICY_OTHER_TA])
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    creator.assert_not_called()


@pytest.mark.parametrize("state", ["missing", "stale"])
def test_resolve_anchor_expiry_unavailable_after_collection(
        anchor_expiry_paths, anchor_expiry_clock, monkeypatch, state):
    federation, resolver, messages = anchor_expiry_paths
    original = resolve_module.collect_trust_chains

    def evict_anchor(*args, **kwargs):
        result = original(*args, **kwargs)
        cache = resolver.function.trust_chain_collector.config_cache
        if state == "missing":
            del cache[TA_ID]
        else:
            cache[TA_ID]["exp"] = anchor_expiry_clock[0] + cache.allowed_delta
        return result

    monkeypatch.setattr(resolve_module, "collect_trust_chains", evict_anchor)
    creator = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", creator)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_anchor_expiry_paths(rsps, messages)
        result = _anchor_subject_request(resolver, IM_ID, [TA_ID])
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    creator.assert_not_called()


def test_resolve_anchor_expiry_warm_then_stale(anchor_expiry_paths, anchor_expiry_clock, monkeypatch):
    federation, resolver, messages = anchor_expiry_paths
    expiry = anchor_expiry_clock[0] + 3600
    _anchor_expiry_reissue(messages, federation[TA_ID], expiry)
    creator = Mock(wraps=resolve_module.create_resolve_response)
    monkeypatch.setattr(resolve_module, "create_resolve_response", creator)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_anchor_expiry_paths(rsps, messages)
        result = _anchor_subject_request(resolver, IM_ID, [TA_ID])
        _assert_anchor_expiry_result(federation, resolver, messages, result, IM_ID, TA_ID, expiry)
        creator.reset_mock()
        anchor_expiry_clock[0] = expiry
        result = _anchor_subject_request(resolver, IM_ID, [TA_ID])
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    creator.assert_not_called()


@pytest.mark.parametrize("at_creation", [False, True])
def test_resolve_anchor_expiry_clock_crossing(
        anchor_expiry_paths, anchor_expiry_clock, monkeypatch, at_creation):
    federation, resolver, messages = anchor_expiry_paths
    expiry = anchor_expiry_clock[0] + 3600
    _anchor_expiry_reissue(messages, federation[TA_ID], expiry)
    original = resolve_module.apply_policies

    def advance_clock(*args, **kwargs):
        chains = original(*args, **kwargs)
        monkeypatch.setattr(resolve_module, "utc_time_sans_frac", lambda: expiry - 1 if at_creation else expiry)
        monkeypatch.setattr("fedservice.entity_statement.create.utc_time_sans_frac", lambda: expiry)
        return chains

    monkeypatch.setattr(resolve_module, "apply_policies", advance_clock)
    signer = Mock(side_effect=AssertionError("expired response must not be signed"))
    monkeypatch.setattr("fedservice.entity_statement.create.sign_federation_jwt", signer)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_anchor_expiry_paths(rsps, messages)
        result = _anchor_subject_request(resolver, IM_ID, [TA_ID])
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    signer.assert_not_called()


def test_resolve_anchor_expiry_retains_authenticated_artifact(
        anchor_expiry_paths, anchor_expiry_clock, monkeypatch):
    federation, resolver, messages = anchor_expiry_paths
    expiry = anchor_expiry_clock[0] + 3600
    url = federation[TA_ID].get_endpoint("entity_configuration").full_path
    replacement = messages[url]
    original_ec = _anchor_expiry_reissue(messages, federation[TA_ID], expiry)
    original = resolve_module.apply_policies

    def replace_cached_anchor(*args, **kwargs):
        chains = original(*args, **kwargs)
        resolver.function.trust_chain_collector.config_cache[TA_ID] = dict(
            factory(replacement).jwt.payload(), _jws=replacement,
        )
        return chains

    monkeypatch.setattr(resolve_module, "apply_policies", replace_cached_anchor)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_anchor_expiry_paths(rsps, messages)
        result = _anchor_subject_request(resolver, IM_ID, [TA_ID], with_ta_ec=True)
    assert original_ec != replacement
    _assert_anchor_expiry_result(federation, resolver, messages, result, IM_ID, TA_ID, expiry, True)


def test_resolve_anchor_expiry_singleton_reuses_verified_subject(anchor_subject, monkeypatch):
    fixture = anchor_subject
    resolver = fixture["resolver"]
    replacement = create_entity_configuration(
        TA_ID, fixture["anchor"].keyjar, metadata=fixture["metadata"], lifetime=172800,
    )
    original = resolve_module.apply_policies

    def replace_cached_subject(*args, **kwargs):
        chains = original(*args, **kwargs)
        resolver.function.trust_chain_collector.config_cache[TA_ID] = dict(
            factory(replacement).jwt.payload(), _jws=replacement,
        )
        return chains

    monkeypatch.setattr(resolve_module, "apply_policies", replace_cached_subject)
    verifier = Mock(wraps=verifier_module.verify_federation_jwt)
    monkeypatch.setattr(verifier_module, "verify_federation_jwt", verifier)
    with responses.RequestsMock() as rsps:
        _register_anchor_subject(rsps, fixture)
        result = _anchor_subject_request(resolver, with_ta_ec=True)
        assert len(rsps.calls) == 1
    verifier.assert_called_once()
    _assert_anchor_subject_response(
        resolver, result, TA_ID, fixture["metadata"], [fixture["ec"]],
        factory(fixture["ec"]).jwt.payload()["exp"],
    )
