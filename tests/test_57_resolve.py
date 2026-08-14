import pytest
import responses
from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from fedservice.entity.function import collect_trust_chains

from fedservice.entity.function import apply_policies
from fedservice.entity.function import verify_trust_chains
from fedservice.entity_statement.create import create_resolve_response
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.message import ResolveResponse
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

    def _perform_resolve(self):
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
        resolver_query = {'sub': self.rp.entity_id,
                          'trust_anchor': self.ta.entity_id}

        with responses.RequestsMock() as rsps:
            for _url, _jwks in extra.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": ENTITY_CONFIGURATION.content_type}, status=200)

            response = resolver.process_request(resolver_query)

        return resolver, resolver_query, response, selected_chain

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
