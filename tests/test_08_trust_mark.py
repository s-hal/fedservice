from copy import deepcopy
import json
from urllib.parse import urlparse

import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.key_import import import_jwks
from requests import Response

from fedservice.defaults import federation_endpoints
from fedservice.defaults import federation_services
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import TRUST_MARK
from fedservice.federation_jwt.registry import TRUST_MARK_STATUS_RESPONSE
from fedservice.message import TrustMark
from fedservice.message import TrustMarkRequest
from fedservice.message import TrustMarkStatusResponse
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"
TA_ID = "https://anchor.example.com"

TA_ENDPOINTS = federation_endpoints("entity_configuration", "fetch", "list")
TA_SERVICES = federation_services("entity_configuration", "entity_statement", "trust_mark_status")
TMI_SERVICES = federation_services(
    "entity_configuration",
    "entity_statement",
    "resolve",
    "list",
    "trust_mark",
)

TRUST_MARK_ISSUER_ID = "https://tmi.example.com"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [TRUST_MARK_ISSUER_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": TA_ENDPOINTS,
            "services": TA_SERVICES,
            "trust_mark_issuers": {"https://refeds.org/sirtfi": [TRUST_MARK_ISSUER_ID]}
        }
    },
    TRUST_MARK_ISSUER_ID: {
        "entity_type": "trust_mark_issuer",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "preference": {
                "organization_name": "Trust Mark Issuer 'R US"
            },
            "authority_hints": [TA_ID],
            "services": TMI_SERVICES,
            "trust_mark_entity": {
                "class": "fedservice.trust_mark_entity.entity.TrustMarkEntity",
                "kwargs": {
                    "trust_mark_specification": {
                        "https://refeds.org/sirtfi": {
                            "lifetime": 2592000
                        }
                    },
                    "trust_mark_db": {
                        "class": "fedservice.trust_mark_entity.FileDB",
                        "kwargs": {
                            "https://refeds.org/sirtfi": "sirtfi",
                        }
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
                                "fedservice.trust_mark_entity.server.trust_mark_status"
                                ".TrustMarkStatus",
                            "kwargs": {}
                        }
                    }
                }
            }
        }
    }
}


class TestSignedTrustMark():

    @pytest.fixture(autouse=True)
    def create_entities(self, tmp_path):
        config = deepcopy(FEDERATION_CONFIG)
        trust_mark_db = config[TRUST_MARK_ISSUER_ID]["kwargs"][
            "trust_mark_entity"
        ]["kwargs"]["trust_mark_db"]["kwargs"]
        trust_mark_db["https://refeds.org/sirtfi"] = str(tmp_path / "sirtfi")
        self.federation_entity = build_federation(config)
        self.ta = self.federation_entity[TA_ID]
        self.tmi = self.federation_entity[TRUST_MARK_ISSUER_ID]

    def test_create_trust_mark_self_signed(self):
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _trust_mark = _issuer.self_signed_trust_mark(
            trust_mark_type='https://openid.net/certification',
            logo_uri=("http://openid.net/wordpress-content/uploads/2016/05/"
                      "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg")
        )

        # Unpack and verify the Trust Mark
        _mark = _issuer.unpack_trust_mark(_trust_mark)

        assert isinstance(_mark, TrustMark)
        assert _mark["trust_mark_type"] == "https://openid.net/certification"
        assert _mark['iss'] == _mark['sub']
        assert _mark['iss'] == self.tmi.entity_id
        assert set(_mark.keys()) == {'iss', 'sub', 'iat', 'trust_mark_type', 'logo_uri'}

    def test_create_unpack_trust_3rd_party(self):
        _sub = "https://op.ntnu.no"

        _tme = self.tmi.server.trust_mark_entity
        _trust_mark = _tme.create_trust_mark("https://refeds.org/sirtfi", _sub)
        _mark = _tme.unpack_trust_mark(_trust_mark, _sub)

        assert isinstance(_mark, TrustMark)

    def test_process_request(self):
        _sub = "https://op.ntnu.no"
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {}
        _trust_mark = _issuer.create_trust_mark("https://refeds.org/sirtfi", _sub)

        result = _endpoint.process_request({'trust_mark': _trust_mark})
        response = _endpoint.do_response(**result)
        verified = verify_federation_jwt(
            profile=TRUST_MARK_STATUS_RESPONSE,
            token=response["response"],
            key_jar=self.tmi.keyjar,
        )

        assert (
            "Content-type",
            TRUST_MARK_STATUS_RESPONSE.content_type,
        ) in response["http_headers"]
        assert verified.claims()["trust_mark"] == _trust_mark
        assert verified.claims()["status"] == "active"

    def test_status_requires_valid_compact_trust_mark(self):
        _sub = "https://op.ntnu.no"
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _trust_mark = _issuer.create_trust_mark("https://refeds.org/sirtfi", _sub)

        _jws = factory(_trust_mark)
        _payload = _jws.jwt.payload()
        query = {"sub": _payload["sub"], "trust_mark_type": _payload["trust_mark_type"]}
        error = _endpoint.process_request(query)
        response = _endpoint.do_response(response_args=error)

        assert error["error"] == "invalid_request"
        assert ("Content-type", "application/json") in response["http_headers"]
        assert json.loads(response["response"])["error"] == "invalid_request"

        malformed = _endpoint.process_request({"trust_mark": "not-a-jwt"})
        assert malformed["error"] == "invalid_request"

    def test_request_response_args(self):
        # Create a Trust Mark
        _sub = "https://op.ntnu.no"
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _trust_mark = _issuer.create_trust_mark("https://refeds.org/sirtfi", _sub)

        # Ask for a verification of the Trust Mark
        tms = self.ta.get_service('trust_mark_status')
        req = tms.get_request_parameters(
            request_args={'trust_mark': _trust_mark},
            fetch_endpoint=self.tmi.get_endpoint('trust_mark_status').full_path
        )
        p = urlparse(req['url'])
        tmr = TrustMarkRequest().from_urlencoded(p.query)

        result = self.tmi.get_endpoint('trust_mark_status').process_request(
            tmr.to_dict()
        )
        verified = verify_federation_jwt(
            profile=TRUST_MARK_STATUS_RESPONSE,
            token=result["response_args"],
            key_jar=self.tmi.keyjar,
        )

        assert verified.claims()["trust_mark"] == _trust_mark
        assert verified.claims()["status"] == "active"

    def test_client_verifies_trust_mark_status_response_profile(self):
        endpoint = self.tmi.get_endpoint("trust_mark_status")
        issuer = endpoint.upstream_get("unit")
        trust_mark = issuer.create_trust_mark(
            "https://refeds.org/sirtfi",
            "https://op.ntnu.no",
        )
        result = endpoint.process_request({"trust_mark": trust_mark})
        http_response = endpoint.do_response(**result)

        import_jwks(
            self.ta.keyjar,
            self.tmi.keyjar.export_jwks(),
            self.tmi.entity_id,
        )
        response = Response()
        response.status_code = 200
        response._content = http_response["response"].encode("utf-8")
        response.headers["Content-Type"] = TRUST_MARK_STATUS_RESPONSE.content_type
        response.url = endpoint.full_path

        service = self.ta.get_service("trust_mark_status")
        parsed = self.ta.client.parse_request_response(
            service,
            response,
            response_body_type=service.response_body_type,
        )

        assert isinstance(parsed, TrustMarkStatusResponse)
        assert parsed["trust_mark"] == trust_mark
        assert parsed["status"] == "active"

    def test_client_rejects_trust_mark_as_status_response(self):
        endpoint = self.tmi.get_endpoint("trust_mark_status")
        issuer = endpoint.upstream_get("unit")
        trust_mark = issuer.create_trust_mark(
            "https://refeds.org/sirtfi",
            "https://op.ntnu.no",
        )
        response = Response()
        response.status_code = 200
        response._content = trust_mark.encode("utf-8")
        response.headers["Content-Type"] = TRUST_MARK_STATUS_RESPONSE.content_type
        response.url = endpoint.full_path

        service = self.ta.get_service("trust_mark_status")
        with pytest.raises(FederationJwtHeaderError):
            self.ta.client.parse_request_response(
                service,
                response,
                response_body_type=service.response_body_type,
            )

    def test_client_verifies_trust_mark_response_profile(self):
        service = self.tmi.get_service("trust_mark")
        self.tmi.client.context.issuer = self.tmi.entity_id
        where_and_what = create_trust_chain_messages(self.tmi, self.ta)
        with responses.RequestsMock() as rsps:
            for url, statement in where_and_what.items():
                rsps.add(
                    "GET",
                    url,
                    body=statement,
                    adding_headers={
                        "Content-Type": ENTITY_CONFIGURATION.content_type
                    },
                    status=200,
                )

            endpoint_url = service.get_endpoint()

        endpoint = self.tmi.get_endpoint("trust_mark")
        assert endpoint_url == endpoint.full_path
        subject = "https://op.ntnu.no"
        result = endpoint.process_request(
            {
                "trust_mark_type": "https://refeds.org/sirtfi",
                "sub": subject,
            }
        )
        endpoint_response = endpoint.do_response(response_args=result)
        response = Response()
        response.status_code = 200
        response._content = endpoint_response["response"].encode("utf-8")
        response.headers.update(dict(endpoint_response["http_headers"]))
        response.url = endpoint.full_path

        parsed = self.tmi.client.parse_request_response(
            service,
            response,
            response_body_type=service.response_body_type,
        )

        assert isinstance(parsed, TrustMark)
        assert parsed["iss"] == self.tmi.entity_id
        assert parsed["sub"] == subject
        assert parsed["trust_mark_type"] == "https://refeds.org/sirtfi"

    def test_client_rejects_status_response_as_trust_mark(self):
        service = self.tmi.get_service("trust_mark")
        self.tmi.client.context.issuer = self.tmi.entity_id
        where_and_what = create_trust_chain_messages(self.tmi, self.ta)
        with responses.RequestsMock() as rsps:
            for url, statement in where_and_what.items():
                rsps.add(
                    "GET",
                    url,
                    body=statement,
                    adding_headers={
                        "Content-Type": ENTITY_CONFIGURATION.content_type
                    },
                    status=200,
                )

            service.get_endpoint()

        status_endpoint = self.tmi.get_endpoint("trust_mark_status")
        issuer = status_endpoint.upstream_get("unit")
        trust_mark = issuer.create_trust_mark(
            "https://refeds.org/sirtfi",
            "https://op.ntnu.no",
        )
        result = status_endpoint.process_request({"trust_mark": trust_mark})
        endpoint_response = status_endpoint.do_response(**result)
        response = Response()
        response.status_code = 200
        response._content = endpoint_response["response"].encode("utf-8")
        response.headers["Content-Type"] = TRUST_MARK.content_type
        response.url = status_endpoint.full_path

        with pytest.raises(FederationJwtHeaderError):
            self.tmi.client.parse_request_response(
                service,
                response,
                response_body_type=service.response_body_type,
            )

    @pytest.mark.parametrize(
        "status,expected_active",
        [
            ("active", True),
            ("expired", False),
            ("revoked", False),
            ("invalid", False),
        ],
    )
    def test_verify_trust_mark_uses_status_response_semantics(
            self, monkeypatch, status, expected_active):
        endpoint = self.tmi.get_endpoint("trust_mark_status")
        issuer = endpoint.upstream_get("unit")
        trust_mark = issuer.create_trust_mark(
            "https://refeds.org/sirtfi",
            self.tmi.entity_id,
        )
        trust_mark_payload = factory(trust_mark).jwt.payload()
        status_response = TrustMarkStatusResponse(
            iss=self.tmi.entity_id,
            iat=trust_mark_payload["iat"],
            trust_mark=trust_mark,
            status=status,
        )
        monkeypatch.setattr(
            self.tmi,
            "do_request",
            lambda *args, **kwargs: status_response,
        )

        where_and_what = create_trust_chain_messages(self.tmi, self.ta)
        with responses.RequestsMock() as rsps:
            for url, statement in where_and_what.items():
                rsps.add(
                    "GET",
                    url,
                    body=statement,
                    adding_headers={
                        "Content-Type": ENTITY_CONFIGURATION.content_type
                    },
                    status=200,
                )

            verified_trust_mark = self.tmi.verify_trust_mark(
                trust_mark,
                check_with_issuer=True,
            )

        if expected_active:
            assert verified_trust_mark["sub"] == self.tmi.entity_id
            assert verified_trust_mark["trust_mark_type"] == (
                "https://refeds.org/sirtfi"
            )
        else:
            assert verified_trust_mark is None

    def test_status_returns_not_found_for_unissued_trust_mark(self):
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _issuer.create_trust_mark(
            "https://refeds.org/sirtfi",
            "https://issued.example.org",
        )
        unissued = _issuer.self_signed_trust_mark(
            trust_mark_type="https://refeds.org/sirtfi",
            sub="https://unissued.example.org",
        )

        error = _endpoint.process_request({"trust_mark": unissued})
        response = _endpoint.do_response(response_args=error)

        assert error["error"] == "not_found"
        assert ("Content-type", "application/json") in response["http_headers"]
        assert json.loads(response["response"])["error"] == "not_found"

    def test_trust_mark_verifier(self):
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {
            "ref": 'https://refeds.org/sirtfi'
        }

        _trust_mark = _issuer.create_trust_mark(trust_mark_type="https://refeds.org/sirtfi",
                                                sub=self.tmi.entity_id)

        where_and_what = create_trust_chain_messages(self.tmi, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": ENTITY_CONFIGURATION.content_type},
                         status=200)

            verified_trust_mark = self.tmi.function.trust_mark_verifier(
                trust_mark=_trust_mark, trust_anchor=self.ta.entity_id)

        assert verified_trust_mark
        assert set(verified_trust_mark.keys()) == {
            'exp', 'iat', 'iss', 'trust_mark_type', 'sub', 'ref'
        }

    def test_metadata(self):
        _metadata = self.tmi.get_metadata()
        assert "federation_entity" in _metadata
        assert set(_metadata["federation_entity"].keys()) == {'federation_resolve_endpoint',
                                                              'federation_trust_mark_endpoint',
                                                              'federation_trust_mark_list_endpoint',
                                                              'federation_trust_mark_status_endpoint',
                                                              'federation_trust_mark_endpoint_auth_methods',
                                                              'federation_trust_mark_list_endpoint_auth_methods',
                                                              'federation_trust_mark_status_endpoint_auth_methods',
                                                              'organization_name'}
        assert _metadata["federation_entity"]["federation_trust_mark_endpoint"] == 'https://tmi.example.com/trust_mark'
