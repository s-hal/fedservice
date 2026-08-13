import base64
import json
import os

import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.message.oidc import AuthorizationRequest

from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.entity.function import get_verified_trust_chains
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import EXPLICIT_REGISTRATION_RESPONSE
from fedservice.federation_jwt.registry import TRUST_MARK
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"


def replace_protected_header(token, remove=None, **updates):
    parts = token.split(".")
    protected_header = dict(factory(token).jwt.headers)
    if remove is not None:
        protected_header.pop(remove)
    protected_header.update(updates)
    encoded = base64.urlsafe_b64encode(
        json.dumps(protected_header, separators=(",", ":")).encode("utf-8")
    )
    parts[0] = encoded.decode("ascii").rstrip("=")
    return ".".join(parts)


def corrupt_signature(token):
    parts = token.split(".")
    replacement = "A" if parts[2][0] != "A" else "B"
    parts[2] = replacement + parts[2][1:]
    return ".".join(parts)


class RecordingMetadataVerifier(object):
    def __init__(self, result):
        self.result = result
        self.tokens = []

    def __call__(self, token):
        self.tokens.append(token)
        return self.result

FE_FUNCTIONS = {
    "trust_chain_collector": {
        "class": "fedservice.entity.function.trust_chain_collector.TrustChainCollector",
        "kwargs": {}
    },
    "verifier": {
        "class": "fedservice.entity.function.verifier.TrustChainVerifier",
        "kwargs": {}
    },
    "policy": {
        "class": "fedservice.entity.function.policy.TrustChainPolicy",
        "kwargs": {}
    },
    "trust_mark_verifier": {
        "class": "fedservice.entity.function.trust_mark_verifier.TrustMarkVerifier",
        "kwargs": {}
    }
}

OIDC_SERVICE = DEFAULT_OIDC_SERVICES.copy()
OIDC_SERVICE.update(DEFAULT_OIDC_FED_SERVICES)

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [RP_ID, OP_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org",
                "scopes_supported": ["openid", "profile"],
                "response_types_supported": ['id_token', 'code', 'code id_token']
            },
            "endpoints": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    RP_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "federation_services": ["oidc_registration", "entity_configuration",
                                    "entity_statement"],
            "authority_hints": [TA_ID],
            "services": OIDC_SERVICE,
            "entity_type_config": {
                "client_id": RP_ID,
                "client_secret": "a longesh password",
                "keys": {"key_defs": DEFAULT_KEY_DEFS},
                "preference": {
                    "grant_types": ["authorization_code", "implicit", "refresh_token"],
                    "id_token_signed_response_alg": "ES256",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "token_endpoint_auth_signing_alg": "ES256",
                    "scopes_supported": ["openid", "profile"],
                    "client_registration_types": ["explicit"]
                },
            }
        }
    },
    OP_ID: {
        "entity_type": "openid_provider",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
            "endpoints": [{
                "oidc_authz": {
                    "path": "authz",
                    'class': 'fedservice.appserver.oidc.authorization.Authorization',
                    "kwargs": {}
                }}, {
                "oidc_registration": {
                    "path": "registration",
                    'class': 'fedservice.appserver.oidc.registration.Registration',
                    "kwargs": {}
                }},
                "entity_configuration"]
        }
    }
}


class TestRpService(object):

    @pytest.fixture(autouse=True)
    def fed_setup(self):
        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.rp = federation[RP_ID]
        self.op = federation[OP_ID]

        _context = self.rp["openid_relying_party"].context
        _context.issuer = self.op.entity_id
        _response_types = _context.get_preference(
            "response_types_supported", _context.supports().get("response_types_supported", [])
        )
        _context.construct_uris(_response_types)

        self.entity_config_service = self.rp["federation_entity"].get_service(
            "entity_configuration")
        self.entity_config_service.upstream_get("context").issuer = OP_ID
        self.registration_service = self.rp["federation_entity"].get_service("registration")

    def _registration_response(self):
        _msgs = create_trust_chain_messages(self.op, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add(
                    "GET",
                    _url,
                    body=_jwks,
                    adding_headers={
                        "Content-Type": "application/entity-statement+jwt"
                    },
                    status=200,
                )

            _trust_chains = get_verified_trust_chains(
                self.rp,
                self.op["federation_entity"].entity_id,
            )

        self.rp["openid_relying_party"].context.server_metadata = (
            _trust_chains[0].metadata
        )
        self.rp["federation_entity"].client.context.server_metadata = (
            _trust_chains[0].metadata
        )

        _sc = self.registration_service.upstream_get("context")
        self.registration_service.endpoint = _sc.get_metadata_claim(
            "federation_registration_endpoint"
        )
        _rp_fe = self.rp["federation_entity"]
        request_jwt = self.registration_service.construct(
            request_args={"entity_id": _rp_fe.context.entity_id}
        )
        request_info = self.registration_service.get_request_parameters(
            request_body_type="jwt",
            method="POST",
        )
        endpoint = self.op["openid_provider"].get_endpoint("registration")

        _msgs = create_trust_chain_messages(self.rp, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add(
                    "GET",
                    _url,
                    body=_jwks,
                    adding_headers={
                        "Content-Type": "application/entity-statement+jwt"
                    },
                    status=200,
                )

            request = endpoint.parse_request(request_info["request"])
            result = endpoint.process_request(request)

        http_response = endpoint.do_response(**result)
        assert (
            "Content-type",
            EXPLICIT_REGISTRATION_RESPONSE.content_type,
        ) in http_response["http_headers"]
        response_token = http_response["response"]
        response_jwt = factory(response_token)
        assert response_jwt.jwt.headers["typ"] == EXPLICIT_REGISTRATION_RESPONSE.typ
        response_payload = response_jwt.jwt.payload()
        assert response_payload["iss"] == OP_ID
        assert response_payload["sub"] == RP_ID
        assert response_payload["aud"] == RP_ID
        assert response_payload["trust_anchor"] == TA_ID
        assert response_payload["authority_hints"] == [TA_ID]
        assert response_payload["iat"] < response_payload["exp"]
        assert "jwks" not in response_payload
        assert set(response_payload["metadata"]) == {"openid_relying_party"}
        assert response_payload["metadata"]["openid_relying_party"]["client_id"]
        return response_token, request_info["body"], request_jwt

    def _parse_registration_response_with_fallback(self, token, request):
        _msgs = create_trust_chain_messages(self.rp, self.ta)
        del _msgs['https://ta.example.org/.well-known/openid-federation']
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add(
                    "GET",
                    _url,
                    body=_jwks,
                    adding_headers={
                        "Content-Type": "application/entity-statement+jwt"
                    },
                    status=200,
                )

            return self.registration_service.parse_response(
                token,
                request=request,
            )

    def test_create_reqistration_request(self):
        # Collect information about the OP
        _msgs = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.op["federation_entity"].entity_id)

        self.rp["openid_relying_party"].context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        # construct the client registration request
        req_args = {"entity_id": self.rp["federation_entity"].entity_id}
        jws = self.registration_service.construct(request_args=req_args)
        assert jws

        _sc = self.registration_service.upstream_get("context")
        self.registration_service.endpoint = _sc.get_metadata_claim("federation_registration_endpoint")

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(
            request_body_type="jwt", method="POST")

        assert set(_info.keys()) == {"method", "url", "body", "headers", "request"}
        assert _info["method"] == "POST"
        assert _info["url"] == "https://op.example.org/registration"
        assert _info["headers"] == {"Content-Type": ENTITY_CONFIGURATION.content_type}

        _jws = _info["body"]
        _jwt = factory(_jws)
        assert _jwt.jwt.headers["typ"] == ENTITY_CONFIGURATION.typ
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {"sub", "iss", "metadata", "jwks", "exp",
                                       "iat", "authority_hints"}
        assert set(payload["metadata"]["openid_relying_party"].keys()) == {
            'application_type',
            'client_registration_types',
            'default_max_age',
            'grant_types',
            'id_token_signed_response_alg',
            'jwks',
            'redirect_uris',
            'request_object_signing_alg',
            'response_modes',
            'response_types',
            'subject_type',
            'token_endpoint_auth_method',
            'token_endpoint_auth_signing_alg',
            'userinfo_signed_response_alg'}

    def test_parse_registration_response(self):
        token, request, jws = self._registration_response()
        response = self._parse_registration_response_with_fallback(token, request)

        assert self.registration_service.upstream_get(
            "context"
        ).registration_response is response

        metadata = response["metadata"]
        # The response doesn't touch the federation_entity metadata, therefor it's not included
        assert set(metadata.keys()) == {'openid_relying_party'}

        assert set(metadata["openid_relying_party"].keys()) == {'application_type',
                                                                'client_id',
                                                                'client_id_issued_at',
                                                                'client_registration_types',
                                                                'client_secret',
                                                                'client_secret_expires_at',
                                                                'default_max_age',
                                                                'grant_types',
                                                                'id_token_signed_response_alg',
                                                                'jwks',
                                                                'redirect_uris',
                                                                'request_object_signing_alg',
                                                                'response_modes',
                                                                'response_types',
                                                                'subject_type',
                                                                'token_endpoint_auth_method',
                                                                'token_endpoint_auth_signing_alg',
                                                                'userinfo_signed_response_alg'}

        response["metadata"]["openid_relying_party"]["scope"] = "openid profile"

        self.registration_service.update_service_context(response)
        # There is a client secret
        assert self.rp["openid_relying_party"].context.claims.get_usage("client_secret")
        _keys = self.rp["openid_relying_party"].context.keyjar.get_signing_key(key_type="oct")
        assert len(_keys) == 2

        assert self.rp["openid_relying_party"].context.claims.get_usage("scope") == ["openid", "profile"]

        # Create a authorization request
        req_args = {
            "state": "ABCDE",
            "nonce": "nonce",
        }

        self.rp["openid_relying_party"].get_context().cstate.set("ABCDE", {"iss": "issuer"})

        msg = self.rp["openid_relying_party"].get_service("authorization").construct(request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)

        _jws = factory(jws)
        reg_uris = _jws.jwt.payload()["metadata"]["openid_relying_party"]["redirect_uris"]
        assert msg["redirect_uri"] in reg_uris

    @pytest.mark.parametrize(
        "token_transform,error_cls",
        [
            (
                lambda token: replace_protected_header(token, remove="typ"),
                FederationJwtHeaderError,
            ),
            (
                lambda token: replace_protected_header(token, typ=TRUST_MARK.typ),
                FederationJwtHeaderError,
            ),
            (
                lambda token: replace_protected_header(token, remove="kid"),
                FederationJwtHeaderError,
            ),
            (corrupt_signature, FederationJwtSignatureError),
        ],
        ids=("missing-typ", "sibling-typ", "missing-kid", "invalid-signature"),
    )
    def test_registration_consumer_rejects_invalid_response(
        self,
        token_transform,
        error_cls,
    ):
        token, request, _request_jwt = self._registration_response()

        with responses.RequestsMock() as rsps:
            with pytest.raises(error_cls):
                self.registration_service.parse_response(
                    token_transform(token),
                    request=request,
                )

            assert not rsps.calls

    def test_metadata_verifier_receives_original_response_token(self):
        token, request, _request_jwt = self._registration_response()
        expected = {"metadata": {"openid_relying_party": {"verified": True}}}
        verifier = RecordingMetadataVerifier(expected)
        self.rp["federation_entity"].function.metadata_verifier = verifier

        with responses.RequestsMock() as rsps:
            result = self.registration_service.parse_response(token, request=request)

            assert not rsps.calls

        assert verifier.tokens == [token]
        assert result is expected
