"""Endpoint-level regression tests for Federation JWT producers."""

import inspect
import json

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory

from fedservice.entity.server.entity_configuration import EntityConfiguration
from fedservice.entity.server.fetch import Fetch
from fedservice.entity.server.resolve import Resolve
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.registry import TRUST_MARK_STATUS_RESPONSE
from fedservice.trust_mark_entity.server import trust_mark_status as trust_mark_status_module
from fedservice.trust_mark_entity.server.trust_mark_status import TrustMarkStatus


ISSUER = "https://issuer.example.org"
SUBJECT = "https://subject.example.org"
TRUST_MARK = "original.compact.trust-mark"


def keyjar_with_signing_key():
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [new_rsa_key(kid="key-1")])
    return key_jar


def content_type(response):
    return dict(response["http_headers"])["Content-type"]


def assert_profile_response(response, profile):
    body = response["response"]

    assert isinstance(body, str)
    assert body.count(".") == 2
    assert jws_factory(body).jwt.headers["typ"] == profile.typ
    assert content_type(response) == profile.content_type
    return body


def test_endpoint_classes_use_canonical_profile_content_types():
    assert EntityConfiguration.response_content_type == ENTITY_CONFIGURATION.content_type
    assert Fetch.response_content_type == SUBORDINATE_STATEMENT.content_type
    assert Resolve.response_content_type == RESOLVE_RESPONSE.content_type
    assert (
        TrustMarkStatus.response_content_type
        == TRUST_MARK_STATUS_RESPONSE.content_type
    )


def test_endpoint_modules_do_not_define_success_media_type_literals():
    modules_and_profiles = [
        (trust_mark_status_module, TRUST_MARK_STATUS_RESPONSE),
    ]

    for module, profile in modules_and_profiles:
        assert profile.content_type not in inspect.getsource(module)


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
