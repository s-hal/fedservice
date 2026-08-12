"""Profile-backed response media types for registration endpoints."""

import inspect

import pytest

from fedservice.appserver.oauth2.registration import Registration as OAuthRegistration
from fedservice.appserver.oidc.registration import Registration as OIDCRegistration
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION


@pytest.mark.parametrize(
    "endpoint_class",
    [OAuthRegistration, OIDCRegistration],
    ids=["oauth2", "oidc"],
)
def test_registration_response_content_type_comes_from_profile(endpoint_class):
    assert endpoint_class.response_content_type == ENTITY_CONFIGURATION.content_type

    source = inspect.getsource(endpoint_class)
    assert "response_content_type = ENTITY_CONFIGURATION.content_type" in source
    assert 'response_content_type = "application/entity-statement+jwt"' not in source


@pytest.mark.parametrize(
    "endpoint_class",
    [OAuthRegistration, OIDCRegistration],
    ids=["oauth2", "oidc"],
)
def test_registration_response_msg_uses_profile_content_type(endpoint_class):
    endpoint = object.__new__(endpoint_class)
    token = "signed-registration-response"

    response = endpoint.do_response(response_msg=token)

    assert response["response"] == token
    assert (
        "Content-type",
        ENTITY_CONFIGURATION.content_type,
    ) in response["http_headers"]
