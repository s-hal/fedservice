import json
from unittest.mock import Mock

from flask import Flask
import pytest

from dc4eu_federation.trust_anchor.views import do_response as dc4eu_response
from edu_federation.trust_anchor.views import do_response as edu_response
from setup_federation.trust_anchor.views import do_response as setup_response
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from tests.test_entity_server_response import resolver


@pytest.fixture(params=[dc4eu_response, edu_response, setup_response],
                ids=["dc4eu", "edu", "setup"])
def adapter(request):
    return request.param


@pytest.mark.parametrize("error,status,expected", [
    ("invalid_request", 404, 404),
    ("temporarily_unavailable", 503, 503),
    ("invalid_request", 401, 401),
    ("invalid_metadata", 400, 400),
    ("invalid_trust_chain", 400, 400),
    ("", 201, 201),
    ("", 404, 404),
    ("", None, 200),
    ("invalid_request", None, 400),
])
def test_body_status_comes_from_endpoint_envelope(adapter, error, status, expected):
    body = json.dumps({"error": error}) if error else "unchanged-response"
    content_type = "application/json" if error else RESOLVE_RESPONSE.content_type
    info = {"response": body, "http_headers": [("Content-type", content_type)]}
    if status is not None:
        info["response_code"] = status
    endpoint = Mock(response_placement="body")
    endpoint.do_response.return_value = info
    query = {"sub": "https://subject.example.org"}
    with Flask(__name__).test_request_context("/resolve"):
        response = adapter(endpoint, query, error=error)

    endpoint.do_response.assert_called_once_with(request=query, error=error)
    assert response.status_code == expected
    assert response.get_data(as_text=True) == body
    assert response.headers["Content-Type"] == content_type


def test_initialized_resolve_preserves_non_400_error_and_transport_fields(adapter, resolver):
    endpoint = resolver.get_endpoint("resolve")
    with Flask(__name__).test_request_context("/resolve"):
        response = adapter(
            endpoint, {}, error="invalid_request", response_code=404,
            error_description="The requested resource is unavailable.",
            http_headers=[("X-Request-ID", "test-request")],
            cookie=[{"name": "session", "value": "test-session"}],
        )

    assert response.status_code == 404
    assert response.get_json() == {
        "error": "invalid_request",
        "error_description": "The requested resource is unavailable.",
    }
    assert response.headers["Content-Type"] == "application/json"
    assert response.headers["X-Request-ID"] == "test-request"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers.getlist("Set-Cookie") == ["session=test-session; Path=/"]


@pytest.mark.parametrize("error", ["", "invalid_request"])
@pytest.mark.parametrize("explicit_placement", [False, True])
def test_url_placement_keeps_redirect_headers_and_cookies(adapter, error, explicit_placement):
    location = "https://client.example.org/callback?state=request-state"
    info = {
        "response": location,
        "response_code": 404,
        "http_headers": [("X-Request-ID", "redirect-request")],
        "cookie": {"name": "session", "value": "test-session"},
    }
    endpoint = Mock(response_placement="body" if explicit_placement else "url")
    if explicit_placement:
        info["response_placement"] = "url"
    endpoint.do_response.return_value = info
    with Flask(__name__).test_request_context("/resolve"):
        response = adapter(endpoint, {}, error=error)

    assert response.status_code == 302
    assert response.headers["Location"] == location
    assert response.headers["X-Request-ID"] == "redirect-request"
    assert response.headers.getlist("Set-Cookie") == ["session=test-session; Path=/"]
