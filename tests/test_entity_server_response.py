import json
from unittest.mock import Mock

from idpyoidc.message.oauth2 import ResponseMessage
import pytest

from fedservice.entity.server.response import do_response
from fedservice.entity_statement.create import create_resolve_response
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from tests.build_federation import make_entity
from tests.test_57_resolve import compact_trust_chain
from tests.test_57_resolve import future_expiration
from tests.test_57_resolve import resolve_metadata


@pytest.fixture
def resolver():
    return make_entity(
        "https://resolver.example.org", "trust_anchor", endpoints=["resolve"]
    )


@pytest.mark.parametrize("status", [None, 404, 503])
def test_error_status_and_optional_claims(resolver, status):
    endpoint = resolver.get_endpoint("resolve")
    claims = {
        "error": "invalid_request",
        "error_description": "The requested resource is unavailable.",
        "error_uri": "https://resolver.example.org/errors/unavailable",
        "state": "request-state",
    }
    kwargs = {} if status is None else {"response_code": status}
    result = do_response(endpoint, **claims, **kwargs)

    assert json.loads(result["response"]) == claims
    assert [h for h in result["http_headers"] if h[0].lower() == "content-type"] == [
        ("Content-type", "application/json")
    ]
    if status is None:
        assert "response_code" not in result
    else:
        assert result["response_code"] == status


def test_error_uses_endpoint_error_class_without_optional_claims(resolver, monkeypatch):
    endpoint = resolver.get_endpoint("resolve")

    class CustomError(ResponseMessage):
        """Distinguish the configured error message from the generic default."""

        def to_json(self, **kwargs):
            self["custom_error"] = True
            return super(CustomError, self).to_json(**kwargs)

    factory = Mock(side_effect=CustomError)
    monkeypatch.setattr(endpoint, "error_cls", factory)
    result = do_response(endpoint, error="invalid_request")

    factory.assert_called_once_with(error="invalid_request")
    assert json.loads(result["response"]) == {
        "error": "invalid_request", "custom_error": True
    }
    assert "response_code" not in result


@pytest.mark.parametrize("placement", ["body", "url"])
def test_error_preserves_envelope_and_replaces_all_content_types(resolver, placement):
    endpoint = resolver.get_endpoint("resolve")
    headers = [
        ("Content-Type", RESOLVE_RESPONSE.content_type),
        ("content-type", "text/html"),
        ("CONTENT-TYPE", "application/jose"),
        ("Content-type", "text/plain"),
        ("X-Request-ID", "request-id"),
        ("Retry-After", "60"),
    ]
    original_headers = list(headers)
    cookies = [{"name": "session", "value": "test-session"}]
    result = do_response(
        endpoint, error="temporarily_unavailable", response_code=503,
        http_headers=headers, cookie=cookies, response_placement=placement,
        content_type=RESOLVE_RESPONSE.content_type,
    )

    assert result["response_code"] == 503
    assert result["response_placement"] == placement
    assert result["cookie"] == cookies
    assert result["http_headers"] == [
        ("X-Request-ID", "request-id"),
        ("Retry-After", "60"),
        ("Content-type", "application/json"),
        ("Pragma", "no-cache"),
        ("Cache-Control", "no-store"),
    ]
    assert headers == original_headers


def test_resolve_success_error_success_keeps_original_token_and_settings(resolver):
    endpoint = resolver.get_endpoint("resolve")
    token = create_resolve_response(
        resolver.entity_id, sub="https://subject.example.org",
        key_jar=resolver.get_attribute("keyjar"), metadata=resolve_metadata(),
        trust_chain=compact_trust_chain(), expires_at=future_expiration(),
    )
    before = do_response(endpoint, response_args=token)
    failure = do_response(endpoint, error="invalid_request", response_code=404)
    after = do_response(endpoint, response_args=token)

    assert before == after
    assert after["response"] == token
    assert "response_code" not in after
    assert ("Content-type", RESOLVE_RESPONSE.content_type) in after["http_headers"]
    assert json.loads(failure["response"]) == {"error": "invalid_request"}
    assert failure["response_code"] == 404
    assert endpoint.response_content_type == RESOLVE_RESPONSE.content_type
    assert endpoint.response_format == "jose"


@pytest.mark.parametrize("error", ["", "invalid_request"])
def test_shared_response_delegates_to_endpoint_method(resolver, monkeypatch, error):
    endpoint = resolver.get_endpoint("resolve")
    delegated = Mock(wraps=endpoint.do_response)
    monkeypatch.setattr(endpoint, "do_response", delegated)
    request = {"sub": "https://subject.example.org"}
    result = do_response(
        endpoint, response_args="original-body", request=request, error=error,
        response_code=202, cookie={"name": "session", "value": "test-session"},
    )

    delegated.assert_called_once()
    args = delegated.call_args[1]
    assert args["request"] is request
    assert args["response_args"] == "original-body"
    assert args["response_code"] == 202
    assert args["cookie"] == {"name": "session", "value": "test-session"}
    assert "error" not in args
    if error:
        assert json.loads(args["response_msg"]) == {"error": error}
        assert args["content_type"] == "application/json"
    else:
        assert "response_msg" not in args
        assert "content_type" not in args
        assert result["response"] == "original-body"
