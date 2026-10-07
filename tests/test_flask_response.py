from importlib import import_module
import json
from unittest.mock import Mock

from flask import Flask
from flask import url_for
from idpyoidc.exception import DecodeError
from idpyoidc.exception import FormatError
from idpyoidc.exception import TooManyValues
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server.exception import InvalidClient
from idpyoidc.server.exception import UnknownClient
import pytest

from dc4eu_federation.trust_anchor.views import do_response as dc4eu_response
from edu_federation.trust_anchor.views import do_response as edu_response
from setup_federation.trust_anchor.views import do_response as setup_response
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.jose import verify_federation_jwt
from tests.build_federation import make_entity


@pytest.fixture
def resolver():
    return make_entity(
        "https://resolver.example.org", "trust_anchor", endpoints=["resolve"]
    )


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
    endpoint = Mock(response_placement="body", error_cls=ResponseMessage)
    endpoint.do_response.return_value = info
    query = {"sub": "https://subject.example.org"}
    with Flask(__name__).test_request_context("/resolve"):
        response = adapter(endpoint, query, error=error)

    expected_args = {"response_args": None, "request": query}
    if error:
        expected_args.update(response_msg=body, content_type="application/json")
    endpoint.do_response.assert_called_once_with(**expected_args)
    assert response.status_code == expected
    assert response.get_data(as_text=True) == body
    assert response.headers["Content-Type"] == content_type


@pytest.mark.parametrize("status", [None, 404, 503])
def test_initialized_resolve_preserves_non_400_error_and_transport_fields(adapter, resolver, status):
    endpoint = resolver.get_endpoint("resolve")
    kwargs = {} if status is None else {"response_code": status}
    with Flask(__name__).test_request_context("/resolve"):
        response = adapter(
            endpoint, {}, error="invalid_request",
            error_description="The requested resource is unavailable.",
            http_headers=[("X-Request-ID", "test-request")],
            cookie=[{"name": "session", "value": "test-session"}],
            response_placement="body", **kwargs,
        )

    assert response.status_code == (400 if status is None else status)
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
    endpoint = Mock(response_placement="body" if explicit_placement else "url",
                    error_cls=ResponseMessage)
    if explicit_placement:
        info["response_placement"] = "url"
    endpoint.do_response.return_value = info
    with Flask(__name__).test_request_context("/resolve"):
        response = adapter(endpoint, {}, error=error)

    assert response.status_code == 302
    assert response.headers["Location"] == location
    assert response.headers["X-Request-ID"] == "redirect-request"
    assert response.headers.getlist("Set-Cookie") == ["session=test-session; Path=/"]


def test_list_route_preserves_url_identity_and_protocol_endpoint(adapter):
    app = Flask(__name__)
    app.register_blueprint(import_module(adapter.__module__).entity)
    endpoint = Mock(response_placement="body")
    endpoint.parse_request.return_value = {}
    endpoint.process_request.return_value = {"response_args": {}}
    endpoint.do_response.return_value = {
        "response": '["https://subject.example.org"]',
        "http_headers": [("Content-type", "application/json")],
    }
    app.federation_entity = Mock()
    app.federation_entity.get_endpoint.return_value = endpoint

    with app.test_request_context():
        assert url_for("entity.list") == "/list"
    response = app.test_client().get("/list")

    assert response.status_code == 200
    assert response.get_json() == ["https://subject.example.org"]
    app.federation_entity.get_endpoint.assert_called_once_with("list")
    endpoint.process_request.assert_called_once_with({})


def test_single_valued_fetch_and_list_queries_are_preserved(adapter):
    entity = make_entity("https://ta.example.org", "trust_anchor", endpoints=["fetch", "list"])
    subject = "https://subject.example.org"
    entity.server.subordinate[subject] = {
        "jwks": entity.keyjar.export_jwks(),
        "entity_types": ["federation_entity"],
        "entity_type": ["federation_entity"],
    }
    app = Flask(__name__)
    app.federation_entity = entity
    app.register_blueprint(import_module(adapter.__module__).entity)
    client = app.test_client()
    fetched = client.get("/fetch", query_string={"sub": subject})
    assert fetched.status_code == 200
    assert fetched.mimetype == "application/entity-statement+jwt"
    listed = client.get("/list", query_string={"entity_type": "federation_entity"})
    assert listed.status_code == 200
    assert listed.get_json() == [subject]


@pytest.mark.parametrize("query", [{}, {"sub": "https://subject.example.org"},
                                   {"trust_anchor": "https://ta.example.org"}])
def test_resolve_missing_parameters_stop_before_processing(adapter, resolver, monkeypatch, query):
    endpoint = resolver.get_endpoint("resolve")
    process = Mock(side_effect=AssertionError("invalid request must not reach processing"))
    monkeypatch.setattr(endpoint, "process_request", process)
    app = Flask(__name__)
    app.federation_entity = resolver
    app.register_blueprint(import_module(adapter.__module__).entity)
    response = app.test_client().get("/resolve", query_string=query)
    assert response.status_code == 400
    assert json.loads(response.get_data(as_text=True))["error"] == "invalid_request"
    assert response.mimetype == "application/json"
    process.assert_not_called()


@pytest.mark.parametrize("operation", ["fetch", "resolve"])
@pytest.mark.parametrize("query", [
    "", "sub=", "sub=http://subject.example.org", "sub=not-an-identifier",
    "sub=https%3A%2F%2Fsubject.example.org%23fragment",
    "sub=&sub=https://subject.example.org", "sub=https://subject.example.org&sub=",
    "sub=https://subject.example.org&sub=https://other.example.org",
])
def test_http_admission_errors_are_json(adapter, monkeypatch, operation, query):
    entity = make_entity("https://ta.example.org", "trust_anchor", endpoints=[operation])
    endpoint = entity.get_endpoint(operation)
    process = Mock(side_effect=AssertionError("invalid request reached processing"))
    monkeypatch.setattr(endpoint, "process_request", process)
    app = Flask(__name__)
    app.federation_entity = entity
    app.register_blueprint(import_module(adapter.__module__).entity)
    if operation == "resolve":
        query += "&trust_anchor=https://ta.example.org"
    response = app.test_client().get("/" + operation + "?" + query)
    assert response.status_code == 400
    assert response.mimetype == "application/json"
    assert response.get_json()["error"] == "invalid_request"
    assert response.headers["Cache-Control"] == "no-store"
    process.assert_not_called()


@pytest.mark.parametrize("accept", [None, "application/json", "invalid, ; header"])
def test_http_fetch_success_error_success(adapter, accept):
    entity = make_entity("https://ta.example.org", "trust_anchor", endpoints=["fetch"])
    subject = "https://subject.example.org"
    entity.server.subordinate[subject] = {"jwks": entity.keyjar.export_jwks()}
    app = Flask(__name__)
    app.federation_entity = entity
    app.register_blueprint(import_module(adapter.__module__).entity)
    client = app.test_client()
    headers = {} if accept is None else {"Accept": accept}
    for failed_query, status, error in [
        ("", 400, "invalid_request"),
        ("sub=https://unknown.example.org", 404, "not_found"),
        ("sub=" + entity.entity_id, 400, "invalid_request"),
    ]:
        for query, expected in [("sub=" + subject, 200), (failed_query, status),
                                ("sub=" + subject, 200)]:
            response = client.get("/fetch?" + query, headers=headers)
            assert response.status_code == expected
            if expected == 200:
                assert response.mimetype == SUBORDINATE_STATEMENT.content_type
                verified = verify_federation_jwt(
                    SUBORDINATE_STATEMENT, response.get_data(as_text=True), entity.keyjar)
                assert verified.claims()["sub"] == subject
            else:
                assert response.mimetype == "application/json"
                assert response.get_json()["error"] == error


@pytest.mark.parametrize("exception", [DecodeError, FormatError, TooManyValues, ValueError])
def test_generic_get_parse_error_uses_existing_serializer(adapter, monkeypatch, exception):
    entity = make_entity("https://ta.example.org", "trust_anchor", endpoints=["list"])
    endpoint = entity.get_endpoint("list")
    monkeypatch.setattr(endpoint, "parse_request", Mock(side_effect=exception("bad input")))
    process = Mock()
    monkeypatch.setattr(endpoint, "process_request", process)
    app = Flask(__name__)
    app.federation_entity = entity
    app.register_blueprint(import_module(adapter.__module__).entity)
    response = app.test_client().get("/list?extension=value")
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_request", "error_description": "bad input"}
    assert response.mimetype == "application/json"
    process.assert_not_called()


def test_generic_error_message_preserves_selected_status_and_fields(adapter, monkeypatch):
    entity = make_entity("https://ta.example.org", "trust_anchor", endpoints=["list"])
    endpoint = entity.get_endpoint("list")
    selected = ResponseMessage(
        error="temporarily_unavailable", error_description="try later",
        error_uri="https://ta.example.org/errors/later", state="request-state", response_code=503,
        http_headers=[("Retry-After", "60")], cookie={"name": "session", "value": "test-session"})
    monkeypatch.setattr(endpoint, "parse_request", Mock(return_value=selected))
    process = Mock()
    monkeypatch.setattr(endpoint, "process_request", process)
    app = Flask(__name__)
    app.federation_entity = entity
    app.register_blueprint(import_module(adapter.__module__).entity)
    response = app.test_client().get("/list")
    assert response.status_code == 503
    assert response.get_json() == {
        "error": "temporarily_unavailable", "error_description": "try later",
        "error_uri": "https://ta.example.org/errors/later", "state": "request-state"}
    assert response.mimetype == "application/json"
    assert response.headers["Retry-After"] == "60"
    assert response.headers.getlist("Set-Cookie") == ["session=test-session; Path=/"]
    process.assert_not_called()


@pytest.mark.parametrize("exception", [InvalidClient, UnknownClient])
def test_get_authentication_failure_behavior_is_preserved(adapter, resolver, monkeypatch, exception):
    endpoint = resolver.get_endpoint("resolve")
    monkeypatch.setattr(endpoint, "parse_request", Mock(side_effect=exception("unknown client")))
    process = Mock()
    monkeypatch.setattr(endpoint, "process_request", process)
    app = Flask(__name__)
    app.federation_entity = resolver
    app.register_blueprint(import_module(adapter.__module__).entity)
    response = app.test_client().get("/resolve")
    assert response.status_code == 400
    assert json.loads(response.get_data(as_text=True)) == {
        "error": "unauthorized_client", "error_description": "unknown client"}
    process.assert_not_called()
