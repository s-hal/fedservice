"""List admission and filtering through initialized endpoints and HTTP adapters."""

from copy import deepcopy
from importlib import import_module
import json
from unittest.mock import Mock
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlsplit

from flask import Flask
from idpyoidc.server.client_authn import PublicAuthn
from idpyoidc.server.exception import UnknownClient
import pytest

from fedservice.message import ListRequest
from tests.build_federation import make_entity


FIRST = "https://first.example.org"
SECOND = "https://second.example.org"


@pytest.fixture
def entity():
    result = make_entity("https://ta.example.org", "trust_anchor", endpoints=["list"])
    result.server.subordinate = {
        FIRST: {"entity_type": ["federation_entity"], "intermediate": True},
        SECOND: {"entity_type": ["federation_entity"], "intermediate": False},
    }
    return result


@pytest.fixture(params=["dc4eu_federation", "edu_federation", "setup_federation"])
def client(entity, request):
    app = Flask(__name__)
    app.federation_entity = entity
    app.register_blueprint(import_module(request.param + ".trust_anchor.views").entity)
    return app.test_client()


@pytest.mark.parametrize("query,expected", [
    ("", [FIRST, SECOND]),
    ("intermediate=true", [FIRST]),
    ("intermediate=false", [FIRST, SECOND]),
    ("intermediate=garbage", "invalid_request"),
    ("intermediate=true&intermediate=false", "invalid_request"),
    ("entity_type=federation_entity&entity_type=federation_entity", [FIRST, SECOND]),
    ("entity_type=extension_type", []),
    ("intermediate=", "invalid_request"),
    ("trust_marked=false", "unsupported_parameter"),
    ("trust_marked=true", "unsupported_parameter"),
    ("trust_mark_type=example&intermediate=true", "unsupported_parameter"),
    ("trust_marked=garbage", "invalid_request"),
    ("trust_mark_type=a&trust_mark_type=a", "invalid_request"),
])
def test_list_http_contract(client, entity, monkeypatch, query, expected):
    endpoint = entity.get_endpoint("list")
    collect = Mock(side_effect=AssertionError("List must not fetch subordinate ECs"))
    monkeypatch.setattr(endpoint, "collect_subordinates", collect)
    for accept in (None, "application/jose", "invalid, ; header"):
        headers = {} if accept is None else {"Accept": accept}
        response = client.get("/list?" + query, headers=headers)
        assert response.mimetype == "application/json"
        if isinstance(expected, list):
            assert response.status_code == 200
            assert sorted(response.get_json()) == sorted(expected)
        else:
            assert response.status_code == 400
            assert response.get_json()["error"] == expected
            assert response.get_json()["error_description"]
    collect.assert_not_called()


@pytest.mark.parametrize("storage", ["entity_type", "entity_types"])
@pytest.mark.parametrize("intermediate", [None, False, True])
@pytest.mark.parametrize("representation", ["query", "dict", "message"])
def test_list_repeated_types_union_and_filter_intersection(
        entity, storage, intermediate, representation):
    third, fourth = "https://third.example.org", "https://fourth.example.org"
    entity.server.subordinate = {
        FIRST: {storage: ["A"], "intermediate": True},
        SECOND: {storage: ["B"], "intermediate": False},
        third: {storage: ["A", "B"], "intermediate": True},
        fourth: {storage: ["neither"], "intermediate": True},
    }
    before = deepcopy(entity.server.subordinate)
    values = {"entity_type": ["A", "B", "A"]}
    if intermediate is not None:
        values["intermediate"] = intermediate if representation != "query" else str(intermediate).lower()
    if representation == "query":
        source = urlencode(values, doseq=True)
    elif representation == "message":
        source = ListRequest(**values)
    else:
        source = values
    endpoint = entity.get_endpoint("list")
    parsed = endpoint.parse_request(source)
    assert isinstance(parsed, ListRequest)
    assert parsed["entity_type"] == ["A", "B", "A"]
    result = json.loads(endpoint.process_request(parsed)["response_msg"])
    assert sorted(result) == sorted([FIRST, third] if intermediate else [FIRST, SECOND, third])
    assert len(result) == len(set(result))
    assert entity.server.subordinate == before


@pytest.mark.parametrize("value,expected", [
    (True, [FIRST]), (False, [FIRST, SECOND]), ("true", [FIRST]),
    ("false", [FIRST, SECOND]), (["true"], [FIRST]), ([False], [FIRST, SECOND]),
])
def test_list_local_boolean_normalization(entity, value, expected):
    endpoint = entity.get_endpoint("list")
    source = {"intermediate": value}
    before = deepcopy(source)
    parsed = endpoint.parse_request(source)
    assert isinstance(parsed["intermediate"], bool)
    assert sorted(json.loads(endpoint.process_request(parsed)["response_msg"])) == sorted(expected)
    assert source == before


@pytest.mark.parametrize("value", ["", "garbage", "True", "FALSE", "1", 0, 1, None,
                                   [], [True, True], ["false", "false"], {}, (True,)])
@pytest.mark.parametrize("field", ["intermediate", "trust_marked"])
def test_list_invalid_local_booleans(entity, field, value):
    result = entity.get_endpoint("list").parse_request({field: value})
    assert result["error"] == "invalid_request"
    assert field in result["error_description"]


@pytest.mark.parametrize("field,value", [
    ("entity_type", ""), ("entity_type", []), ("entity_type", [""]),
    ("entity_type", ["A", ""]), ("entity_type", ["A", 2]),
    ("entity_type", None), ("entity_type", True), ("entity_type", 2),
    ("entity_type", {"A": True}), ("entity_type", ("A",)),
    ("trust_mark_type", ""), ("trust_mark_type", []), ("trust_mark_type", None),
    ("trust_mark_type", ["a", "a"]), ("trust_mark_type", 3),
    ("trust_mark_type", {"a": True}),
])
def test_list_invalid_local_identifiers(entity, field, value):
    result = entity.get_endpoint("list").parse_request({field: value})
    assert result["error"] == "invalid_request"
    assert field in result["error_description"]


@pytest.mark.parametrize("query", [
    "intermediate", "intermediate=true&intermediate=true", "intermediate=&intermediate=true",
    "intermediate=True", "intermediate=False", "trust_marked=True", "trust_marked=False",
    "trust_marked", "trust_marked=false&trust_marked=false", "trust_marked=&trust_marked=true",
    "entity_type", "entity_type=A&entity_type=", "entity_type=&entity_type=A",
    "trust_mark_type", "trust_mark_type=&trust_mark_type=a", "trust_mark_type=a&trust_mark_type=a",
])
def test_list_invalid_queries_stop_before_lookup(entity, monkeypatch, query):
    endpoint = entity.get_endpoint("list")
    post_parse = Mock(side_effect=AssertionError("invalid input reached post-parse callback"))
    monkeypatch.setattr(endpoint, "post_parse_request", [post_parse])
    result = endpoint.parse_request(query)
    assert result["error"] == "invalid_request"
    assert result["error_description"]
    post_parse.assert_not_called()


@pytest.mark.parametrize("filters", [
    {"trust_marked": False}, {"trust_marked": True}, {"trust_mark_type": "not-a-uri"},
    {"trust_marked": "false", "entity_type": "federation_entity", "intermediate": True},
    {"trust_mark_type": ["example"], "trust_marked": False},
])
@pytest.mark.parametrize("extended", [False, True])
def test_list_unsupported_trust_mark_filters_do_not_collect(entity, monkeypatch, filters, extended):
    endpoint = entity.get_endpoint("list")
    endpoint.extended = extended
    collect = Mock(side_effect=AssertionError("unsupported filter must not collect"))
    monkeypatch.setattr(endpoint, "collect_subordinates", collect)
    result = endpoint.process_request(endpoint.parse_request(filters))
    assert result["error"] == "unsupported_parameter"
    assert result["response_code"] == 400
    assert any(name in result["error_description"] for name in filters if name.startswith("trust_mark"))
    assert "response_msg" not in result
    collect.assert_not_called()


@pytest.mark.parametrize("field,record", [
    ("entity_type", {}), ("entity_type", {"entity_type": None}),
    ("entity_type", {"entity_types": "A"}), ("entity_type", {"entity_types": [1]}),
    ("intermediate", {}), ("intermediate", {"intermediate": "true"}),
])
def test_list_missing_registration_information_is_unsupported(client, entity, field, record):
    entity.server.subordinate[SECOND] = record
    response = client.get("/list", query_string={field: "true" if field == "intermediate" else "A"})
    assert response.status_code == 400
    assert response.mimetype == "application/json"
    assert response.get_json()["error"] == "unsupported_parameter"
    assert field in response.get_json()["error_description"]


def test_list_empty_database_and_nonmatching_types_are_arrays(client, entity):
    for records, query in [({}, ""), ({}, "intermediate=true"), ({}, "entity_type=A"),
                           ({FIRST: {"entity_types": []}}, "entity_type=A")]:
        entity.server.subordinate = records
        response = client.get("/list?" + query)
        assert response.status_code == 200
        assert response.mimetype == "application/json"
        assert response.get_json() == []


def test_list_keeps_authentication_verification_and_callbacks(entity, monkeypatch):
    endpoint = entity.get_endpoint("list")
    auth = Mock(return_value={"client_id": "local-client", "method": "client_secret_basic"})
    monkeypatch.setattr(endpoint, "client_authentication", auth)
    verify = Mock(wraps=endpoint.verify_request)
    monkeypatch.setattr(endpoint, "verify_request", verify)
    post = Mock(side_effect=lambda request, *args, **kwargs: request)
    monkeypatch.setattr(endpoint, "post_parse_request", [post])
    parsed = endpoint.parse_request("intermediate=false")
    assert isinstance(parsed, ListRequest)
    assert parsed["client_id"] == "local-client"
    assert parsed["authenticated"] is True
    assert sorted(json.loads(endpoint.process_request(parsed)["response_msg"])) == [FIRST, SECOND]
    auth.assert_called_once()
    verify.assert_called_once()
    post.assert_called_once()
    failure = ValueError("unexpected callback failure")
    post.side_effect = failure
    with pytest.raises(ValueError) as error:
        endpoint.parse_request("intermediate=false")
    assert error.value is failure


@pytest.mark.parametrize("filters", [{"entity_type": "federation_entity"},
                                     {"entity_type": ["federation_entity"]}, {}])
def test_list_direct_local_requests(entity, filters):
    result = entity.get_endpoint("list").process_request(filters)
    assert sorted(json.loads(result["response_msg"])) == [FIRST, SECOND]


def test_list_direct_invalid_request_is_rejected(entity):
    result = entity.get_endpoint("list").process_request({"intermediate": "garbage"})
    assert result["error"] == "invalid_request"
    assert result["response_code"] == 400


def test_list_accepts_registration_type_key_views(entity):
    # get_subordinate_info() uses Combo.keys(), not a wire-format JSON array.
    entity.server.subordinate = {FIRST: {"entity_types": {"A": object(), "B": object()}.keys()}}
    endpoint = entity.get_endpoint("list")
    parsed = endpoint.parse_request("entity_type=B")
    assert json.loads(endpoint.process_request(parsed)["response_msg"]) == [FIRST]


def test_list_unknown_filter_is_unsupported_but_authentication_fields_are_not(entity):
    endpoint = entity.get_endpoint("list")
    result = endpoint.process_request(endpoint.parse_request("unknown_filter=true"))
    assert result["error"] == "unsupported_parameter"
    assert result["response_code"] == 400
    assert "unknown_filter" in result["error_description"]
    result = endpoint.process_request({"client_id": "local-client", "authenticated": True})
    assert sorted(json.loads(result["response_msg"])) == [FIRST, SECOND]


@pytest.fixture
def public_endpoint(entity, monkeypatch):
    endpoint = entity.get_endpoint("list")
    context = endpoint.upstream_get("context")
    monkeypatch.setattr(context, "cdb", {
        "local-client": {"client_id": "local-client", "client_authn_method": ["public"]},
    }, raising=False)
    monkeypatch.setattr(context, "client_authn_methods", {
        "public": PublicAuthn(endpoint.upstream_get),
    })
    monkeypatch.setattr(endpoint, "client_authn_method", ["public"])
    return endpoint


@pytest.mark.parametrize("source", [
    {"client_id": "local-client", "intermediate": False},
    "client_id=local-client&intermediate=false",
])
def test_list_real_public_authentication(public_endpoint, source):
    observed = []

    def post_parse(request, client_id, **kwargs):
        observed.append((request.to_dict(), client_id, kwargs["auth_info"]))
        return request

    public_endpoint.post_parse_request.append(post_parse)
    parsed = public_endpoint.parse_request(source)
    expected = {"client_id": "local-client", "intermediate": False}
    assert isinstance(parsed, ListRequest)
    assert parsed.to_dict() == expected
    assert isinstance(parsed["client_id"], str)
    assert observed == [(expected, "local-client", {
        "client_id": "local-client", "method": "public",
    })]
    context = public_endpoint.upstream_get("context")
    assert context.cdb["local-client"]["auth_method"] == {"ListRequest": "public"}
    result = public_endpoint.process_request(parsed)
    assert sorted(json.loads(result["response_msg"])) == [FIRST, SECOND]


@pytest.mark.parametrize("source", [
    {"client_id": "unknown-client", "intermediate": False},
    "client_id=unknown-client&intermediate=false",
])
def test_list_real_public_authentication_rejects_unknown_client(public_endpoint, source):
    post_parse = Mock(side_effect=AssertionError("unknown client reached post-parse callback"))
    public_endpoint.post_parse_request.append(post_parse)
    with pytest.raises(UnknownClient, match="Unknown Client ID"):
        public_endpoint.parse_request(source)
    post_parse.assert_not_called()


@pytest.mark.parametrize("field", ["intermediate", "trust_marked"])
@pytest.mark.parametrize("value,wire_value,expected", [
    (True, "true", True), (False, "false", False),
    ("true", "true", True), ("false", "false", False),
])
def test_list_boolean_wire_round_trip(field, value, wire_value, expected):
    source = {field: value, "entity_type": ["openid_provider", "openid_relying_party"]}
    before = deepcopy(source)
    request = ListRequest(**source)
    expected_values = {field: expected, "entity_type": ["openid_provider", "openid_relying_party"]}
    assert request.to_dict() == expected_values

    query = request.to_urlencoded()
    assert parse_qs(query) == {
        field: [wire_value], "entity_type": ["openid_provider", "openid_relying_party"],
    }
    parsed = ListRequest().from_urlencoded(query)
    assert parsed[field] is expected
    assert parsed.to_dict() == expected_values
    assert dict(request) == expected_values
    assert request.to_dict() == expected_values
    assert json.loads(request.to_json()) == expected_values
    assert source == before


@pytest.fixture
def list_service():
    entity = make_entity("https://client.example.org", "trust_anchor", services=["list"])
    return entity.get_service("list")


@pytest.mark.parametrize("filters,expected_query,expected", [
    ({"intermediate": True}, {"intermediate": ["true"]}, [FIRST]),
    ({"intermediate": False}, {"intermediate": ["false"]}, [FIRST, SECOND]),
    ({}, {}, [FIRST, SECOND]),
    ({"trust_marked": True}, {"trust_marked": ["true"]}, "unsupported_parameter"),
    ({"trust_marked": False}, {"trust_marked": ["false"]}, "unsupported_parameter"),
])
def test_list_client_wire_request(client, entity, list_service, monkeypatch,
                                  filters, expected_query, expected):
    collect = Mock(side_effect=AssertionError("List must not fetch subordinate ECs"))
    monkeypatch.setattr(entity.get_endpoint("list"), "collect_subordinates", collect)
    before = deepcopy(filters)
    parameters = list_service.get_request_parameters(
        endpoint="https://ta.example.org/list", **filters
    )
    assert parameters["method"] == "GET"
    response = client.get(parameters["url"])
    assert response.mimetype == "application/json"
    if isinstance(expected, list):
        assert response.status_code == 200
        assert sorted(response.get_json()) == expected
    else:
        assert response.status_code == 400
        assert response.get_json()["error"] == expected
    assert parse_qs(urlsplit(parameters["url"]).query) == expected_query
    assert filters == before
    collect.assert_not_called()
