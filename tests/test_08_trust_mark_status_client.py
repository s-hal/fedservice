"""Bound Trust Mark Status POSTs through actual client and CLI dispatch."""

import json
from pathlib import Path
import runpy
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.client.client_auth import BearerHeader
from idpyoidc.client.exception import Unsupported
from idpyoidc.client.exception import WrongContentType
import pytest
import responses

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.registry import TRUST_MARK
from fedservice.federation_jwt.registry import TRUST_MARK_STATUS_RESPONSE
from fedservice.message import TrustMarkStatusResponse
from fedservice.trust_mark_entity.server.trust_mark_status import create_trust_mark_status_response
from fedservice.utils import make_federation_entity
from tests.test_55_entity_statement_subject_binding import corrupt_signature


ISSUER = "https://issuer.example.org"
OTHER = "https://other.example.org"
ANCHOR = "https://anchor.example.org"
SUBJECT = "https://subject.example.org"
MARK_TYPE = "https://marks.example.org/type"
ENDPOINT = ISSUER + "/status?tenant=one"
SCRIPT = Path(__file__).resolve().parents[1] / "script" / "get_trust_mark_status.py"


@pytest.fixture(scope="module")
def jar():
    keys = KeyJar()
    for index, owner in enumerate((ISSUER, OTHER, ANCHOR)):
        keys.add_keys(owner, [new_ec_key(crv="P-256", kid="status-{}".format(index), use="sig")])
    return keys


@pytest.fixture
def peer(jar):
    def mark(issuer=ISSUER, tag="first"):
        return sign_federation_jwt(
            TRUST_MARK, {"sub": SUBJECT, "trust_mark_type": MARK_TYPE, "tag": tag},
            jar, issuer, "ES256")

    def status(token, value="active", issuer=ISSUER):
        return create_trust_mark_status_response(jar, issuer, token, value, signing_alg="ES256")

    return SimpleNamespace(mark=mark, status=status)


@pytest.fixture
def client(jar):
    entity = make_federation_entity(
        "https://client.example.org", services=["trust_mark_status"],
        endpoints=["entity_configuration"], signing_alg="ES256",
        key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]})
    for owner in (ISSUER, OTHER):
        entity.keyjar.import_jwks(jar.export_jwks(issuer_id=owner), owner)
    return entity.client


def request(client, mark, **kwargs):
    options = dict(request_args={"trust_mark": mark}, entity_id=ISSUER, endpoint=ENDPOINT)
    options.update(kwargs)
    return client.do_request("trust_mark_status", **options)


def respond(http, token, endpoint=ENDPOINT, content_type=TRUST_MARK_STATUS_RESPONSE.content_type):
    http.add("POST", endpoint, body=token, status=200, content_type=content_type)


@pytest.mark.parametrize("status", ["active", "expired", "revoked", "invalid"])
@pytest.mark.parametrize("foreign_mark_issuer", [False, True])
def test_bound_post_and_status_values(peer, client, status, foreign_mark_issuer):
    mark = peer.mark(OTHER if foreign_mark_issuer else ISSUER)
    with responses.RequestsMock() as http:
        respond(http, peer.status(mark, status))
        result = request(client, mark)
        outgoing = http.calls[0].request
    assert isinstance(result, TrustMarkStatusResponse)
    assert result["iss"] == ISSUER
    assert result["trust_mark"] == mark
    assert result["status"] == status
    assert outgoing.method == "POST"
    assert outgoing.url == ENDPOINT
    assert outgoing.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert parse_qs(outgoing.body) == {"trust_mark": [mark]}
    assert parse_qs(urlsplit(outgoing.url).query) == {"tenant": ["one"]}
    assert not any(key.startswith("expected_") for key in outgoing.headers)


@pytest.mark.parametrize("case", ["issuer", "endpoint", "empty_mark", "non_string", "malformed",
                                  "tuple", "get", "aliases", "encoding"])
def test_bad_requests_fail_before_http(peer, client, case):
    options = dict(entity_id=ISSUER, endpoint=ENDPOINT, request_args={"trust_mark": peer.mark()})
    if case in ("issuer", "endpoint"):
        del options["entity_id" if case == "issuer" else "endpoint"]
    elif case == "tuple":
        options["request_args"] = {"sub": SUBJECT, "trust_mark_type": MARK_TYPE}
    elif case in ("empty_mark", "non_string", "malformed"):
        options["request_args"]["trust_mark"] = {"empty_mark": "", "non_string": None, "malformed": "not-a-jwt"}[case]
    elif case == "get":
        options["method"] = "GET"
    elif case == "aliases":
        options["fetch_endpoint"] = OTHER + "/status"
    else:
        options["request_body_type"] = "json"
    with responses.RequestsMock() as http:
        with pytest.raises(ValueError):
            client.do_request("trust_mark_status", **options)
        assert not http.calls


def test_issuer_and_endpoint_aliases(peer, client):
    mark = peer.mark()
    with responses.RequestsMock() as http:
        respond(http, peer.status(mark))
        result = client.do_request("trust_mark_status", issuer=ISSUER, fetch_endpoint=ENDPOINT,
                                   request_args={"trust_mark": mark})
    assert result["trust_mark"] == mark
    info = client.get_service("trust_mark_status").get_request_parameters(
        request_args={"trust_mark": mark}, entity_id=ISSUER, endpoint=ENDPOINT, fetch_endpoint=ENDPOINT)
    assert info["url"] == ENDPOINT


@pytest.mark.parametrize("configured_default", [False, True])
def test_real_authentication_header_is_retained(peer, client, configured_default):
    service = client.get_service("trust_mark_status")
    service.client_authn_methods = {"bearer_header": BearerHeader()}
    if configured_default:
        service.default_authn_method = "bearer_header"
    mark = peer.mark()
    with responses.RequestsMock() as http:
        respond(http, peer.status(mark))
        request(client, mark, authn_method="" if configured_default else "bearer_header",
                access_token="synthetic-status-test-token")
        assert http.calls[0].request.headers["Authorization"] == "Bearer synthetic-status-test-token"
        assert parse_qs(http.calls[0].request.body) == {"trust_mark": [mark]}
    with pytest.raises(Unsupported):
        request(client, mark, authn_method="unsupported-test-method")


@pytest.mark.parametrize("case,error", [
    ("issuer", FederationJwtPayloadError), ("mark", FederationJwtPayloadError),
    ("signature", FederationJwtSignatureError), ("typ", FederationJwtHeaderError),
    ("media", WrongContentType), ("missing_media", WrongContentType),
    ("unsigned", ValueError),
])
def test_unacceptable_response_does_not_update_success(peer, client, jar, monkeypatch, case, error):
    mark = peer.mark()
    response_mark = peer.mark(tag="second") if case == "mark" else mark
    issuer = OTHER if case == "issuer" else ISSUER
    token = peer.status(response_mark, issuer=issuer)
    if case in ("issuer", "mark"):
        verified = verify_federation_jwt(TRUST_MARK_STATUS_RESPONSE, token, client.get_attribute("keyjar"))
        assert verified.claims()["iss"] == issuer
        if case == "mark":
            assert response_mark != mark
            first = verify_federation_jwt(TRUST_MARK, mark, jar).claims()
            second = verify_federation_jwt(TRUST_MARK, response_mark, jar).claims()
            assert first["sub"] == second["sub"] and first["trust_mark_type"] == second["trust_mark_type"]
    content_type = TRUST_MARK_STATUS_RESPONSE.content_type
    if case == "signature":
        token = corrupt_signature(token)
    elif case == "typ":
        token = mark
    elif case == "media":
        content_type = "application/json"
    elif case == "missing_media":
        content_type = None
    elif case == "unsigned":
        token = json.dumps({"iss": ISSUER, "iat": utc_time_sans_frac(), "trust_mark": mark, "status": "active"})
    service = client.get_service("trust_mark_status")
    update = Mock(wraps=service.update_service_context)
    monkeypatch.setattr(service, "update_service_context", update)
    with responses.RequestsMock() as http:
        respond(http, token, content_type=content_type)
        with pytest.raises(error):
            request(client, mark)
        if case == "missing_media":
            assert "Content-Type" not in http.calls[0].response.headers
    update.assert_not_called()


@pytest.mark.parametrize("missing", ["expected_issuer", "expected_trust_mark"])
def test_direct_parse_requires_context(peer, client, missing):
    mark = peer.mark()
    context = dict(expected_issuer=ISSUER, expected_trust_mark=mark)
    del context[missing]
    with pytest.raises(ValueError):
        client.get_service("trust_mark_status").parse_response(peer.status(mark), **context)


def test_interleaved_contexts_and_json_errors(peer, client, monkeypatch):
    service = client.get_service("trust_mark_status")
    first_mark, second_mark = peer.mark(), peer.mark(OTHER)
    args = {"trust_mark": first_mark}
    first = service.get_request_parameters(request_args=args, endpoint=ENDPOINT, entity_id=ISSUER)
    second = service.get_request_parameters(request_args={"trust_mark": second_mark},
                                            endpoint=OTHER + "/status", entity_id=OTHER)
    args["trust_mark"] = second_mark
    update = Mock(wraps=service.update_service_context)
    monkeypatch.setattr(service, "update_service_context", update)
    with responses.RequestsMock() as http:
        respond(http, peer.status(second_mark, issuer=OTHER), OTHER + "/status")
        respond(http, peer.status(first_mark))
        last = client.service_request(service, response_body_type="jwt", **second)
        initial = client.service_request(service, response_body_type="jwt", **first)
        assert initial["trust_mark"] == first_mark
        assert last["trust_mark"] == second_mark
        respond(http, peer.status(second_mark))
        with pytest.raises(FederationJwtPayloadError, match="trust_mark"):
            client.service_request(service, response_body_type="jwt", **first)
        http.add("POST", ENDPOINT, status=400, json={"error": "invalid_request"})
        assert request(client, first_mark)["error"] == "System error"
    assert update.call_count == 2
    assert service.parse_response('{"error":"invalid_request"}', sformat="json")["error"] == "invalid_request"
    with pytest.raises(ValueError, match="compact JWT"):
        service.parse_response('{"status":"active"}', sformat="json")


def cli_paths(jar, direct=True):
    now = utc_time_sans_frac()
    public = {owner: jar.export_jwks(issuer_id=owner) for owner in (ISSUER, ANCHOR)}
    common = dict(iat=now - 10, exp=now + 3600)
    issuer = dict(common, iss=ISSUER, sub=ISSUER, jwks=public[ISSUER], authority_hints=[ANCHOR],
                  metadata={"federation_entity": {"federation_trust_mark_status_endpoint": ENDPOINT} if direct else {}})
    anchor = dict(common, iss=ANCHOR, sub=ANCHOR, jwks=public[ANCHOR],
                  metadata={"federation_entity": {"federation_fetch_endpoint": ANCHOR + "/fetch"}})
    statement = dict(common, iss=ANCHOR, sub=ISSUER, jwks=public[ISSUER])
    if not direct:
        statement["metadata_policy"] = {"federation_entity": {
            "federation_trust_mark_status_endpoint": {"value": ENDPOINT}}}
    result = {}
    for owner, claims, profile, url in (
        (ISSUER, issuer, ENTITY_CONFIGURATION, ISSUER + "/.well-known/openid-federation"),
        (ANCHOR, anchor, ENTITY_CONFIGURATION, ANCHOR + "/.well-known/openid-federation"),
        (ANCHOR, statement, SUBORDINATE_STATEMENT, ANCHOR + "/fetch?sub=" + ISSUER),
    ):
        result[url] = sign_federation_jwt(profile, claims, jar, owner, "ES256", iat=common["iat"])
    return result


@pytest.mark.parametrize("case", ["valid", "anchor_issuer", "policy_only", "invalid_mark", "empty_file", "missing_file"])
def test_cli_uses_mark_file_and_direct_authenticated_ec(peer, jar, tmp_path, monkeypatch, capsys, case):
    mark = peer.mark()
    mark_file = tmp_path / "mark.jwt"
    if case != "missing_file":
        mark_file.write_text("" if case == "empty_file" else "not-a-jwt" if case == "invalid_mark" else "\n " + mark + " \n", encoding="utf-8")
    anchors = tmp_path / "anchors.json"
    anchor = ISSUER if case == "anchor_issuer" else ANCHOR
    anchors.write_text(json.dumps({anchor: jar.export_jwks(issuer_id=anchor)}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", [str(SCRIPT), "--trust-mark-file", str(mark_file),
                                   "-t", str(anchors), ISSUER])
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        for url, token in cli_paths(jar, direct=case != "policy_only").items():
            http.add("GET", url, body=token, content_type=ENTITY_CONFIGURATION.content_type)
        respond(http, peer.status(mark))
        if case in ("valid", "anchor_issuer"):
            runpy.run_path(str(SCRIPT), run_name="__main__")
            posts = [call.request for call in http.calls if call.request.method == "POST"]
            assert len(posts) == 1
            assert posts[0].url == ENDPOINT
            assert parse_qs(posts[0].body) == {"trust_mark": [mark]}
            assert "active" in capsys.readouterr().out
        else:
            error = FileNotFoundError if case == "missing_file" else SystemExit if case == "empty_file" else ValueError
            with pytest.raises(error):
                runpy.run_path(str(SCRIPT), run_name="__main__")
            assert not any(call.request.method == "POST" for call in http.calls)


def test_cli_help_describes_original_mark_input(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", [str(SCRIPT), "--help"])
    with pytest.raises(SystemExit) as error:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert error.value.code == 0
    text = capsys.readouterr().out
    assert "--trust-mark-file" in text and "UTF-8" in text
    assert "--subject" not in text and "--trust_mark_type" not in text
