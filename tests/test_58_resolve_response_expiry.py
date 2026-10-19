"""Resolve use deadlines are separate from permitted JWT verification skew."""

from dataclasses import replace
import json
from unittest.mock import Mock

from cryptojwt.jwt import utc_time_sans_frac
import pytest
import responses

from fedservice.entity.client import resolve as resolve_module
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.message import Metadata
from fedservice.message import ResolveResponse
from tests.test_58_resolve_response_binding import client
from tests.test_58_resolve_response_binding import compact
from tests.test_58_resolve_response_binding import keys
from tests.test_58_resolve_response_binding import peer
from tests.test_58_resolve_response_binding import request
from tests.test_58_resolve_response_binding import respond
from tests.test_58_resolve_response_binding import RESOLVER


@pytest.fixture
def clock(monkeypatch):
    current = [utc_time_sans_frac()]
    monkeypatch.setattr(resolve_module, "time", lambda: current[0])
    monkeypatch.setattr("cryptojwt.jwt.utc_time_sans_frac", lambda: int(current[0]))
    monkeypatch.setattr("fedservice.federation_jwt.jose.utc_time_sans_frac", lambda: int(current[0]))
    return current


@pytest.fixture
def update(client, monkeypatch):
    service = client.get_service("resolve")
    spy = Mock(wraps=service.update_service_context)
    monkeypatch.setattr(service, "update_service_context", spy)
    return spy


@pytest.mark.parametrize("fraction", [0, 0.5])
@pytest.mark.parametrize("offset", [-0.125, 0, 0.125, 1, 14])
def test_use_deadline_does_not_change_canonical_leeway(
        peer, keys, client, clock, update, fraction, offset):
    payload = peer.payload()
    payload.update(iat=clock[0] - 60 + fraction, exp=clock[0] + 30 + fraction)
    token = compact(payload, keys[RESOLVER])
    clock[0] = payload["exp"] + offset
    verified = verify_federation_jwt(RESOLVE_RESPONSE, token, client.get_attribute("keyjar"))
    assert verified.raw_token() == token
    assert verified.claims()["exp"] == verified.message()["exp"] == payload["exp"]
    with responses.RequestsMock() as http:
        respond(http, token)
        if offset < 0:
            result = request(client)
            assert isinstance(result, ResolveResponse)
            assert result["exp"] == payload["exp"]
            assert result["iat"] == payload["iat"]
            update.assert_called_once()
        else:
            with pytest.raises(FederationJwtPayloadError, match="Resolve result has expired"):
                request(client)
            update.assert_not_called()
        assert len(http.calls) == 1
    assert verified.claims()["exp"] == payload["exp"]


def test_repeated_response_is_checked_on_each_consumption(peer, keys, client, clock, update):
    payload = peer.payload()
    payload["exp"] = clock[0] + 30.5
    token = compact(payload, keys[RESOLVER])
    with responses.RequestsMock() as http:
        respond(http, token)
        clock[0] = payload["exp"] - 0.125
        first = request(client)
        assert first["exp"] == payload["exp"]
        for offset in (0, 0.125, 14):
            clock[0] = payload["exp"] + offset
            with pytest.raises(FederationJwtPayloadError, match="Resolve result has expired"):
                request(client)
        assert len(http.calls) == 4
    update.assert_called_once()
    assert update.call_args[0][0] is first


@pytest.mark.parametrize("stage", ["http", "metadata"])
def test_request_crossing_expiry_does_not_update_success(
        peer, keys, client, clock, update, monkeypatch, stage):
    payload = peer.payload()
    payload["exp"] = clock[0] + 30.5
    token = compact(payload, keys[RESOLVER])
    clock[0] = payload["exp"] - 0.125
    calls = []
    if stage == "metadata":
        original = Metadata.verify

        def verify_metadata(self, **kwargs):
            result = original(self, **kwargs)
            calls.append(clock[0])
            clock[0] = payload["exp"]
            return result

        monkeypatch.setattr(Metadata, "verify", verify_metadata)

    def receive(request):
        if stage == "http":
            calls.append(clock[0])
            clock[0] = payload["exp"]
        return 200, {"Content-Type": RESOLVE_RESPONSE.content_type}, token

    with responses.RequestsMock() as http:
        http.add_callback("GET", RESOLVER + "/resolve", callback=receive)
        with pytest.raises(FederationJwtPayloadError, match="Resolve result has expired"):
            request(client)
        assert len(http.calls) == 1
    assert calls == [payload["exp"] - 0.125]
    update.assert_not_called()


def test_deadline_uses_authenticated_claim_not_changed_message(
        peer, keys, client, clock, update, monkeypatch):
    payload = peer.payload()
    payload["exp"] = clock[0] + 30.5
    token = compact(payload, keys[RESOLVER])
    calls = []

    class ChangedView(ResolveResponse):
        def verify(self, **kwargs):
            result = super().verify(**kwargs)
            calls.append(self["exp"])
            self["exp"] += 3600
            return result

    monkeypatch.setattr(resolve_module, "RESOLVE_RESPONSE",
                        replace(RESOLVE_RESPONSE, message_cls=ChangedView))
    clock[0] = payload["exp"]
    with responses.RequestsMock() as http:
        respond(http, token)
        with pytest.raises(FederationJwtPayloadError, match="Resolve result has expired"):
            request(client)
    assert calls == [payload["exp"]]
    update.assert_not_called()


def test_json_error_is_not_subject_to_success_deadline(client, clock, update):
    clock[0] += 3600
    with responses.RequestsMock() as http:
        http.add("GET", RESOLVER + "/resolve", status=400,
                 json={"error": "invalid_trust_chain"})
        error = request(client)
        assert error["error"] == "System error"
        assert json.loads(error["error_description"]) == {"error": "invalid_trust_chain"}
    parsed = client.get_service("resolve").parse_response(
        '{"error":"invalid_trust_chain"}', sformat="json")
    assert parsed["error"] == "invalid_trust_chain"
    update.assert_not_called()
