"""Profile-backed HTTP behavior for the Trust Mark endpoint."""

import inspect

from fedservice.federation_jwt.registry import TRUST_MARK
from fedservice.trust_mark_entity.server.trust_mark import TrustMark


def test_trust_mark_endpoint_content_type_comes_from_profile():
    assert TrustMark.response_content_type == TRUST_MARK.content_type

    source = inspect.getsource(TrustMark)
    assert "response_content_type = TRUST_MARK.content_type" in source
    assert 'response_content_type = "application/trust-mark+jwt"' not in source


def test_trust_mark_success_response_uses_profile_content_type():
    endpoint = object.__new__(TrustMark)
    token = "signed-trust-mark"

    response = endpoint.do_response(response_args={"response": token})

    assert response["response"] == token
    assert ("Content-type", TRUST_MARK.content_type) in response["http_headers"]
