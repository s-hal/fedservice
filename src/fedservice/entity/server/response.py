"""Shared JSON error serialization through the idpyoidc response envelope."""

from idpyoidc.server.endpoint import Endpoint


def error_response(endpoint, error, request=None, **kwargs):
    """Serialize an operation-selected error without choosing its HTTP status."""
    response = endpoint.error_cls(error=error)
    for claim in ("error_description", "error_uri", "state"):
        if claim in kwargs:
            response[claim] = kwargs[claim]

    if "http_headers" in kwargs:
        # The dependency replaces only the exact spelling "Content-type".
        kwargs["http_headers"] = [
            header for header in kwargs["http_headers"]
            if header[0].lower() != "content-type"
        ]
    kwargs["response_msg"] = response.to_json()
    kwargs["content_type"] = "application/json"
    return Endpoint.do_response(endpoint, request=request, **kwargs)
