"""Shared response adaptation through the endpoint's response machinery."""


def do_response(endpoint, response_args=None, request=None, error="", **kwargs):
    """Adapt operation-selected errors and delegate response construction."""
    if error:
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
    return endpoint.do_response(response_args=response_args, request=request, **kwargs)
