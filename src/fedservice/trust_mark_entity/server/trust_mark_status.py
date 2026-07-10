import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

from fedservice.federation_jwt.registry import TRUST_MARK_STATUS_RESPONSE
from fedservice.federation_jwt.signing import sign_federation_jwt_with_keyjar

logger = logging.getLogger(__name__)


def create_trust_mark_status_response(
        keyjar, entity_id, trust_mark, status, signing_alg="RS256"
):
    payload = {
        "iss": entity_id,
        "iat": utc_time_sans_frac(),
        "trust_mark": trust_mark,
        "status": status,
    }
    return sign_federation_jwt_with_keyjar(
        profile=TRUST_MARK_STATUS_RESPONSE,
        payload=payload,
        key_jar=keyjar,
        issuer=entity_id,
        alg=signing_alg,
    )


class TrustMarkStatus(Endpoint):
    request_cls = oidc.Message
    response_format = "jose"
    response_content_type = "application/trust-mark-status-response+jwt"
    name = "trust_mark_status"
    endpoint_name = 'federation_trust_mark_status_endpoint'

    def __init__(self,
                 upstream_get: Callable,
                 **kwargs):
        _client_authn_method = kwargs.get("client_authn_method", None)
        if not _client_authn_method:
            kwargs["client_authn_method"] = ["none"]

        Endpoint.__init__(self, upstream_get, **kwargs)

    def process_request(self,
                        request: Optional[dict] = None,
                        **kwargs) -> dict:
        _trust_mark_issuer = self.upstream_get("unit")

        if 'trust_mark' not in request:
            return self.error_cls(
                error="invalid_request",
                error_description=(
                    "A compact trust_mark is required for the signed status response"
                ),
            )

        try:
            _mark = _trust_mark_issuer.unpack_trust_mark(request['trust_mark'])
        except Exception:
            _mark = None

        if _mark and _trust_mark_issuer.find(_mark['trust_mark_type'], _mark['sub']):
            _jws = create_trust_mark_status_response(
                keyjar=_trust_mark_issuer.upstream_get(
                        'attribute', 'keyjar'
                    ),
                entity_id=_trust_mark_issuer.entity_id,
                trust_mark=request['trust_mark'],
                status="active",
            )
            return {'response_args': _jws}

        return self.error_cls(
            error="not_found",
            error_description="No active trust mark matching the query",
        )

    def do_response(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            error: Optional[str] = "",
            **kwargs
    ) -> dict:
        if not error and isinstance(response_args, Message):
            error = response_args.get("error", "")
            if error:
                for claim in ["error_description", "error_uri", "state"]:
                    if claim in response_args:
                        kwargs[claim] = response_args[claim]

        if error:
            response = self.error_cls(error=error)
            for claim in ["error_description", "error_uri", "state"]:
                if claim in kwargs:
                    response[claim] = kwargs[claim]
            return Endpoint.do_response(
                self,
                response_msg=response.to_json(),
                content_type="application/json",
            )

        return Endpoint.do_response(
            self,
            response_args=response_args,
            request=request,
            **kwargs
        )

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
