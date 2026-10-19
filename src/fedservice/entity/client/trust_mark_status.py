from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.jws.jws import factory
from idpyoidc.client.configure import Configuration
from idpyoidc.client.util import get_http_body
from idpyoidc.constant import URL_ENCODED
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService
from fedservice.entity.utils import get_federation_entity
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import TRUST_MARK_STATUS_RESPONSE
from fedservice.payload_validation import _validate_entity_identifier


def _request_expectations(issuer, trust_mark):
    _validate_entity_identifier(issuer, "expected_issuer")
    if not isinstance(trust_mark, str) or not trust_mark:
        raise ValueError("expected_trust_mark must be a nonempty compact token string")
    try:
        parsed = factory(trust_mark)
        if parsed is None or len(parsed.jwt.part) != 3 or not all(parsed.jwt.part):
            raise ValueError("Not a signed compact token")
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as err:
        raise ValueError("expected_trust_mark must be a nonempty compact token string") from err
    return issuer, trust_mark


class TrustMarkStatus(FederationService):
    """The service that talks to the OIDC federation Status endpoint."""

    msg_type = oauth2.Message
    response_cls = message.Message
    error_msg = ResponseMessage
    synchronous = True
    service_name = "trust_mark_status"
    http_method = "POST"
    response_body_type = "jwt"
    response_content_type = TRUST_MARK_STATUS_RESPONSE.content_type

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def construct_request(self, request_args=None, **kwargs):
        """Construct the Federation request without OAuth client usage defaults."""
        return message.TrustMarkStatusRequest(**(request_args or {}))

    def get_headers_args(self):
        """Supply the Federation client identifier to configured authentication."""
        return {"client_id": self.upstream_get("context").entity_id}

    def parse_response(self, info, sformat="", state="", **kwargs):
        """Verify successful JWT responses as Trust Mark Status Responses."""
        if not sformat:
            sformat = self.response_body_type

        if sformat not in ("jwt", "jws", "jose"):
            response = super(TrustMarkStatus, self).parse_response(
                info,
                sformat=sformat,
                state=state,
                **kwargs
            )
            if "error" in response:
                return response
            raise ValueError("Trust Mark Status success requires a compact JWT response")

        issuer, trust_mark = _request_expectations(
            kwargs.get("expected_issuer"), kwargs.get("expected_trust_mark"))
        federation_entity = get_federation_entity(self)
        verified = verify_federation_jwt(
            profile=TRUST_MARK_STATUS_RESPONSE,
            token=info,
            key_jar=federation_entity.keyjar,
        )
        if verified.claims()["iss"] != issuer:
            raise FederationJwtPayloadError("Trust Mark Status issuer does not match requested issuer")
        if verified.claims()["trust_mark"] != trust_mark:
            raise FederationJwtPayloadError("Trust Mark Status trust_mark does not match requested token")
        return verified.message()

    def get_request_parameters(
            self,
            request_args: Optional[dict] = None,
            method: Optional[str] = "",
            request_body_type: Optional[str] = "",
            authn_method: Optional[str] = "",
            fetch_endpoint: Optional[str] = "",
            endpoint: Optional[str] = "",
            **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        :param method: HTTP method used.
        :param authn_method: Client authentication method
        :param request_args: Message arguments
        :param request_body_type:
        :param fetch_endpoint:
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP request
        """
        if method and method != "POST":
            raise ValueError("Trust Mark Status requires POST")
        if request_body_type and request_body_type != "urlencoded":
            raise ValueError("Trust Mark Status requires form encoding")
        if endpoint and fetch_endpoint and endpoint != fetch_endpoint:
            raise ValueError("endpoint conflicts with fetch_endpoint")
        endpoint = endpoint or fetch_endpoint
        if not isinstance(endpoint, str) or not endpoint:
            raise ValueError("Trust Mark Status requires an explicit endpoint")
        issuer, trust_mark = _request_expectations(
            kwargs.get("entity_id", kwargs.get("issuer")),
            (request_args or {}).get("trust_mark"))
        request = self.construct_request({"trust_mark": trust_mark})
        # Service.get_request_parameters reads context.issuer, which direct
        # Federation service calls need not set. Keep issuer context per request
        # while reusing its authentication, header and form facilities.
        header_args = dict(kwargs, iss=issuer, endpoint_url=endpoint)
        header_args.update(self.get_headers_args())
        headers = self.get_headers(request, http_method="POST", authn_method=authn_method,
                                   **header_args)
        headers["Content-Type"] = URL_ENCODED
        info = {"url": endpoint, "method": "POST", "request": request,
                "body": get_http_body(request, URL_ENCODED), "headers": headers}
        info.update(expected_issuer=issuer, expected_trust_mark=trust_mark)
        return info
