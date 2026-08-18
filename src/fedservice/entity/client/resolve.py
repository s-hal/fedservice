from typing import Callable
from typing import Optional
from typing import Union

from idpyoidc.client.configure import Configuration
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService
from fedservice.entity.utils import get_federation_entity
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.message import ResolveRequest


class Resolve(FederationService):
    """The service that talks to the OIDC federation List endpoint."""

    response_cls = message.ResolveResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "resolve"
    http_method = "GET"
    response_body_type = "jose"
    response_content_type = RESOLVE_RESPONSE.content_type

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def parse_response(self, info, sformat="", state="", **kwargs):
        """Verify successful compact responses as Resolve Responses."""
        if not sformat:
            sformat = self.response_body_type

        # Profile-backed +jwt media types reach services with the jwt label.
        if sformat not in ["jose", "jwt"]:
            return super(Resolve, self).parse_response(
                info,
                sformat=sformat,
                state=state,
                **kwargs
            )

        federation_entity = get_federation_entity(self)
        verified = verify_federation_jwt(
            profile=RESOLVE_RESPONSE,
            token=info,
            key_jar=federation_entity.keyjar,
        )
        return verified.message()

    def get_request_parameters(
            self,
            request_args: Optional[dict] = None,
            authn_method: Optional[str] = "",
            endpoint: Optional[str] = "",
            **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        :param request_args: Message arguments
        :param authn_method: Client authentication method
        :param endpoint:
        :param kwargs: extra keyword arguments
        :return: List of entity IDs
        """
        if not endpoint:
            self.upstream_get('unit')
            raise AttributeError("Missing endpoint")

        _req = ResolveRequest(**request_args)
        _req.verify()

        return {"url": _req.request(endpoint), 'method': self.http_method}
