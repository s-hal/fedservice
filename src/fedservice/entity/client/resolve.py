from time import time
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.jws.jws import factory as jws_factory
from idpyoidc.client.configure import Configuration
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService
from fedservice.entity.utils import get_federation_entity
from fedservice.exception import WrongSubject
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.message import ResolveRequest
from fedservice.payload_validation import _validate_entity_identifier


def _binding_expectations(values):
    for name in ("expected_resolver", "expected_subject", "expected_audience"):
        _validate_entity_identifier(values.get(name), name)
    anchors = values.get("expected_trust_anchors")
    if not isinstance(anchors, (list, tuple)) or not anchors:
        raise ValueError("expected_trust_anchors must be a nonempty collection")
    for anchor in anchors:
        _validate_entity_identifier(anchor, "expected_trust_anchors")
    return (values["expected_resolver"], values["expected_subject"],
            tuple(anchors), values["expected_audience"])


def _check_chain_boundaries(chain, expected_start, anchors, location):
    if not isinstance(chain, (list, tuple)) or not chain or not all(
            isinstance(item, str) and item for item in chain):
        raise FederationJwtPayloadError("{} trust_chain must be a nonempty array".format(location))
    identities = []
    # The trusted resolver's outer signature authenticates these statements.
    # Decode endpoints only; this neither verifies inner signatures nor imports keys.
    for token in (chain[0], chain[-1]):
        try:
            parsed = jws_factory(token)
            if parsed is None or parsed.jwt is None or len(parsed.jwt.part) != 3:
                raise ValueError("Not a compact statement")
            if not parsed.jwt.part[2] or parsed.jwt.headers.get("typ") != ENTITY_CONFIGURATION.typ:
                raise ValueError("Not an Entity Statement")
            claims = parsed.jwt.payload()
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as err:
            raise FederationJwtPayloadError(
                "{} trust_chain boundary cannot be decoded".format(location)) from err
        try:
            if not isinstance(claims, dict):
                raise ValueError("Not an object")
            for name in ("iss", "sub"):
                _validate_entity_identifier(claims.get(name), name)
        except ValueError as err:
            raise FederationJwtPayloadError(
                "{} trust_chain boundary has invalid identifiers".format(location)) from err
        identities.append((claims["iss"], claims["sub"]))
    if identities[0][0] != identities[0][1]:
        raise FederationJwtPayloadError(
            "{} trust_chain start must be self-issued".format(location))
    if identities[0][1] != expected_start:
        error = WrongSubject if location == "Payload" else FederationJwtPayloadError
        raise error("{} trust_chain start does not match the request".format(location))
    # The anchor EC may be omitted; either terminal form is issued by the anchor.
    if identities[-1][0] not in anchors:
        raise FederationJwtPayloadError(
            "{} trust_chain anchor was not requested".format(location))


class Resolve(FederationService):
    """The service that talks to the OpenID Federation Resolve endpoint."""

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
        if sformat not in ["jose", "jwt", "jws"]:
            response = super(Resolve, self).parse_response(
                info,
                sformat=sformat,
                state=state,
                **kwargs
            )
            if "error" in response:
                return response
            raise ValueError("Resolve success requires a compact JWT response")

        resolver, subject, anchors, audience = _binding_expectations(kwargs)
        federation_entity = get_federation_entity(self)
        verified = verify_federation_jwt(
            profile=RESOLVE_RESPONSE,
            token=info,
            key_jar=federation_entity.keyjar,
        )
        claims = verified.claims()
        if claims["iss"] != resolver:
            raise FederationJwtPayloadError("Resolve Response issuer does not match requested resolver")
        if claims["sub"] != subject:
            raise WrongSubject("Resolve Response subject does not match requested entity")
        _check_chain_boundaries(claims["trust_chain"], subject, anchors, "Payload")
        if "trust_chain" in verified.header():
            _check_chain_boundaries(verified.header()["trust_chain"], resolver, anchors, "Header")
        if "aud" in claims:
            audiences = (claims["aud"],) if isinstance(claims["aud"], str) else claims["aud"]
            if audience not in audiences:
                raise FederationJwtPayloadError("Resolve Response audience does not identify requester")
        if time() >= claims["exp"]:
            raise FederationJwtPayloadError("Resolve result has expired")
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
        :return: HTTP request information and private response-binding expectations
        """
        if not endpoint:
            self.upstream_get('unit')
            raise AttributeError("Missing endpoint")

        resolver = kwargs.get("entity_id", kwargs.get("issuer"))
        _validate_entity_identifier(resolver, "resolver")
        request_args = dict(request_args or {})
        for parameter in ("trust_anchor", "entity_type"):
            if isinstance(request_args.get(parameter), str):
                request_args[parameter] = [request_args[parameter]]
        _req = ResolveRequest(**request_args)
        _req.verify()

        info = {
            "url": _req.request(endpoint), "method": self.http_method,
            "expected_resolver": resolver, "expected_subject": _req["sub"],
            "expected_trust_anchors": tuple(_req["trust_anchor"]),
            "expected_audience": get_federation_entity(self).entity_id,
        }
        _binding_expectations(info)
        return info
