import logging

from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.server.oidc import registration

from fedservice import save_trust_chains
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.entity.utils import get_federation_entity
from fedservice.exception import NoTrustedChains
from fedservice.federation_jwt.registry import EXPLICIT_REGISTRATION_RESPONSE

logger = logging.getLogger(__name__)


class Registration(registration.Registration):
    request_format = 'jose'
    request_placement = 'body'
    response_format = 'jose'
    response_content_type = EXPLICIT_REGISTRATION_RESPONSE.content_type
    endpoint_name = "federation_registration_endpoint"
    _status = {
        "client_registration_types_supported": ["automatic", "explicit"]
    }

    def parse_request(self, request, auth=None, **kwargs):
        return request

    def process_request(self, request=None, **kwargs):
        """

        :param request: An entity statement in the form of a signed JT
        :param kwargs:
        :return:
        """
        payload = verify_self_signed_signature(request)
        _entity_types = set(payload['metadata'].keys())
        if len(_entity_types) == 1:
            opponent_entity_type = _entity_types.pop()
        else:
            opponent_entity_type = _entity_types.difference({'federation_entity'}).pop()

        _federation_entity = get_federation_entity(self)

        # Collect trust chains for client
        _trust_chains = get_verified_trust_chains(self, entity_id=payload['sub'])
        if not _trust_chains:
            raise NoTrustedChains(f"No trust chains for {payload['sub']}")

        save_trust_chains(self.upstream_get("context"), _trust_chains)
        trust_chain = _federation_entity.pick_trust_chain(_trust_chains)
        _federation_entity.trust_chain_anchor = trust_chain.anchor

        req = RegistrationRequest(**payload["metadata"][opponent_entity_type])
        req["client_id"] = payload['sub']
        # Perform non-federation registration
        response_info = self.non_fed_process_request(req, **kwargs)
        if "response_args" in response_info:
            logger.debug(f"Registration response args: {response_info['response_args']}")
            _context = _federation_entity.context

            _response_metadata = req.to_dict()
            _response_metadata.update(response_info['response_args'])

            registration_response = _context.create_explicit_registration_response(
                subject=payload['sub'],
                metadata={opponent_entity_type: _response_metadata},
                trust_chain=trust_chain,
            )
            response_info["response_msg"] = registration_response
            response_info["response_code"] = 200
            del response_info["response_args"]

        return response_info

    def non_fed_process_request(self, req, **kwargs):
        if "new_id" not in kwargs:
            kwargs["new_id"] = False
        # handle the registration request as in the non-federation case.
        return registration.Registration.process_request(self, req, authn=None, **kwargs)
