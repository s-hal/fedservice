from copy import deepcopy
import logging

from idpyoidc.exception import DecodeError
from idpyoidc.exception import FormatError
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import TooManyValues
from idpyoidc.server.endpoint import Endpoint

from fedservice import message
from fedservice.entity_statement.create import create_subordinate_statement
from fedservice.exception import UnknownEntity
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT

logger = logging.getLogger(__name__)


class Fetch(Endpoint):
    request_cls = message.FetchRequest
    response_cls = message.SubordinateStatement
    response_format = "jose"
    response_content_type = SUBORDINATE_STATEMENT.content_type
    name = "fetch"
    endpoint_name = "federation_fetch_endpoint"

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get=upstream_get, **kwargs)

    def get_policy(self, entity_id):
        pass

    def parse_request(self, request, http_info=None, verify_args=None, **kwargs):
        """Select request errors for known query decoding failures."""
        try:
            return super().parse_request(request, http_info=http_info,
                                         verify_args=verify_args, **kwargs)
        except (DecodeError, FormatError, TooManyValues) as err:
            return self.error_cls(error="invalid_request", error_description=str(err))

    def process_request(self, request=None, **kwargs):
        # Direct publication callers use the same subject admission as HTTP callers.
        try:
            admitted = self.request_cls(**(request if request is not None else {}))
            admitted.verify()
        except (DecodeError, MissingRequiredAttribute, ValueError) as err:
            return {"error": "invalid_request", "error_description": str(err),
                    "response_code": 400}
        request = admitted
        if request["sub"] == self.upstream_get("attribute", "entity_id"):
            return {"error": "invalid_request", "error_description": "Cannot fetch self-subject.",
                    "response_code": 400}
        _context = self.upstream_get("context")
        _issuer = request.get("iss")
        if not _issuer:
            _issuer = self.upstream_get('attribute', 'entity_id')

        _sub = request.get("sub")
        _keyjar = self.upstream_get('attribute', 'keyjar')
        # if not _sub or _sub == _issuer:
        #     _server = self.upstream_get("server")
        #     _entity = _server.upstream_get('unit')
        #     _metadata = _entity.get_metadata()
        #     _es = create_entity_configuration(iss=_entity.context.entity_id,
        #                                       sub=_entity.context.entity_id,
        #                                       key_jar=_keyjar,
        #                                       metadata=_metadata,
        #                                       authority_hints=self.upstream_get('authority_hints'))
        # else:
        _server = self.upstream_get("unit")
        # Information stored about this entity. Contains jwks and possibly entity type and authority_hints
        try:
            _response = _server.subordinate.get(_sub)
        except UnknownEntity:
            _response = None
        if not _response:
            logger.debug(f"Unknown subordinate: {_sub}")
            return {"error": "not_found", "error_description": "Unknown subordinate.",
                    "response_code": 404}

        _entity_types = _response.get('entity_types')
        _response = deepcopy({k: v for k, v in _response.items() if k != 'entity_types'})
        _policy = _server.policy.get(_sub)
        if not _policy:  # No entity specific policy
            if _entity_types is not None:
                _policy = {'metadata': {}}
                for entity_type in _entity_types:
                    _et_policy = _server.policy.get(entity_type)
                    if not _et_policy:
                        continue
                    for _typ in ['metadata', 'metadata_policy']:
                        if _typ in _et_policy:
                            try:
                                _policy[_typ].update({entity_type: _et_policy[_typ]})
                            except KeyError:
                                _policy[_typ] = {entity_type: _et_policy[_typ]}

                if _policy == {'metadata': {}}:  # Nothing has changed
                    _policy = None

        if _policy:
            _response.update(deepcopy(_policy))
        _response.pop('entity_types', None)
        # Stored EC data and policy configuration are not SS publication claims.
        for claim in ("authority_hints", "trust_anchor_hints", "trust_marks",
                      "trust_mark_issuers", "trust_mark_owners"):
            _response.pop(claim, None)

        _es = create_subordinate_statement(iss=_issuer,
                                           sub=_sub,
                                           key_jar=_keyjar,
                                           **_response)
        return {"response_msg": _es}
