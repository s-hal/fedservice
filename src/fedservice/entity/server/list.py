import json
import logging
from collections.abc import KeysView

from cryptojwt import KeyJar
from idpyoidc.exception import DecodeError
from idpyoidc.exception import FormatError
from idpyoidc.exception import TooManyValues
from idpyoidc.key_import import import_jwks
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity.function import mutable_verified_claims
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.message import ListRequest

logger = logging.getLogger(__name__)


class List(Endpoint):
    request_cls = ListRequest
    # response_cls = EntityIDList
    response_format = 'json'
    response_content_type = "application/json"
    name = "list"
    endpoint_name = 'federation_list_endpoint'

    def __init__(self, upstream_get, extended=False, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.extended = extended

    def parse_request(self, request, http_info=None, verify_args=None, **kwargs):
        """Use normal endpoint admission and map expected decoding failures."""
        try:
            return super().parse_request(request, http_info=http_info,
                                         verify_args=verify_args, **kwargs)
        except (DecodeError, FormatError, TooManyValues) as err:
            return self.error_cls(error="invalid_request", error_description=str(err))

    def filter(self,
               subordinates: dict,
               entity_type: str = '',
               trust_mark_type: str = '',
               trust_marked=None,
               **kwargs):
        match = []
        for entity_id, conf in subordinates.items():
            matched = False
            if entity_type:
                if entity_type in conf['metadata']:
                    matched = True
            if trust_marked:
                if 'trust_marks' in conf:
                    matched = True
                else:
                    matched = False
            if trust_mark_type:
                trust_marks = conf.get('trust_marks') or []
                matched = False
                for trust_mark in trust_marks:
                    if trust_mark['trust_mark_type'] == trust_mark_type:
                        matched = True

            if matched:
                match.append(entity_id)
        return match

    def process_request(self, request=None, **kwargs):
        """Apply supported registration filters, without fetching Trust Marks."""
        try:
            admitted = self.request_cls(**(request if request is not None else {}))
            admitted.verify()
        except (DecodeError, ValueError) as err:
            return {"error": "invalid_request", "error_description": str(err),
                    "response_code": 400}
        request = admitted
        unsupported = set(request).difference({"entity_type", "intermediate",
                                               "client_id", "authenticated"})
        if unsupported:
            return {"error": "unsupported_parameter", "response_code": 400,
                    "error_description": "Unsupported List filter: {}".format(
                        ", ".join(sorted(unsupported)))}

        _db = self.upstream_get("unit").subordinate
        matched = []
        for entity_id, item in _db.items():
            if request.get("intermediate") and not isinstance(item.get("intermediate"), bool):
                return {"error": "unsupported_parameter", "response_code": 400,
                        "error_description": "Registration cannot support intermediate filtering."}
            if "entity_type" in request:
                # Registration's plural storage field is not a wire metadata claim.
                types = item.get("entity_types", item.get("entity_type"))
                if (not isinstance(types, (list, tuple, KeysView)) or
                        any(not isinstance(value, str) or not value for value in types)):
                    return {"error": "unsupported_parameter", "response_code": 400,
                            "error_description": "Registration cannot support entity_type filtering."}
                if not set(request["entity_type"]).intersection(types):
                    continue
            if request.get("intermediate") and not item["intermediate"]:
                continue
            matched.append(entity_id)
        return {"response_msg": json.dumps(matched)}

    def collect_subordinates(self) -> dict:
        _server_entity = self.upstream_get("unit")
        _federation_entity = _server_entity.upstream_get("unit")
        keyjar = KeyJar()
        _collector = _federation_entity.function.trust_chain_collector
        sub = {}
        for entity_id, conf in _federation_entity.server.subordinate.items():
            #  get entity configuration for subordinate
            _entity_configuration = _collector.get_entity_configuration(entity_id)
            # Verify signature with the keys I have
            keyjar = import_jwks(keyjar, conf['jwks'], entity_id)
            verified = verify_federation_jwt(
                profile=ENTITY_CONFIGURATION,
                token=_entity_configuration,
                key_jar=keyjar,
            )
            sub[entity_id] = mutable_verified_claims(verified.claims())
        return sub
