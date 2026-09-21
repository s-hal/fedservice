import logging
from typing import Optional
from typing import Union

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.message import Message
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.entity_statement.create import create_resolve_response
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.message import ResolveRequest

logger = logging.getLogger(__name__)


class Resolve(Endpoint):
    request_cls = ResolveRequest
    response_format = "jose"
    response_content_type = RESOLVE_RESPONSE.content_type
    name = "resolve"
    endpoint_name = 'federation_resolve_endpoint'

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)

    def process_request(self, request=None, **kwargs):
        _federation_entity = get_federation_entity(self)
        _trust_anchors = request['trust_anchor']

        # verified trust chains with policy adjusted metadata
        _chains, signed_entity_configuration = collect_trust_chains(_federation_entity,
                                                                    entity_id=request['sub'],
                                                                    stop_at=(_trust_anchors[0]
                                                                             if len(_trust_anchors) == 1
                                                                             else ""))
        _trust_chains = verify_trust_chains(_federation_entity, _chains,
                                            signed_entity_configuration)
        relevant_chains = [
            chain for chain in _trust_chains if chain.anchor in _trust_anchors
        ]
        _trust_chains = apply_policies(_federation_entity, relevant_chains)
        if not _trust_chains:
            if relevant_chains and all(
                    chain.err.get("metadata_policy", {}).get("error") == "invalid_metadata"
                    for chain in relevant_chains):
                return {
                    "error": "invalid_metadata",
                    "error_description": "Resolve metadata policy rejected all candidate chains.",
                    "response_code": 400,
                }
            return {
                "error": "invalid_trust_chain",
                "error_description": "Resolve found no acceptable chain for the requested trust anchor.",
                "response_code": 400,
            }
        _chosen_chain = _trust_chains[0]
        _trust_anchor = _chosen_chain.anchor

        if "entity_type" in request:
            metadata = {entity_type: _chosen_chain.metadata[entity_type]
                        for entity_type in request['entity_type']
                        if entity_type in _chosen_chain.metadata}
        else:
            metadata = _chosen_chain.metadata

        # Now for the trust marks
        verified_trust_marks = []
        expires_at = _chosen_chain.exp
        for _tm_entry in _chosen_chain.verified_chain[-1].get("trust_marks", []):
            _trust_mark = _tm_entry.get("trust_mark")
            _outer_tmt = _tm_entry.get("trust_mark_type")
            if not _trust_mark or not _outer_tmt:
                continue

            try:
                _verified_mark = _federation_entity.function.trust_mark_verifier(trust_mark=_trust_mark,
                                                                                 trust_anchor=_trust_anchor,
                                                                                 entity_id=request['sub'],
                                                                                 outer_trust_mark_type=_outer_tmt)
            except Exception as e:
                logger.exception(f"Trust mark verifier raised unexpectedly, skipping trust mark: {e}")
                continue

            if _verified_mark:
                verified_trust_marks.append({
                    "trust_mark_type": _verified_mark["trust_mark_type"],
                    "trust_mark": _trust_mark
                })
                trust_mark_exp = _verified_mark.get("exp")
                if isinstance(trust_mark_exp, int):
                    expires_at = min(expires_at, trust_mark_exp)

        expired_result = {
            "error": "invalid_trust_chain",
            "error_description": "Resolve result has expired.",
            "response_code": 400,
        }
        if expires_at <= utc_time_sans_frac():
            return expired_result

        trust_chain = _federation_entity.function.trust_chain_collector.get_chain(
            _chosen_chain.iss_path, _trust_anchor, kwargs.get("with_ta_ec"))

        if verified_trust_marks:
            args = {"trust_marks": verified_trust_marks}
        else:
            args = {}

        try:
            _jws = create_resolve_response(_federation_entity.entity_id,
                                           sub=request["sub"],
                                           key_jar=_federation_entity.get_attribute('keyjar'),
                                           metadata=metadata,
                                           trust_chain=trust_chain,
                                           expires_at=expires_at,
                                           **args)
        except ValueError:
            # Expiration can pass between the operation check and creation.
            if expires_at <= utc_time_sans_frac():
                return expired_result
            raise
        return {'response_args': _jws}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
