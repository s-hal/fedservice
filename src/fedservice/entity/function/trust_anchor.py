from typing import Optional

from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import mutable_verified_claims
from fedservice.entity.utils import get_federation_entity
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION


def get_verified_trust_anchor_statement(federation_entity, entity_id: str):
    _collector = federation_entity.function.trust_chain_collector
    _ec = _collector.get_entity_configuration(entity_id)
    verified = verify_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        token=_ec,
        key_jar=federation_entity.keyjar,
    )
    return mutable_verified_claims(verified.claims())


def get_verified_endpoint(unit, entity_id: str, endpoint_name: str) -> Optional[str]:
    _federation_entity = get_federation_entity(unit)

    if entity_id in _federation_entity.trust_anchors:
        res = get_verified_trust_anchor_statement(_federation_entity, entity_id)
        try:
            endpoint = res["metadata"]["federation_entity"].get(endpoint_name)
        except KeyError:
            endpoint = None
    else:
        _trust_chains = get_verified_trust_chains(unit, entity_id)
        _trust_chain = _federation_entity.pick_trust_chain(_trust_chains)
        try:
            endpoint = _trust_chain.metadata["federation_entity"].get(endpoint_name)
        except KeyError:
            endpoint = None

    return endpoint
