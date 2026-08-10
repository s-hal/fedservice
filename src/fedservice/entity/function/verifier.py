import logging
from collections.abc import Mapping
from typing import Callable
from typing import List
from typing import Optional

from cryptojwt import KeyBundle
from cryptojwt.jws.jws import factory

from fedservice.entity.function import Function
from fedservice.entity.utils import get_federation_entity
from fedservice.entity_statement.constraints import meets_restrictions
from fedservice.entity_statement.statement import TrustChain
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.key_resolver import KeyJarResolver
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT

logger = logging.getLogger(__name__)


def _mutable_json(value):
    if isinstance(value, Mapping):
        return {key: _mutable_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mutable_json(item) for item in value]
    return value


class TrustChainVerifier(Function):

    def __init__(self, upstream_get: Callable, trust_anchor: Optional[List[str]] = None):
        Function.__init__(self, upstream_get)
        self.trust_anchor = trust_anchor or []

    def trusted_anchor(self, entity_statement) -> bool:
        _jwt = factory(entity_statement)
        payload = _jwt.jwt.payload()
        if self.trust_anchor:
            return payload['iss'] in self.trust_anchor
        elif self.upstream_get:
            _federation = get_federation_entity(self)
            return payload["iss"] in _federation.function.trust_chain_collector.trust_anchors
        return False

    def verify_trust_chain(self, entity_statement_list: List) -> Optional[List]:
        """
        Verifies the trust chain. Works its way down from the Trust Anchor to the leaf.

        :param entity_statement_list: List of entity statements. The entity's self-signed statement last.
        :return: List of lists of verified entity statements
        """
        logger.debug("Find verified trust chains")
        res = []

        for i in range(len(entity_statement_list) - 1, -1, -1):
            if self.trusted_anchor(entity_statement_list[i]):
                # Trust chain ending in a trust anchor I know.
                verified_trust_chain = self._verify_trust_chain(entity_statement_list[i:])
                if verified_trust_chain:
                    res.append(verified_trust_chain)
        if not res:
            logger.debug("Found no verified trust anchors")
        return res

    def _verify_trust_chain(self, entity_statement_list: List) -> Optional[List]:
        """
        Verifies the trust chain. Works its way down from the Trust Anchor to the leaf.

        :param entity_statement_list: List of entity statements. The entity's self-signed statement last.
        :return: A sequence of verified entity statements
        """
        logger.debug("verify_trust_chain")

        verified_entity_statement = []

        n = len(entity_statement_list) - 1
        _keyjar = self.upstream_get("attribute", "keyjar")
        key_resolver = KeyJarResolver(_keyjar)
        for index, entity_statement in enumerate(entity_statement_list):
            if index == n:
                profile = ENTITY_CONFIGURATION
            else:
                profile = SUBORDINATE_STATEMENT

            verified = verify_federation_jwt(
                profile=profile,
                token=entity_statement,
                key_resolver=key_resolver,
            )
            logger.debug("JWS header: %s", verified.header())
            res = _mutable_json(verified.claims())
            logger.debug("Verified entity statement: %s", res)
            try:
                _jwks = res['jwks']
            except KeyError:
                if len(verified_entity_statement) != n:
                    raise ValueError('Missing signing JWKS')
            else:
                _kb = KeyBundle(keys=_jwks['keys'])
                try:
                    old = _keyjar.get_issuer_keys(res['sub'])
                except KeyError:
                    _keyjar.add_kb(res['sub'], _kb)
                else:
                    new = [k for k in _kb if k not in old]
                    if new:
                        _key_spec = [f'{k.kty}:{k.use}:{k.kid}' for k in new]
                        logger.debug(
                            "New keys added to the federation key jar for '{}': {}".format(
                                res['sub'], _key_spec)
                        )
                        # Only add keys to the KeyJar if they are not already there.
                        _kb.set(new)
                        _keyjar.add_kb(res['sub'], _kb)

            verified_entity_statement.append(res)

        if verified_entity_statement and meets_restrictions(verified_entity_statement):
            return verified_entity_statement
        else:
            return []

    def trust_chain_expires_at(self, trust_chain):
        exp = -1
        for entity_statement in trust_chain:
            if exp >= 0:
                if entity_statement['exp'] < exp:
                    exp = entity_statement['exp']
            else:
                exp = entity_statement['exp']
        return exp

    def __call__(self, chain: List[str]) -> Optional[List]:
        """

        :param chain: A chain of Entity Statements. The first one issued by a TA about an
            entity, the last an Entity Configuration.
        :returns: A TrustChain instances
        """
        logger.debug("Evaluate trust chain")
        verified_trust_chains = self.verify_trust_chain(chain)

        if not verified_trust_chains:
            return None

        trust_chains = []
        for verified_trust_chain in verified_trust_chains:
            _expires_at = self.trust_chain_expires_at(verified_trust_chain)

            trust_chain = TrustChain(exp=_expires_at, verified_chain=verified_trust_chain)

            # Collect the issuers in the trust path
            iss_path = [x['iss'] for x in verified_trust_chain]
            trust_chain.anchor = iss_path[0]
            iss_path.reverse()
            trust_chain.iss_path = iss_path

            trust_chain.chain = chain
            trust_chains.append(trust_chain)

        return trust_chains
