import logging
from typing import Callable
from typing import Optional

from cryptojwt import KeyJar

from fedservice import get_payload
from fedservice.entity import FederationEntity
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message

from fedservice import message
from fedservice.entity.function import Function
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function.trust_anchor import get_verified_trust_anchor_statement
from fedservice.entity.utils import get_federation_entity
from fedservice.federation_jwt.errors import FederationJwtError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import TRUST_MARK
from fedservice.federation_jwt.registry import TRUST_MARK_DELEGATION

logger = logging.getLogger(__name__)


class TrustMarkVerifier(Function):
    """
    The steps are:
    1) Verify the trust mark itself. That is; that it contains all the required claims and has not expired.
    2) Check that the trust mark issuer is recognized by the trust anchor
    3) If delegation is active.
        a) verify that the delegator is recognized by the trust anchor
        b) verify the signature of the delegation
    4) Find a trust chain to the trust mark issuer
    5) Verify the signature of the trust mark
    """
    def __init__(self, upstream_get: Optional[Callable] = None,
                 federation_entity: Optional[FederationEntity] = None
                 ):
        if not upstream_get and not federation_entity:
            raise ValueError("Must have one of upstream_get and federation_entity")
        Function.__init__(self, upstream_get)
        self.federation_entity = federation_entity

    def check_delegation(
        self,
        trust_anchor_statement,
        trust_mark,
        verified_delegation=None,
    ) -> bool:
        _owners = trust_anchor_statement.get("trust_mark_owners", {})
        if _owners:
            _delegator = _owners.get(trust_mark["trust_mark_type"])
        else:
            _delegator = None

        if "delegation" in trust_mark:
            if _delegator is None or verified_delegation is None:
                return False
            if _delegator["sub"] != verified_delegation.get("iss"):
                logger.warning(
                    f"{verified_delegation.get('iss')} not recognized delegator "
                    f"for {trust_mark['trust_mark_type']}"
                )
                return False
            if verified_delegation.get("sub") != trust_mark.get("iss"):
                logger.warning("Delegation subject does not match Trust Mark issuer")
                return False
            if verified_delegation.get("trust_mark_type") != trust_mark.get(
                "trust_mark_type"
            ):
                logger.warning("Delegation and Trust Mark types do not match")
                return False
        else:
            if _delegator:
                return False

        return True

    def __call__(self,
                 trust_mark: str,
                 trust_anchor: str,
                 check_status: Optional[bool] = False,
                 entity_id: Optional[str] = None,
                 outer_trust_mark_type: Optional[str] = None
                 ) -> Optional[Message]:
        """
        Verifies that a trust mark is issued by someone in the federation and that
        the signing key is a federation key.

        :param trust_mark: A signed JWT representing a trust mark
        :returns: TrustClaim message instance if OK otherwise None
        """

        try:
            payload = get_payload(trust_mark)
        except Exception:
            return None
        _trust_mark = message.TrustMark(**payload)
        try:
            _trust_mark.verify(entity_id=entity_id)
        except Exception:
            return None

        # Get trust anchor information in order to verify the issuer and if needed the delegator.
        if self.federation_entity:
            _federation_entity = self.federation_entity
        else:
            _federation_entity = get_federation_entity(self)

        trust_anchor_statement = get_verified_trust_anchor_statement(_federation_entity, trust_anchor)

        # Now time to verify the signature of the trust mark
        _trust_chains = []
        if _trust_mark["iss"] != trust_anchor:
            _trust_chains = get_verified_trust_chains(_federation_entity, _trust_mark['iss'])
            if not _trust_chains:
                logger.warning(f"Could not find any verifiable trust chains for {_trust_mark['iss']}")
                return None

            if trust_anchor not in [_tc.anchor for _tc in _trust_chains]:
                logger.warning(f'No verified trust chain to the trust anchor: {trust_anchor}')
                return None

        keyjar = _federation_entity.get_attribute('keyjar')

        try:
            verified_mark = verify_federation_jwt(
                profile=TRUST_MARK,
                token=trust_mark,
                key_jar=keyjar,
            )
        except FederationJwtError:
            return None

        verified_claims = verified_mark.claims()
        if (
            outer_trust_mark_type is not None
            and outer_trust_mark_type != verified_claims.get("trust_mark_type")
        ):
            logger.warning(
                f"Trust Mark type mismatch. outer={outer_trust_mark_type} "
                f"inner={verified_claims.get('trust_mark_type')} "
                f"iss={verified_claims.get('iss')} sub={verified_claims.get('sub')}"
            )
            return None

        _trust_mark_issuers = trust_anchor_statement.get("trust_mark_issuers")
        if _trust_mark_issuers is None:
            return None
        _allowed_issuers = _trust_mark_issuers.get(
            verified_claims["trust_mark_type"]
        )
        if _allowed_issuers is None:
            return None
        if _allowed_issuers and verified_claims["iss"] not in _allowed_issuers:
            logger.warning(
                f'Trust mark issuer {verified_claims["iss"]} not trusted by the '
                f'trust anchor for trust mark type: '
                f'{verified_claims["trust_mark_type"]}'
            )
            return None

        verified_delegation = None
        if "delegation" in verified_claims:
            verified_delegation = self.verify_delegation(
                verified_claims,
                trust_anchor,
                trust_anchor_statement=trust_anchor_statement,
            )
        if not self.check_delegation(
            trust_anchor_statement,
            verified_claims,
            verified_delegation=verified_delegation,
        ):
            return None

        return verified_claims

    def verify_delegation(
        self,
        trust_mark,
        trust_anchor_id,
        trust_anchor_statement=None,
    ):
        if trust_anchor_statement is None:
            _federation_entity = get_federation_entity(self)
            _collector = _federation_entity.function.trust_chain_collector
            trust_anchor_statement = (
                _collector.get_verified_self_signed_entity_configuration(
                    trust_anchor_id
                )
            )

        trust_mark_type = trust_mark["trust_mark_type"]
        trust_mark_issuers = trust_anchor_statement.get("trust_mark_issuers", {})
        trust_mark_owners = trust_anchor_statement.get("trust_mark_owners", {})
        if trust_mark_type not in trust_mark_issuers:
            return None
        if trust_mark_type not in trust_mark_owners:
            return None

        tm_owner_info = trust_mark_owners[trust_mark_type]
        try:
            key_jar = import_jwks(
                KeyJar(),
                tm_owner_info["jwks"],
                tm_owner_info["sub"],
            )
            verified = verify_federation_jwt(
                profile=TRUST_MARK_DELEGATION,
                token=trust_mark["delegation"],
                key_jar=key_jar,
            )
        except Exception:
            return None

        return dict(verified.claims())
