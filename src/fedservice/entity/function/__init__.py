import logging
from collections.abc import Mapping
from inspect import Parameter
from inspect import signature
from typing import Callable
from typing import List
from typing import Optional

from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import KeyJar
from idpyoidc.impexp import ImpExp
from idpyoidc.key_import import import_jwks

from fedservice.entity.utils import get_federation_entity
from fedservice.exception import WrongSubject
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION

logger = logging.getLogger(__name__)


def mutable_verified_claims(value):
    """Project recursively frozen verified claims into mutable JSON values."""
    if isinstance(value, Mapping):
        return {
            key: mutable_verified_claims(item) for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [mutable_verified_claims(item) for item in value]
    return value


def unverified_entity_statement(signed_jwt):
    _jws = factory(signed_jwt)
    return _jws.jwt.payload()


def verify_self_signed_signature(token):
    """
    Verify signature using only keys in the entity statement.
    Will raise exception if signature verification fails.

    :param token: Signed JWT
    :return: Payload of the signed JWT
    """

    payload = unverified_entity_statement(token)
    keyjar = KeyJar()
    keyjar = import_jwks(keyjar, payload['jwks'], payload['iss'])

    verified = verify_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        token=token,
        key_jar=keyjar,
    )
    _val = mutable_verified_claims(verified.claims())
    _val["_jws"] = token
    return _val


class _CollectedChain(list):
    """Raw chain with attempt-local cache provenance, excluded from JSON list data."""

    def __init__(self, values=(), statement_context=None, configuration_context=None):
        super().__init__(values)
        self._statement_context = dict(statement_context or {})
        self._configuration_context = dict(configuration_context or {})

    def __add__(self, values):
        return _CollectedChain(super().__add__(values), self._statement_context,
                               self._configuration_context)


def tree2chains(unit):
    res = []
    configurations = getattr(unit, '_configuration_context', {})
    for issuer, branch in unit.items():
        if branch is None:
            res.append(_CollectedChain())
            continue

        (statement, unit) = branch
        context = getattr(branch, '_statement_context', {})
        if not unit:
            res.append(_CollectedChain([statement], context,
                                       getattr(unit, '_configuration_context', {})))
            continue

        _lists = tree2chains(unit)
        for l in _lists:
            l.append(statement)
            l._statement_context.update(context)

        if not res:
            res = _lists
        else:
            res.extend(_lists)
    for chain in res:
        chain._configuration_context.update(configurations)
    return res


def _accepts_keyword(callback, name):
    """Negotiate optional context without invoking or bypassing an override."""
    try:
        parameters = signature(callback).parameters
    except (TypeError, ValueError):
        # Opaque callables retain the established calling convention.
        return False
    parameter = parameters.get(name)
    return (parameter is not None and parameter.kind in (
        Parameter.POSITIONAL_OR_KEYWORD, Parameter.KEYWORD_ONLY)) or any(
            item.kind == Parameter.VAR_KEYWORD for item in parameters.values())


def collect_trust_chains(unit,
                         entity_id: str,
                         signed_entity_configuration: Optional[str] = "",
                         stop_at: Optional[str] = "",
                         authority_hints: Optional[list] = None,
                         for_resolve: bool = False):
    _federation_entity = get_federation_entity(unit)

    _collector = _federation_entity.function.trust_chain_collector

    # Collect the trust chains
    if signed_entity_configuration:
        entity_configuration = verify_self_signed_signature(signed_entity_configuration)
        if entity_configuration.get("sub") != entity_id:
            raise WrongSubject(
                "Statement subject does not match requested entity: {}".format(entity_id)
            )
        if authority_hints:
            entity_configuration["authority_hints"] = authority_hints
        tree = _collector.collect_tree(entity_id, entity_configuration, stop_at=stop_at)
    else:
        try:
            if for_resolve and _accepts_keyword(_collector, 'for_resolve'):
                _collector_response = _collector(entity_id, stop_at=stop_at, for_resolve=True)
            else:
                _collector_response = _collector(entity_id, stop_at=stop_at)
        except Exception as err:
            logger.error(f"Trust chain collection failed {err}")
            raise (err)
        if _collector_response:
            tree, signed_entity_configuration = _collector_response
        else:
            tree = None

    if tree:
        chains = tree2chains(tree)
        logger.debug("%d chains", len(chains))
        return chains, signed_entity_configuration
    elif tree == {}:
        if for_resolve and entity_id in _collector.trust_anchors:
            return [_CollectedChain(configuration_context=getattr(
                tree, '_configuration_context', {}))], signed_entity_configuration
        return [], signed_entity_configuration
    else:
        return [], None


def verify_trust_chains(unit, chains: List[List[str]], *entity_statements, for_resolve=False):
    #
    _verifier = get_federation_entity(unit).function.verifier

    logger.debug("verify_trust_chains")
    res = []
    examined = []
    constraint_rejections = []
    try:
        for c in chains:
            if entity_statements:
                c.extend(entity_statements)
            # An incomplete path that never reaches a configured anchor is not
            # a rejected replacement; keep its collected material for a retry.
            if not hasattr(_verifier, 'trusted_anchor') or any(
                    _verifier.trusted_anchor(token) for token in c):
                examined.append(c)
            while True:
                failures = [] if for_resolve else None
                trust_chains = _verify_with_outcomes(_verifier, c, constraint_rejections, failures)
                if trust_chains:
                    res.extend(trust_chains)
                if not failures:
                    break
                collector = get_federation_entity(unit).function.trust_chain_collector
                if hasattr(c, '_statement_context'):
                    c._statement_failures = set(failures)
                retry = collector.retry_statement_verification(c, failures, res)
                if retry is None:
                    retry = collector.retry_configuration_verification(c, failures)
                if retry is None:
                    break
                c = retry
                examined.append(c)
    except Exception:
        if for_resolve:
            collector = get_federation_entity(unit).function.trust_chain_collector
            for chain in examined:
                # Preserve owned prior evidence, but do not turn a local error into success.
                collector.retry_statement_verification(chain, chain)
                collector.retry_configuration_verification(chain, chain)
        raise
    finally:
        _finish_statement_verification(unit, examined, res, constraint_rejections)
    return res


def _verify_with_outcomes(verifier, chain, constraint_rejections, statement_failures=None):
    verify = getattr(verifier, 'verify_with_outcomes', None)
    if verify is None:
        return verifier(chain)
    if statement_failures is None or not _accepts_keyword(verify, 'statement_failures'):
        accepted, rejected = verify(chain)
    else:
        accepted, rejected = verify(chain, statement_failures=statement_failures)
    constraint_rejections.extend(rejected)
    return accepted


def _finish_statement_verification(unit, chains, accepted, constraint_rejections):
    collector = getattr(get_federation_entity(unit).function, 'trust_chain_collector', None)
    finish = getattr(collector, "finish_statement_verification", None)
    if finish is not None:
        finish(chains, accepted, constraint_rejections=constraint_rejections)


def verify_trust_chain(unit, chain: List[str]):
    #
    _verifier = get_federation_entity(unit).function.verifier

    logger.debug("verify_trust_chain")
    accepted = None
    constraint_rejections = []
    examined = ([chain] if not hasattr(_verifier, 'trusted_anchor') or any(
        _verifier.trusted_anchor(token) for token in chain) else [])
    try:
        accepted = _verify_with_outcomes(_verifier, chain, constraint_rejections)
        return accepted
    finally:
        _finish_statement_verification(unit, examined, accepted or [], constraint_rejections)


def apply_policies(unit, trust_chains):
    """
    Goes through the collected trust chains, verifies them and applies policies.

    :param unit: A Unit instance
    :param trust_chains: List of TrustChain instances
    :return: List of processed TrustChain instances
    """
    _policy_applier = get_federation_entity(unit).function.policy

    res = []
    for trust_chain in trust_chains:
        trust_chain.err.pop("metadata_policy", None)
        try:
            _policy_applier(trust_chain)
        except PolicyError:
            trust_chain.metadata.clear()
            trust_chain.combined_policy.clear()
            subject = trust_chain.verified_chain[-1]["sub"]
            trust_chain.err["metadata_policy"] = {
                "error": "invalid_metadata",
                "stage": "metadata_policy",
                "subject": subject,
                "trust_anchor": trust_chain.anchor,
            }
            logger.warning(
                "Metadata policy rejected candidate: subject=%s trust_anchor=%s "
                "error=invalid_metadata",
                subject, trust_chain.anchor,
            )
            continue
        res.append(trust_chain)
    collector = getattr(get_federation_entity(unit).function, 'trust_chain_collector', None)
    finish = getattr(collector, 'finish_policy_validation', None)
    if finish is not None:
        finish(trust_chains, res)
    return res

class Function(ImpExp):

    def __init__(self, upstream_get: Callable):
        ImpExp.__init__(self)
        self.upstream_get = upstream_get


def get_verified_trust_chains(unit, entity_id: str, stop_at: Optional[str] = "", for_resolve=False):
    """Collect, verify and apply policy using the calling operation's cache rules."""
    chains, leaf_ec = collect_trust_chains(unit, entity_id, stop_at=stop_at, for_resolve=for_resolve)
    if len(chains) == 0:
        return []

    trust_chains = verify_trust_chains(unit, chains, leaf_ec, for_resolve=for_resolve)
    trust_chains = apply_policies(unit, trust_chains)
    return trust_chains


def get_entity_endpoint(unit, entity_id, metadata_type, metadata_parameter):
    _federation_entity = get_federation_entity(unit)
    if entity_id in _federation_entity.trust_anchors:
        # Fetch Entity Configuration
        _ec = _federation_entity.client.do_request("entity_configuration", entity_id=entity_id)
        return _ec["metadata"][metadata_type][metadata_parameter]
    else:
        trust_chains = get_verified_trust_chains(unit, entity_id)
        # pick one
        if trust_chains:
            return trust_chains[0].metadata[metadata_type][metadata_parameter]
        else:
            return ""


def get_verified_jwks(unit, _signed_jwks_uri):
    # Fetch a signed JWT that contains a JWKS.
    # Verify the signature on the JWS with a federation key
    # To be implemented
    return None


class PolicyError(Exception):
    pass
