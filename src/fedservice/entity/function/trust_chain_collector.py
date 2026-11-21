import logging
from contextlib import contextmanager
from contextvars import ContextVar
from ssl import SSLError
import sys
from threading import RLock
import time
import traceback
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from idpyoidc.client.exception import WrongContentType
from idpyoidc.exception import MissingPage
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message
from requests.exceptions import ConnectionError
from requests.exceptions import ProxyError
from requests.exceptions import SSLError as RequestsSSLError
from requests.exceptions import Timeout

from fedservice.defaults import DEFAULT_MAX_REQUESTS
from fedservice.defaults import DEFAULT_MAX_SUPERIORS
from fedservice.entity.function import Function
from fedservice.entity.function import _CollectedChain
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import mutable_verified_claims
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.entity_statement.cache import ESCache
from fedservice.exception import FailedConfigurationRetrieval
from fedservice.exception import WrongSubject
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.jose import validate_entity_configuration_discovery_header
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.payload_validation import _validate_numeric_date

logger = logging.getLogger(__name__)

_EC_VALIDATION_ERRORS = (FederationJwtHeaderError, FederationJwtKeyResolutionError,
                        FederationJwtPayloadError, FederationJwtSignatureError,
                        ValueError, KeyError, TypeError, AttributeError, WrongSubject)
_CONTEXT_UNSET = object()


class _RequestLimitReached(Exception):
    """Stop collection without discarding already collected candidates."""


class _CollectedBranch(tuple):
    """Keep the entry's collection-time provenance beside its unchanged raw JWT."""

    def __new__(cls, statement, superiors, context):
        branch = super().__new__(cls, (statement, superiors))
        branch._statement_context = context
        return branch


class _CollectedTree(dict):
    """Discovery artifacts belonging to this traversal, not later cache reads."""

    def __init__(self, configurations):
        super().__init__()
        self._configuration_context = configurations


def _transient_retrieval(error):
    if isinstance(error, FailedConfigurationRetrieval):
        return error.status_code in (500, 502, 503, 504)
    return getattr(error, '_fedservice_http_outage', False)


def _peer_failure(error):
    """Mark failures only where HTTP or received statement parsing recognizes them."""
    error._fedservice_peer_failure = True
    return error


def _validate_collection_limit(name, value, minimum):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError("{} must be an integer >= {}".format(name, minimum))
    return value


def unverified_entity_statement(signed_jwt):
    _jws = factory(signed_jwt)
    if not _jws:
        raise ValueError(f"Not a proper signed JWT: {signed_jwt}")
    return _jws.jwt.payload()


def _check_subject(statement, expected_subject):
    if statement.get("sub") != expected_subject:
        raise WrongSubject("Statement subject does not match requested entity: {}".format(
            expected_subject
        ))


def verify_self_signed_signature(statement, *, for_discovery=False):
    """
    Verify signature using only keys in the entity statement.
    Will raise exception if signature verification fails.

    :param statement: Signed JWT
    :param for_discovery: Apply ordinary discovery's additional header restriction.
    :return: Payload of the signed JWT
    """

    payload = unverified_entity_statement(statement)
    keyjar = KeyJar()
    if payload['iss'] not in keyjar:
        keyjar = import_jwks(keyjar, payload['jwks'], payload['iss'])

    verified = verify_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        token=statement,
        key_jar=keyjar,
    )
    if for_discovery:
        validate_entity_configuration_discovery_header(verified.header())
    return mutable_verified_claims(verified.claims())


def get_endpoint(endpoint_type, config):
    _fe = config['metadata']['federation_entity']
    return _fe.get(f"federation_{endpoint_type}_endpoint")


def cache_key(authority, entity):
    return f"{authority}!!{entity}"


def time_key(authority, entity):
    return f"{authority}!exp!{entity}"


class TrustChainCollector(Function):

    def __init__(self,
                 upstream_get: Callable,
                 trust_anchors: dict,
                 allowed_delta: int = 300,
                 keyjar: Optional[KeyJar] = None,
                 max_superiors: int = DEFAULT_MAX_SUPERIORS,
                 max_requests: int = DEFAULT_MAX_REQUESTS,
                 refresh_fraction=None,
                 **kwargs
                 ):
        """Configure on-demand refresh independently of hard expiry.

        ``entity.init_kwargs.function.trust_chain_collector.refresh_fraction``
        selects elapsed-lifetime refresh when set to a finite number in (0, 1].
        It overrides allowed_delta, including builder defaults; None retains
        legacy delta mode. A fraction of 1 refreshes only at expiry.
        """
        if refresh_fraction is not None:
            setting = "trust_chain_collector.refresh_fraction"
            _validate_numeric_date(refresh_fraction, setting)
            if not 0 < refresh_fraction <= 1:
                raise ValueError("{} must be > 0 and <= 1".format(setting))
        Function.__init__(self, upstream_get)
        self.max_superiors = _validate_collection_limit("max_superiors", max_superiors, 0)
        self.max_requests = _validate_collection_limit("max_requests", max_requests, 1)
        self._request_budget = ContextVar("collector_request_budget", default=None)
        self.trust_anchors = trust_anchors
        self.allowed_delta = allowed_delta
        self.refresh_fraction = refresh_fraction
        self.config_cache = ESCache(allowed_delta=allowed_delta)
        self.entity_statement_cache = ESCache(allowed_delta=allowed_delta)
        self._statement_lock = RLock()
        self._statement_sequence = 0
        # Only live-entry revision/origin data, not an acceptance history. The
        # origin survives identical refreshes until applicable policy succeeds.
        self._statement_revisions = {}
        # Keep the preceding pair until ordinary chain verification decides a
        # staged replacement. Staged cache presence is not verified evidence.
        self._pending_statements = {}
        self._pending_configurations = {}
        self._configuration_lock = RLock()
        self._resolve_anchor = ContextVar('collector_resolve_anchor', default=None)
        # should not have a Key Jar of its own
        if keyjar:
            self.keyjar = keyjar
        else:
            self.keyjar = None
            keyjar = upstream_get("attribute", "keyjar")
        for id, keys in trust_anchors.items():
            keyjar = import_jwks(keyjar, keys, id)

    @contextmanager
    def using_resolve_anchor(self, verified_anchor):
        """Supply authenticated anchor evidence to one nested Resolve collection."""
        claims = verified_anchor.claims()
        if (verified_anchor.profile is not ENTITY_CONFIGURATION
                or claims['iss'] != claims['sub'] or claims['iss'] not in self.trust_anchors
                or time.time() >= claims['exp']):
            raise FederationJwtPayloadError('Selected Resolve anchor is not usable')
        token = self._resolve_anchor.set(verified_anchor)
        try:
            yield
        finally:
            self._resolve_anchor.reset(token)

    @contextmanager
    def _collection(self, max_superiors, for_resolve=False):
        if max_superiors is None:
            max_superiors = self.max_superiors
        _validate_collection_limit("max_superiors", max_superiors, 0)
        # Each public entry starts a fresh operation, including reentrant calls.
        # Only the private recursive traversal shares this context-local budget.
        token = self._request_budget.set({"remaining": self.max_requests, "exhausted": False,
                                         "for_resolve": for_resolve})
        try:
            yield max_superiors
        finally:
            self._request_budget.reset(token)

    def _get_service(self, service):
        federation_entity = get_federation_entity(self)
        return federation_entity.client.get_service(service)

    def _check_request_limit(self):
        """Check availability without charging the next HTTP invocation."""
        budget = self._request_budget.get()
        if budget is not None and budget["remaining"] == 0:
            budget["exhausted"] = True
            raise _RequestLimitReached()
        return budget

    def get_document(self, url: str, expected_content_type: str):
        """

        :param url: Target URL
        :param expected_content_type: Required successful-response media type.
        :return: Signed EntityConfiguration or SubordinateStatement
        """
        _keyjar = self.upstream_get('attribute', 'keyjar')

        _httpc_params = _keyjar.httpc_params
        logger.debug(f"keyjar.httpc_params: {_httpc_params}")
        if not _httpc_params:
            federation_entity = get_federation_entity(self)
            _httpc_params = federation_entity.httpc_params
            logger.debug(f"federation_entity.httpc_params: {_httpc_params}")

        logger.debug(f"Using HTTPC Params: {_httpc_params}")
        httpc = self.upstream_get('attribute', 'httpc')
        budget = self._check_request_limit()
        if budget is not None:
            budget["remaining"] -= 1
        try:
            response = httpc("GET", url, **_httpc_params)
        except (Timeout, ConnectionError) as err:
            # Mark only failures of the actual HTTP invocation, not exceptions
            # raised by discovery preparation, parsing or verification code.
            err._fedservice_http_outage = not isinstance(err, (RequestsSSLError, ProxyError))
            _peer_failure(err)
            logger.error(f'Could not connect to {url}:{err}')
            raise

        if response.status_code == 200:
            raw_content_type = response.headers.get("content-type")
            if not raw_content_type:
                raise _peer_failure(WrongContentType(
                    "Missing Content-Type; expected {}".format(
                        expected_content_type
                    )
                ))

            content_type = raw_content_type.split(";", 1)[0].strip().lower()
            if content_type != expected_content_type.lower():
                raise _peer_failure(WrongContentType(
                    "Expected Content-Type {}; received {}".format(
                        expected_content_type,
                        raw_content_type,
                    )
                ))
            return response.text
        elif response.status_code == 404:
            raise _peer_failure(MissingPage(f"No such page: '{url}'"))
        else:
            logger.error(f"status_code: {response.status_code} on get {url}")
            if response.text:
                logger.info(f"Error description: {response.text}")
            raise _peer_failure(FailedConfigurationRetrieval(status_code=response.status_code))

    def get_entity_configuration(self, entity_id):
        """
        Get configuration information about an entity from itself.
        The configuration information is in the format of an Entity Statement

        :param entity_id: About whom the entity statement should be
        :return: Configuration information as a signed JWT
        """
        logger.debug(f"--get_configuration_information({entity_id})")
        _serv = self._get_service('entity_configuration')
        _res = _serv.get_request_parameters(request_args={"entity_id": entity_id})
        logger.debug(f"Get configuration from: {_res['url']}")
        try:
            # if self.use_ssc:
            #     logger.debug("Use SelfSignedCert support")
            #     self_signed_config = self.do_ssc_seq(_url, entity_id)
            # else:
            self_signed_config = self.get_document(
                _res['url'],
                ENTITY_CONFIGURATION.content_type,
            )
        except SSLError as err:
            logger.error(err)
            raise
        except ConnectionError as err:
            logger.error(err)
            raise
        except Exception as err:
            logger.exception(err)
            raise

        # This rejects mismatched candidates; it does not establish trust.
        try:
            _check_subject(unverified_entity_statement(self_signed_config), entity_id)
        except (ValueError, KeyError, TypeError, AttributeError, WrongSubject) as error:
            raise _peer_failure(error)
        return self_signed_config

    def get_metadata(self, entity_id):
        _ec = self.config_cache[entity_id]
        if _ec is not None:
            _check_subject(_ec, entity_id)
        if _ec is None or self.too_old(_ec):
            _federation_entity = get_federation_entity(self)
            _chains, _ = collect_trust_chains(_federation_entity, entity_id)
            _trust_chains = verify_trust_chains(_federation_entity, _chains)
            _ec = self.config_cache[entity_id]
        if _ec is None:
            raise FailedConfigurationRetrieval("Entity Configuration expired during metadata retrieval")
        _check_subject(_ec, entity_id)
        return _ec['metadata']

    def get_verified_self_signed_entity_configuration(self, entity_id: str) -> str:
        signed_entity_config = self.get_entity_configuration(entity_id)
        if signed_entity_config is None:
            return ''

        entity_config = verify_self_signed_signature(signed_entity_config, for_discovery=True)
        _check_subject(entity_config, entity_id)
        if time.time() >= entity_config["exp"]:
            raise FederationJwtPayloadError("Entity Configuration has expired")
        return entity_config

    def _get_cached_entity_configuration(self, entity_id, require_fetch_endpoint=False,
                                         for_resolve=False):
        anchor = self._resolve_anchor.get() if for_resolve else None
        if anchor is not None and anchor.claims()['sub'] == entity_id:
            if entity_id not in self.trust_anchors or time.time() >= anchor.claims()['exp']:
                raise FederationJwtPayloadError('Selected Resolve anchor is not usable')
            claims = mutable_verified_claims(anchor.claims())
            claims['_jws'] = anchor.raw_token()
            return claims, anchor.raw_token()
        with self._configuration_lock:
            entity_config = self.config_cache[entity_id]
            pending = self._pending_configurations.get(entity_id)
            previous = (pending[1] if pending is not None and (
                pending[0] is entity_config or (for_resolve and entity_config is None))
                        else entity_config)
        signed = None
        if entity_config is not None:
            _check_subject(entity_config, entity_id)
            signed = entity_config.get("_jws") or getattr(entity_config, "_jws", None)
            if (signed and not self.too_old(entity_config) and
                    (not require_fetch_endpoint or get_endpoint("fetch", entity_config))):
                _check_subject(unverified_entity_statement(signed), entity_id)
                return entity_config, signed
            # A locally denied refresh must not evict a completed candidate's EC.
            self._check_request_limit()
        try:
            replacement = self.get_entity_configuration(entity_id)
        except Exception as error:
            if for_resolve:
                if getattr(error, '_fedservice_peer_failure', False):
                    retained = self._retained_configuration(entity_id, previous)
                    if retained is not None:
                        self._restore_configuration(entity_id, pending, retained)
                        return retained, retained['_jws']
                raise
            if (_transient_retrieval(error) and entity_config is not None and signed
                    and time.time() < entity_config['exp']
                    and self.config_cache[entity_id] is not None):
                _check_subject(unverified_entity_statement(signed), entity_id)
                return entity_config, signed
            self._discard_configuration(entity_id, entity_config)
            raise
        try:
            if not replacement:
                if for_resolve:
                    retained = self._retained_configuration(entity_id, previous)
                    self._restore_configuration(entity_id, pending, retained)
                    return (retained, retained['_jws']) if retained is not None else (None, None)
                self._discard_configuration(entity_id, entity_config)
                return None, None
            fresh = verify_self_signed_signature(replacement, for_discovery=True)
            _check_subject(fresh, entity_id)
            # Apply only hard expiry to newly fetched material. Repeating early
            # refresh here could loop when its lifetime is shorter than allowed_delta.
            if time.time() >= fresh['exp']:
                raise FederationJwtPayloadError("Entity Configuration has expired")
        except Exception as error:
            if for_resolve:
                if isinstance(error, _EC_VALIDATION_ERRORS):
                    retained = self._retained_configuration(entity_id, previous)
                    if retained is not None:
                        self._restore_configuration(entity_id, pending, retained)
                        return retained, retained['_jws']
                raise
            self._discard_configuration(entity_id, entity_config)
            raise
        fresh['_jws'] = replacement
        with self._configuration_lock:
            current = self.config_cache[entity_id]
            if current is None or current is entity_config:
                if for_resolve or (entity_config is not None and signed):
                    self._pending_configurations[entity_id] = (fresh, previous)
                self.config_cache[entity_id] = fresh
        return fresh, replacement

    def _retained_configuration(self, entity_id, previous):
        if previous is None or not previous.get('_jws') or time.time() >= previous['exp']:
            return None
        try:
            claims = verify_self_signed_signature(previous['_jws'], for_discovery=True)
            _check_subject(claims, entity_id)
            if claims['exp'] != previous['exp'] or time.time() >= claims['exp']:
                return None
        except _EC_VALIDATION_ERRORS:
            return None
        return previous

    def _configuration_context(self, entity_id, configuration):
        with self._configuration_lock:
            pending = self._pending_configurations.get(entity_id)
            if pending is not None and pending[0] is not configuration:
                pending = None
            return {entity_id: (configuration, pending)}

    def _discard_configuration(self, entity_id, previous):
        with self._configuration_lock:
            if previous is not None and self.config_cache[entity_id] is previous:
                del self.config_cache[entity_id]
                self._pending_configurations.pop(entity_id, None)

    def finish_configuration_verification(self, entity_id, token, accepted,
                                          context=_CONTEXT_UNSET):
        """Finish a retained EC replacement after established-trust verification."""
        with self._configuration_lock:
            pending = self._pending_configurations.get(entity_id)
            if context is not _CONTEXT_UNSET and (context is None or pending is not context[1]):
                return
            if (accepted and context is not _CONTEXT_UNSET
                    and self.config_cache[entity_id] is context[0]):
                # Independent acceptance owns a new cache identity even when
                # its signed bytes are unchanged. Older retrievals cannot publish over it.
                self.config_cache[entity_id] = dict(context[0])
            if pending is not None and pending[0].get('_jws') == token:
                if not accepted:
                    self._discard_configuration(entity_id, pending[0])
                if self._pending_configurations.get(entity_id) is pending:
                    self._pending_configurations.pop(entity_id, None)

    def retain_configuration(self, entity_id, context):
        """Revalidate prior evidence without overwriting an independent cache owner."""
        if context is None or context[1] is None:
            return None
        _, pending = context
        previous = self._retained_configuration(entity_id, pending[1])
        self._restore_configuration(entity_id, pending, previous)
        return previous

    def _restore_configuration(self, entity_id, pending, previous):
        if pending is None or previous is None:
            return
        with self._configuration_lock:
            current = self.config_cache[entity_id]
            if (self._pending_configurations.get(entity_id) is pending and
                    (current is pending[0] or current is None)):
                self.config_cache[entity_id] = previous
                self._pending_configurations.pop(entity_id)

    def retry_configuration_verification(self, chain, rejected):
        """Retry rejected subject ECs without another discovery request."""
        configurations = dict(getattr(chain, '_configuration_context', {}))
        replacements = {}
        for entity_id, context in configurations.items():
            token = context[0].get('_jws')
            if token in rejected:
                previous = self.retain_configuration(entity_id, context)
                if previous is not None and previous['_jws'] != token:
                    replacements[token] = previous['_jws']
                    configurations[entity_id] = (previous, None)
        if replacements:
            return _CollectedChain([replacements.get(token, token) for token in chain],
                                   getattr(chain, '_statement_context', {}), configurations)
        return None

    def get_federation_fetch_endpoint(self, intermediate: str) -> str:
        logger.debug(f'--get_federation_fetch_endpoint({intermediate})')
        entity_config, _ = self._get_cached_entity_configuration(
            intermediate, require_fetch_endpoint=True)
        return get_endpoint("fetch", entity_config) if entity_config is not None else ''

    def get_entity_statement(self, fetch_endpoint, issuer, subject):
        """
        Get Entity Statement by one entity about another or about itself

        :param fetch_endpoint: The federation fetch endpoint
        :param issuer: Who should issue the entity statement
        :param subject: About whom the entity statement should be
        :return: A signed JWT
        """
        _serv = self._get_service('entity_statement')
        _res = _serv.get_request_parameters(subject=subject, fetch_endpoint=fetch_endpoint)

        # if self.use_ssc:
        #     signed_entity_statement = self.do_ssc_seq(_url, issuer)
        # else:
        try:
            statement = self.get_document(
                _res['url'],
                SUBORDINATE_STATEMENT.content_type,
            )
            try:
                _check_subject(unverified_entity_statement(statement), subject)
            except (ValueError, KeyError, TypeError, AttributeError, WrongSubject) as error:
                raise _peer_failure(error)
            return statement
        except FailedConfigurationRetrieval:
            logger.error(f"Failed to fetch {_res['url']}")
            logger.error(f"Request: {_res}")
            raise

    def collect_tree(self,
                     entity_id: str,
                     entity_configuration: Union[dict, Message],
                     seen: Optional[list] = None,
                     max_superiors: Optional[int] = None,
                     stop_at: Optional[str] = "") -> Optional[dict]:
        """
        Collect superiors one level at the time

        :param entity_id: The entity ID
        :param entity_configuration: Entity Configuration as a dictionary
        :param seen: Authorities on the current path, for cycles and depth.
        :param max_superiors: Maximum superior hops; None uses the instance setting.
        :param stop_at: The ID of the trust anchor at which the trust chain should stop.
        :return: Dictionary of superiors
        """
        with self._collection(max_superiors) as limit:
            return self._collect_tree(entity_id, entity_configuration, seen, limit, stop_at)

    def _collect_tree(self, entity_id, entity_configuration, seen, max_superiors, stop_at):
        budget = self._request_budget.get()
        superior = (_CollectedTree(self._configuration_context(entity_id, entity_configuration))
                    if budget['for_resolve'] else {})
        if entity_configuration is None or time.time() >= entity_configuration["exp"]:
            raise FederationJwtPayloadError("Entity Configuration is unavailable or expired")
        if seen is None:
            seen = []

        logger.debug(f'Collect superiors to: {entity_id}')
        logger.debug(f'Collect based on: {entity_configuration}')
        if 'authority_hints' not in entity_configuration:
            logger.debug("No authority for this entity")
            return superior
        elif entity_configuration['iss'] == stop_at:
            logger.debug("Reached stop point")
            return superior
        if len(seen) >= max_superiors:
            return superior

        logger.debug(f"Authority_hints: {entity_configuration['authority_hints']}")
        budget = self._request_budget.get()
        for authority in entity_configuration['authority_hints']:
            # Siblings share the allowance: another branch must not restart HTTP work.
            if budget["exhausted"]:
                break
            logger.info(f"authority: {authority}")
            # seen detects cycles on this path; siblings may share an authority.
            if authority in seen:
                logger.warning(f"Loop detected at {authority}")
                continue
            try:
                superior[authority] = self._collect_branch(entity_id, authority, seen,
                                                           max_superiors, stop_at)
            except _RequestLimitReached:
                break
            except Exception:
                # Malformed peer data can also raise KeyError or TypeError.
                # Keep this failure local so the authority-hints loop can
                # still find an independent valid chain.
                message = traceback.format_exception(*sys.exc_info())
                logger.error(message)
                continue

        return superior

    def _cached_entity_statement(self, entity, authority, refresh=False, for_resolve=False):
        return self._cached_statement(entity, authority, refresh, for_resolve=for_resolve)[0]

    def _cached_statement(self, entity, authority, refresh=False, for_resolve=False):
        with self._statement_lock:
            state = self._statement_snapshot(entity, authority)
            pending = self._statement_record(entity, authority, state)
            if (for_resolve and pending is not None and state[0] is not None
                    and state[1] is not None and time.time() >= state[1]):
                retained = self._retained_statement(entity, authority, state, pending)
                if retained is not None:
                    # Restore only the live revision, before any reader retires
                    # its pending record. The pair still needs ordinary verification.
                    restored = self._store_statement(entity, authority, *pending[2], original=pending[2])
                    self._retire_statement(entity, authority, state)
                    state, pending = restored, None
        entity_statement, expiry, _ = state
        if entity_statement is None or expiry is None or time.time() >= expiry:
            self._discard_statement(entity, authority, state)
            return None, None
        statement = unverified_entity_statement(entity_statement)
        _check_subject(statement, entity)
        if statement.get('exp') != expiry:
            self._discard_statement(entity, authority, state)
            return None, None
        if refresh and self.too_old(statement):
            return None, None
        return entity_statement, pending

    def _statement_pair(self, entity, authority):
        return self._statement_snapshot(entity, authority)[:2]

    def _statement_snapshot(self, entity, authority):
        with self._statement_lock:
            revision = self._statement_revisions.get((authority, entity))
            return (self.entity_statement_cache[cache_key(authority, entity)],
                    self.entity_statement_cache[time_key(authority, entity)],
                    revision[0] if revision is not None else None)

    def _statement_record(self, entity, authority, state):
        with self._statement_lock:
            pending = self._pending_statements.get((authority, entity))
            if pending is not None and self._pending_state(pending) == state:
                return pending
            revision = self._statement_revisions.get((authority, entity))
            if revision is not None and revision[0] == state[2] and revision[1] != state[:2]:
                return state[0], state[1], revision[1], state[2]
            return None

    @staticmethod
    def _pending_state(pending):
        return pending[0], pending[1], pending[3]

    def _advance_statement_revision(self, entity, authority, original):
        # Callers hold the collector lock; deletion never resets this sequence.
        self._statement_sequence += 1
        self._statement_revisions[(authority, entity)] = (self._statement_sequence, original)
        return self._statement_sequence

    def _store_statement(self, entity, authority, token, expiry, original):
        with self._statement_lock:
            self.entity_statement_cache[cache_key(authority, entity)] = token
            self.entity_statement_cache[time_key(authority, entity)] = expiry
            revision = self._advance_statement_revision(entity, authority, original)
            return token, expiry, revision

    def _retire_statement(self, entity, authority, state):
        with self._statement_lock:
            pending = self._pending_statements.get((authority, entity))
            if pending is not None and self._pending_state(pending) == state:
                self._pending_statements.pop((authority, entity))

    def _discard_statement(self, entity, authority, previous):
        with self._statement_lock:
            if self._statement_snapshot(entity, authority) != previous:
                return
            for key in (cache_key(authority, entity), time_key(authority, entity)):
                if key in self.entity_statement_cache:
                    del self.entity_statement_cache[key]
            self._statement_revisions.pop((authority, entity), None)
            self._retire_statement(entity, authority, previous)

    def finish_statement_verification(self, chains, accepted, constraint_rejections=()):
        """Finalize staged cache pairs from the existing chain verifier's results."""
        examined = {token for chain in chains for token in chain}
        usable = {token: claims for chain in accepted for token, claims in zip(
            chain.chain[-len(chain.verified_chain):], chain.verified_chain)}
        constrained = {token for chain in constraint_rejections for token in chain}
        invalid = {token for chain in chains
                   for token in getattr(chain, '_statement_failures', ())}
        contexts = {record for chain in chains
                    for record in getattr(chain, '_statement_context', {}).items()}
        with self._statement_lock:
            for chain in accepted:
                # Collection-time provenance cannot acquire a newer revision's
                # deletion rights just because its compact JWT is identical.
                chain._statement_replacements = {}
                chain._statement_restorations = {}
                context = getattr(chain.chain, '_statement_context', {})
                raw = chain.chain[-len(chain.verified_chain):]
                for token, claims in zip(raw[:-1], chain.verified_chain[:-1]):
                    pair = (claims['iss'], claims['sub'])
                    pending = context.get(pair)
                    if (pending is not None and pending[:2] == (token, claims['exp'])
                            and pending[:2] != pending[2]):
                        chain._statement_replacements[pair] = self._pending_state(pending)
            for (authority, entity), pending in list(self._pending_statements.items()):
                token, expiry, previous, revision = pending
                state = (token, expiry, revision)
                if token not in examined or ((authority, entity), pending) not in contexts:
                    continue
                if token not in usable and previous[0] is not None:
                    retained = next(((raw, claims['exp']) for raw, claims in usable.items()
                                     if claims['iss'] == authority and claims['sub'] == entity
                                     and time.time() < claims['exp']), None)
                    if ((token in constrained or token in invalid) and retained is not None
                            and self._statement_snapshot(entity, authority) == state):
                        # Keep the actual accepted pair, including FCONF-134's
                        # changed first refresh, subject to its policy decision.
                        restored = self._store_statement(entity, authority, *retained, original=previous)
                        for chain in accepted:
                            # Carry restoration ownership on participating siblings,
                            # not just the candidate selected before policy runs.
                            if any(claims['iss'] == authority and claims['sub'] == entity
                                   for claims in chain.verified_chain[:-1]):
                                chain._statement_restorations[(authority, entity)] = restored
                            if retained != previous and retained[0] in chain.chain[-len(chain.verified_chain):]:
                                chain._statement_replacements[(authority, entity)] = restored
                        self._retire_statement(entity, authority, state)
                    else:
                        self._discard_statement(entity, authority, state)
                else:
                    self._retire_statement(entity, authority, state)
        for chain in chains:
            getattr(chain, '_statement_context', {}).clear()
        for chain in chains:
            configurations = getattr(chain, '_configuration_context', {})
            for entity_id, context in configurations.items():
                token = context[0]['_jws']
                # An earlier SS rejection may prevent examining this EC at all.
                if token in usable or token in invalid or token in constrained:
                    self.finish_configuration_verification(entity_id, token, token in usable, context)
        if not any(getattr(chain, '_configuration_context', {}) for chain in chains):
            for entity_id, (fresh, previous) in list(self._pending_configurations.items()):
                token = fresh['_jws']
                if token in examined:
                    self.finish_configuration_verification(entity_id, token, token in usable)

    def finish_policy_validation(self, chains, accepted):
        """Reconcile tentative restorations and discard owned rejected replacements."""
        with self._statement_lock:
            restorations = {item for chain in chains for item in
                            chain.__dict__.pop('_statement_restorations', {}).items()}
            usable = []
            # Successful chain AND policy validation protects the matching live
            # entry from older cleanup, even if this operation only reused it.
            for chain in accepted:
                if not getattr(chain, 'chain', None):
                    continue
                raw = chain.chain[-len(chain.verified_chain):]
                for token, claims in zip(raw[:-1], chain.verified_chain[:-1]):
                    usable.append((token, claims))
                    authority, entity = claims['iss'], claims['sub']
                    state = self._statement_snapshot(entity, authority)
                    if state[:2] == (token, claims['exp']) and time.time() < claims['exp']:
                        self._advance_statement_revision(entity, authority, state[:2])
                        self._retire_statement(entity, authority, state)
            for (authority, entity), state in restorations:
                # Only this attempt's unchanged restoration may be reconciled.
                # Missing entries and independently advanced revisions stay intact.
                if self._statement_snapshot(entity, authority) != state:
                    continue
                retained = next(((token, claims['exp']) for token, claims in usable
                                 if claims['iss'] == authority and claims['sub'] == entity
                                 and time.time() < claims['exp']), None)
                if retained is not None:
                    self._store_statement(entity, authority, *retained, original=retained)
                    self._retire_statement(entity, authority, state)
                else:
                    # This leaf's policy failure does not invalidate an unchanged
                    # shared original. Never resurrect it from a rejected replacement.
                    original = self._statement_revisions[(authority, entity)][1]
                    if state[:2] != original or time.time() >= state[1]:
                        self._discard_statement(entity, authority, state)
            for chain in chains:
                replacements = chain.__dict__.pop('_statement_replacements', {})
                if chain in accepted:
                    continue
                # Candidate-local rejection may discard only the captured entry
                # revision, never an identical pair accepted or recreated later.
                for (authority, entity), state in replacements.items():
                    self._discard_statement(entity, authority, state)

    def _get_entity_statement(self, entity: str, authority: str,
                              fetch_endpoint: Optional[str] = None) -> Optional[str]:
        return self._get_statement(entity, authority, fetch_endpoint)[0]

    def _get_statement(self, entity, authority, fetch_endpoint=None, for_resolve=False):
        entity_statement, record = self._cached_statement(
            entity, authority, refresh=True, for_resolve=for_resolve)
        if entity_statement is None:
            with self._statement_lock:
                previous = self._statement_snapshot(entity, authority)
                record = self._statement_record(entity, authority, previous)
            logger.debug(f"Have not seen '{authority}' before")
            fed_fetch_endpoint = (self.get_federation_fetch_endpoint(authority)
                                  if fetch_endpoint is None else fetch_endpoint)
            if not fed_fetch_endpoint:
                return None, None
            logger.debug(f"Federation fetch endpoint: '{fed_fetch_endpoint}' for '{authority}'")
            self._check_request_limit()
            try:
                entity_statement = self.get_entity_statement(fed_fetch_endpoint, authority, entity)
            except Exception as error:
                if for_resolve:
                    if getattr(error, '_fedservice_peer_failure', False):
                        retained = self._retained_statement(entity, authority, previous, record)
                        if retained is not None:
                            return retained, None
                    # A local error must not erase independently accepted evidence.
                    raise
                if (_transient_retrieval(error) and previous[0] is not None
                        and previous[1] is not None and time.time() < previous[1]
                        and self._cached_entity_statement(entity, authority) is not None):
                    return previous[0], record
                self._discard_statement(entity, authority, previous)
                raise
            try:
                # This hint can reject stale material, never establish trust.
                statement = unverified_entity_statement(entity_statement)
                _check_subject(statement, entity)
                if statement.get('iss') != authority:
                    raise FederationJwtPayloadError("Statement issuer does not match requested authority")
                _validate_numeric_date(statement.get("exp"), "exp")
                if time.time() >= statement["exp"]:
                    if for_resolve:
                        return self._retained_statement(entity, authority, previous, record), None
                    self._discard_statement(entity, authority, previous)
                    return None, None
            except Exception as error:
                if for_resolve:
                    if isinstance(error, (ValueError, KeyError, TypeError, AttributeError, WrongSubject)):
                        retained = self._retained_statement(entity, authority, previous, record)
                        if retained is not None:
                            return retained, None
                    raise
                self._discard_statement(entity, authority, previous)
                raise
            logger.debug(
                f"Unverified entity statement from {fed_fetch_endpoint} about {entity}: "
                f"{statement}")
            with self._statement_lock:
                record = None
                if self._statement_snapshot(entity, authority) == previous:
                    pending = self._statement_record(entity, authority, previous)
                    retained = pending[2] if pending is not None else previous[:2]
                    state = self._store_statement(entity, authority, entity_statement, statement['exp'],
                                                  original=retained)
                    record = (entity_statement, statement['exp'], retained, state[2])
                    self._pending_statements[(authority, entity)] = record

        _check_subject(unverified_entity_statement(entity_statement), entity)

        return entity_statement, record

    def _retained_statement(self, entity, authority, state, record):
        """Return preceding evidence for normal verification, never a tentative refresh."""
        token, expiry = record[2] if record is not None else state[:2]
        if token is None or expiry is None:
            return None
        if time.time() >= expiry:
            if state[1] is not None and time.time() >= state[1]:
                self._discard_statement(entity, authority, state)
            return None
        claims = unverified_entity_statement(token)
        if (claims.get('iss') != authority or claims.get('sub') != entity
                or claims.get('exp') != expiry):
            return None
        return token

    def retry_statement_verification(self, chain, rejected, accepted=()):
        """Roll back owned invalid SS objects and build a no-HTTP candidate retry."""
        context = dict(getattr(chain, '_statement_context', {}))
        replacements = {}
        with self._statement_lock:
            for (authority, entity), pending in list(context.items()):
                token, expiry, previous, revision = pending
                if token not in rejected:
                    continue
                state = (token, expiry, revision)
                sibling = next(((raw, candidate) for candidate in accepted
                                for raw, claims in zip(
                                    candidate.chain[-len(candidate.verified_chain):],
                                    candidate.verified_chain)
                                if claims['iss'] == authority and claims['sub'] == entity
                                and raw != token and time.time() < claims['exp']), None)
                if sibling is not None:
                    # Finalization reconciles this already verified sibling with
                    # policy validation before promoting it to accepted state.
                    replacements[token] = sibling[0]
                    provenance = getattr(sibling[1].chain, '_statement_context', {})
                    if (authority, entity) in provenance:
                        context[(authority, entity)] = provenance[(authority, entity)]
                    else:
                        context.pop((authority, entity))
                    continue
                retained = self._retained_statement(entity, authority, state, pending)
                if retained is None or retained == token:
                    continue
                # An independent acceptance or recreation owns the live entry now.
                if self._statement_snapshot(entity, authority) != state:
                    continue
                self._store_statement(entity, authority, *previous, original=previous)
                self._retire_statement(entity, authority, state)
                replacements[token] = retained
                context.pop((authority, entity))
        if replacements:
            return _CollectedChain([replacements.get(token, token) for token in chain], context,
                                   getattr(chain, '_configuration_context', {}))
        return None

    def collect_branch(self, entity, authority, seen=None, max_superiors=None, stop_at=""):
        """
        Collect an entity statement about an entity submitted by another entity, the authority.
        This consist of first finding the fed_fetch_endpoint URL for the authority and then
        asking the authority for its view of the entity.

        :param authority: An authority from the authority_hints
        :param stop_at: When this entity ID is reached stop processing
        :param entity: The ID of the entity
        :param seen: Authorities on the current path, for cycles and depth.
        :param max_superiors: Maximum superior hops; None uses the instance setting.
        :return:
        """
        with self._collection(max_superiors) as limit:
            try:
                return self._collect_branch(entity, authority, seen, limit, stop_at)
            except _RequestLimitReached:
                return None

    def _collect_branch(self, entity, authority, seen, max_superiors, stop_at):
        logger.debug(f'Get view of "{entity}" from "{authority}"')
        # Should I stop when I reach the first trust anchor ?
        if entity == authority and entity in self.trust_anchors:
            return None

        if seen is None:
            _seen = []
        else:
            _seen = seen[:]

        _seen.append(authority)
        if len(_seen) > max_superiors:
            logger.debug("Reached max superiors on path %s", _seen)
            return None

        previous = self._statement_snapshot(entity, authority)
        budget = self._request_budget.get()
        remaining = budget["remaining"]
        discovery_complete = False
        try:
            # Refresh authority discovery even when its subordinate JWT is cached.
            needs_fetch = self._cached_entity_statement(
                entity, authority, refresh=True, for_resolve=budget['for_resolve']) is None
            _entity_configuration, _ = self._get_cached_entity_configuration(
                authority, require_fetch_endpoint=needs_fetch, for_resolve=budget['for_resolve'])
            if _entity_configuration is None:
                return None
            discovery_complete = True
            if budget['for_resolve'] and authority not in self.trust_anchors:
                context = self._configuration_context(authority, _entity_configuration)[authority]
                self.finish_configuration_verification(
                    authority, _entity_configuration['_jws'], True, context)
            entity_statement, record = self._get_statement(
                entity, authority, fetch_endpoint=get_endpoint("fetch", _entity_configuration) or '',
                for_resolve=budget["for_resolve"])
        except _RequestLimitReached:
            # No early eviction needs rollback. Failed discovery requests
            # must not be treated as quota-only retention.
            if (not budget['for_resolve'] and not discovery_complete
                    and budget['remaining'] != remaining):
                self._discard_statement(entity, authority, previous)
            raise
        except Exception:
            if not budget['for_resolve'] and not discovery_complete:
                self._discard_statement(entity, authority, previous)
            raise

        if entity_statement:
            if not budget['for_resolve']:
                _entity_configuration = self.config_cache[authority]
            superiors = self._collect_tree(
                authority, _entity_configuration, _seen, max_superiors, stop_at)
            context = {(authority, entity): record} if record is not None else {}
            return _CollectedBranch(entity_statement, superiors, context)
        else:
            return None

    def too_old(self, statement):
        """Check refresh eligibility, not acceptance or hard expiry.

        Fraction mode uses signed iat/exp without resetting their threshold on
        retrieval. A valid already-due replacement is usable for this lookup;
        a later lookup may fetch it again. This is not rate limiting or an
        operation-wide fetch-count guarantee.
        """
        if self.refresh_fraction is None:
            return time.time() >= statement["exp"] - max(0, self.allowed_delta)
        try:
            issued_at, expires_at = statement["iat"], statement["exp"]
            _validate_numeric_date(issued_at, "iat")
            _validate_numeric_date(expires_at, "exp")
            if expires_at <= issued_at:
                raise ValueError("exp must be after iat")
            refresh_at = (expires_at if self.refresh_fraction == 1 else
                          issued_at + self.refresh_fraction * (expires_at - issued_at))
            _validate_numeric_date(refresh_at, "refresh threshold")
        except (KeyError, TypeError, ValueError, OverflowError) as err:
            raise FederationJwtPayloadError("Invalid statement lifetime for refresh") from err
        return time.time() >= refresh_at

    def __call__(self,
                 entity_id: str,
                 max_superiors: Optional[int] = None,
                 seen: Optional[List[str]] = None,
                 stop_at: Optional[str] = '',
                 for_resolve: bool = False):
        """Collect from the subject EC with one operation-local HTTP allowance."""
        with self._collection(max_superiors, for_resolve=for_resolve) as limit:
            try:
                entity_config, signed_entity_config = self._get_cached_entity_configuration(
                    entity_id, for_resolve=for_resolve)
                if entity_config is None:
                    return None
                return self._collect_tree(entity_id, entity_config, seen, limit,
                                          stop_at), signed_entity_config
            except _RequestLimitReached:
                return None

    def add_trust_anchor(self, entity_id, jwks):
        if self.keyjar:
            _keyjar = self.keyjar
        elif self.upstream_get:
            _keyjar = self.upstream_get('attribute', 'keyjar')
        else:
            raise ValueError("Missing keyjar")

        _keyjar = import_jwks(_keyjar, jwks, entity_id)
        self.trust_anchors[entity_id] = jwks

    def get_chain(self, iss_path, trust_anchor, with_ta_ec: Optional[bool] = False):
        # Entity configuration for the leaf
        leaf = self.config_cache[iss_path[0]]
        if leaf is None:
            raise FederationJwtPayloadError("Chain Entity Configuration is unavailable or expired")
        res = [leaf['_jws']]
        # Entity statements up the chain
        for i in range(len(iss_path) - 1):
            statement = self._cached_entity_statement(iss_path[i], iss_path[i + 1])
            if statement is None:
                raise FederationJwtPayloadError("Chain Subordinate Statement is unavailable or expired")
            res.append(statement)
        # Possibly add Trust Anchor entity configuration
        if with_ta_ec and (len(iss_path) != 1 or iss_path[0] != trust_anchor):
            anchor = self.config_cache[trust_anchor]
            if anchor is None:
                raise FederationJwtPayloadError("Chain anchor configuration is unavailable or expired")
            res.append(anchor['_jws'])
        return res
