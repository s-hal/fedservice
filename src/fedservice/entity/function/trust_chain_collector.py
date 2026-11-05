import logging
from contextlib import contextmanager
from contextvars import ContextVar
from ssl import SSLError
import sys
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
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import mutable_verified_claims
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.entity_statement.cache import ESCache
from fedservice.exception import FailedConfigurationRetrieval
from fedservice.exception import WrongSubject
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.jose import validate_entity_configuration_discovery_header
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.payload_validation import _validate_numeric_date

logger = logging.getLogger(__name__)


class _RequestLimitReached(Exception):
    """Stop collection without discarding already collected candidates."""


def _transient_retrieval(error):
    if isinstance(error, FailedConfigurationRetrieval):
        return error.status_code in (500, 502, 503, 504)
    return getattr(error, '_fedservice_http_outage', False)


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
        # Keep the preceding pair until ordinary chain verification decides a
        # staged replacement. Staged cache presence is not verified evidence.
        self._pending_statements = {}
        self._pending_configurations = {}
        # should not have a Key Jar of its own
        if keyjar:
            self.keyjar = keyjar
        else:
            self.keyjar = None
            keyjar = upstream_get("attribute", "keyjar")
        for id, keys in trust_anchors.items():
            keyjar = import_jwks(keyjar, keys, id)

    @contextmanager
    def _collection(self, max_superiors):
        if max_superiors is None:
            max_superiors = self.max_superiors
        _validate_collection_limit("max_superiors", max_superiors, 0)
        # Each public entry starts a fresh operation, including reentrant calls.
        # Only the private recursive traversal shares this context-local budget.
        token = self._request_budget.set({"remaining": self.max_requests, "exhausted": False})
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
            logger.error(f'Could not connect to {url}:{err}')
            raise

        if response.status_code == 200:
            raw_content_type = response.headers.get("content-type")
            if not raw_content_type:
                raise WrongContentType(
                    "Missing Content-Type; expected {}".format(
                        expected_content_type
                    )
                )

            content_type = raw_content_type.split(";", 1)[0].strip().lower()
            if content_type != expected_content_type.lower():
                raise WrongContentType(
                    "Expected Content-Type {}; received {}".format(
                        expected_content_type,
                        raw_content_type,
                    )
                )
            return response.text
        elif response.status_code == 404:
            raise MissingPage(f"No such page: '{url}'")
        else:
            logger.error(f"status_code: {response.status_code} on get {url}")
            if response.text:
                logger.info(f"Error description: {response.text}")
            raise FailedConfigurationRetrieval(status_code=response.status_code)

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
        except MissingPage:  # if tenant involved
            _tres = _serv.get_request_parameters(request_args={"entity_id": entity_id}, tenant=True)
            logger.debug(f"Get configuration from (tenant): '{entity_id}'")
            if _tres["url"] != _res["url"]:
                # if self.use_ssc:
                #     self_signed_config = self.do_ssc_seq(_tenant_url, entity_id)
                # else:
                self_signed_config = self.get_document(
                    _tres["url"],
                    ENTITY_CONFIGURATION.content_type,
                )
                logger.debug(f'Self signed statement: {self_signed_config}')
            else:
                raise MissingPage(f"No such page: '{_tres['url']}'")
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
        _check_subject(unverified_entity_statement(self_signed_config), entity_id)
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

    def _get_cached_entity_configuration(self, entity_id, require_fetch_endpoint=False):
        entity_config = self.config_cache[entity_id]
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
            if (_transient_retrieval(error) and entity_config is not None and signed
                    and time.time() < entity_config['exp']
                    and self.config_cache[entity_id] is not None):
                _check_subject(unverified_entity_statement(signed), entity_id)
                return entity_config, signed
            self._discard_configuration(entity_id, entity_config)
            raise
        try:
            if not replacement:
                self._discard_configuration(entity_id, entity_config)
                return None, None
            fresh = verify_self_signed_signature(replacement, for_discovery=True)
            _check_subject(fresh, entity_id)
            # Apply only hard expiry to newly fetched material. Repeating early
            # refresh here could loop when its lifetime is shorter than allowed_delta.
            if time.time() >= fresh['exp']:
                raise FederationJwtPayloadError("Entity Configuration has expired")
        except Exception:
            self._discard_configuration(entity_id, entity_config)
            raise
        fresh['_jws'] = replacement
        current = self.config_cache[entity_id]
        if current is None or current is entity_config:
            if entity_config is not None and signed:
                self._pending_configurations[entity_id] = (fresh, entity_config)
            self.config_cache[entity_id] = fresh
        return fresh, replacement

    def _discard_configuration(self, entity_id, previous):
        if previous is not None and self.config_cache[entity_id] is previous:
            del self.config_cache[entity_id]
            self._pending_configurations.pop(entity_id, None)

    def finish_configuration_verification(self, entity_id, token, accepted):
        """Finish a retained EC replacement after established-trust verification."""
        pending = self._pending_configurations.get(entity_id)
        if pending is not None and pending[0].get('_jws') == token:
            if not accepted:
                self._discard_configuration(entity_id, pending[0])
            self._pending_configurations.pop(entity_id, None)

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
            _check_subject(unverified_entity_statement(statement), subject)
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
        superior = {}
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

    def _cached_entity_statement(self, entity, authority, refresh=False):
        _cache_key = cache_key(authority, entity)
        _time_key = time_key(authority, entity)
        entity_statement = self.entity_statement_cache[_cache_key]
        expiry = self.entity_statement_cache[_time_key]
        if entity_statement is None or expiry is None or time.time() >= expiry:
            self._discard_statement(entity, authority, (entity_statement, expiry))
            return None
        statement = unverified_entity_statement(entity_statement)
        _check_subject(statement, entity)
        if statement.get('exp') != expiry:
            self._discard_statement(entity, authority, (entity_statement, expiry))
            return None
        if refresh and self.too_old(statement):
            return None
        return entity_statement

    def _statement_pair(self, entity, authority):
        return (self.entity_statement_cache[cache_key(authority, entity)],
                self.entity_statement_cache[time_key(authority, entity)])

    def _discard_statement(self, entity, authority, previous):
        if self._statement_pair(entity, authority) == previous:
            for key in (cache_key(authority, entity), time_key(authority, entity)):
                if key in self.entity_statement_cache:
                    del self.entity_statement_cache[key]
            self._pending_statements.pop((authority, entity), None)

    def finish_statement_verification(self, chains, accepted, constraint_rejections=()):
        """Finalize staged cache pairs from the existing chain verifier's results."""
        examined = {token for chain in chains for token in chain}
        usable = {token: claims for chain in accepted for token, claims in zip(
            chain.chain[-len(chain.verified_chain):], chain.verified_chain)}
        constrained = {token for chain in constraint_rejections for token in chain}
        for chain in accepted:
            # Keep replacement provenance on this attempt's result, not in shared
            # pending state that could outlive callers which do not apply policies.
            chain._statement_replacements = {}
            raw = chain.chain[-len(chain.verified_chain):]
            for token, claims in zip(raw[:-1], chain.verified_chain[:-1]):
                pair = (claims['iss'], claims['sub'])
                pending = self._pending_statements.get(pair)
                if (pending is not None and pending[:2] == (token, claims['exp'])
                        and pending[:2] != pending[2]):
                    chain._statement_replacements[pair] = pending[:2]
        for (authority, entity), (token, expiry, previous) in list(self._pending_statements.items()):
            if token not in examined:
                continue
            if token not in usable and previous[0] is not None:
                claims = usable.get(previous[0])
                if (token in constrained and claims is not None
                        and claims['iss'] == authority and claims['sub'] == entity
                        and claims['exp'] == previous[1] and time.time() < previous[1]
                        and self._statement_pair(entity, authority) == (token, expiry)):
                    # A sibling's constraint failure does not invalidate the
                    # exact preceding pair used by an accepted candidate.
                    self.entity_statement_cache[cache_key(authority, entity)] = previous[0]
                    self.entity_statement_cache[time_key(authority, entity)] = previous[1]
                    self._pending_statements.pop((authority, entity), None)
                else:
                    self._discard_statement(entity, authority, (token, expiry))
            else:
                self._pending_statements.pop((authority, entity), None)
        for entity_id, (fresh, previous) in list(self._pending_configurations.items()):
            token = fresh['_jws']
            if token in examined:
                self.finish_configuration_verification(entity_id, token, token in usable)

    def finish_policy_validation(self, chains, accepted):
        """Discard rejected replacements, preserving unchanged shared statements."""
        usable = {token for chain in accepted if getattr(chain, 'chain', None)
                  for token in chain.chain[-len(chain.verified_chain):]}
        for chain in chains:
            replacements = chain.__dict__.pop('_statement_replacements', {})
            if chain in accepted:
                continue
            # A candidate's policy failure is not a global rejection of its
            # unchanged ancestors. Only its newly staged evidence needs cleanup.
            for (authority, entity), pair in replacements.items():
                if pair[0] not in usable:
                    self._discard_statement(entity, authority, pair)

    def _get_entity_statement(self, entity: str, authority: str,
                              fetch_endpoint: Optional[str] = None) -> Optional[str]:
        entity_statement = self._cached_entity_statement(entity, authority, refresh=True)
        if entity_statement is None:
            previous = self._statement_pair(entity, authority)
            logger.debug(f"Have not seen '{authority}' before")
            fed_fetch_endpoint = (self.get_federation_fetch_endpoint(authority)
                                  if fetch_endpoint is None else fetch_endpoint)
            if not fed_fetch_endpoint:
                return None
            logger.debug(f"Federation fetch endpoint: '{fed_fetch_endpoint}' for '{authority}'")
            self._check_request_limit()
            try:
                entity_statement = self.get_entity_statement(fed_fetch_endpoint, authority, entity)
            except Exception as error:
                if (_transient_retrieval(error) and previous[0] is not None
                        and previous[1] is not None and time.time() < previous[1]
                        and self._cached_entity_statement(entity, authority) is not None):
                    return previous[0]
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
                    self._discard_statement(entity, authority, previous)
                    return None
            except Exception:
                self._discard_statement(entity, authority, previous)
                raise
            logger.debug(
                f"Unverified entity statement from {fed_fetch_endpoint} about {entity}: "
                f"{statement}")
            if self._statement_pair(entity, authority) == previous:
                pending = self._pending_statements.get((authority, entity))
                retained = pending[2] if pending and pending[:2] == previous else previous
                self._pending_statements[(authority, entity)] = (
                    entity_statement, statement['exp'], retained)
                self.entity_statement_cache[cache_key(authority, entity)] = entity_statement
                self.entity_statement_cache[time_key(authority, entity)] = statement["exp"]

        _check_subject(unverified_entity_statement(entity_statement), entity)

        return entity_statement

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

        previous = self._statement_pair(entity, authority)
        budget = self._request_budget.get()
        remaining = budget["remaining"]
        discovery_complete = False
        try:
            # Refresh authority discovery even when its subordinate JWT is cached.
            needs_fetch = self._cached_entity_statement(entity, authority, refresh=True) is None
            _entity_configuration, _ = self._get_cached_entity_configuration(
                authority, require_fetch_endpoint=needs_fetch)
            if _entity_configuration is None:
                return None
            discovery_complete = True
            entity_statement = self._get_entity_statement(
                entity, authority, fetch_endpoint=get_endpoint("fetch", _entity_configuration) or '')
        except _RequestLimitReached:
            # No early eviction needs rollback. An EC 404 followed by denied
            # tenant fallback is still a failed refresh, not quota-only retention.
            if not discovery_complete and budget['remaining'] != remaining:
                self._discard_statement(entity, authority, previous)
            raise
        except Exception:
            if not discovery_complete:
                self._discard_statement(entity, authority, previous)
            raise

        if entity_statement:
            _entity_configuration = self.config_cache[authority]
            return entity_statement, self._collect_tree(
                authority, _entity_configuration, _seen, max_superiors, stop_at)
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
                 stop_at: Optional[str] = ''):
        """Collect from the subject EC with one operation-local HTTP allowance."""
        with self._collection(max_superiors) as limit:
            try:
                entity_config, signed_entity_config = self._get_cached_entity_configuration(entity_id)
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
