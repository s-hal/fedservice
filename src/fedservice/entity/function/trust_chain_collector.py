import logging
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
from requests.exceptions import RequestException

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
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT

logger = logging.getLogger(__name__)


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


def verify_self_signed_signature(statement):
    """
    Verify signature using only keys in the entity statement.
    Will raise exception if signature verification fails.

    :param statement: Signed JWT
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
                 **kwargs
                 ):
        Function.__init__(self, upstream_get)
        self.trust_anchors = trust_anchors
        self.allowed_delta = allowed_delta
        self.config_cache = ESCache(allowed_delta=allowed_delta)
        self.entity_statement_cache = ESCache(allowed_delta=allowed_delta)
        # should not have a Key Jar of its own
        if keyjar:
            self.keyjar = keyjar
        else:
            self.keyjar = None
            keyjar = upstream_get("attribute", "keyjar")
        for id, keys in trust_anchors.items():
            keyjar = import_jwks(keyjar, keys, id)

    def _get_service(self, service):
        federation_entity = get_federation_entity(self)
        return federation_entity.client.get_service(service)

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
        try:
            response = self.upstream_get('attribute', 'httpc')("GET", url, **_httpc_params)
        except ConnectionError as err:
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
            raise FailedConfigurationRetrieval()

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
            _chains, token = collect_trust_chains(_federation_entity, entity_id)
            if not _chains and token and entity_id in self.trust_anchors:
                _chains = [[]]
            _trust_chains = verify_trust_chains(_federation_entity, _chains, token)
            if not _trust_chains:
                raise FailedConfigurationRetrieval("No verified chain for requested metadata")
            _ec = self.config_cache[entity_id]
        if _ec is None:
            raise FailedConfigurationRetrieval("Entity Configuration expired during metadata retrieval")
        _check_subject(_ec, entity_id)
        return _ec['metadata']

    def get_verified_self_signed_entity_configuration(self, entity_id: str) -> str:
        signed_entity_config = self.get_entity_configuration(entity_id)
        if signed_entity_config is None:
            return ''

        entity_config = verify_self_signed_signature(signed_entity_config)
        _check_subject(entity_config, entity_id)
        if time.time() >= entity_config["exp"]:
            raise FederationJwtPayloadError("Entity Configuration has expired")
        return entity_config

    def _get_cached_entity_configuration(self, entity_id):
        entity_config = self.config_cache[entity_id]
        if entity_config is not None:
            _check_subject(entity_config, entity_id)
            signed = entity_config.get("_jws") or getattr(entity_config, "_jws", None)
            if signed and not self.too_old(entity_config):
                _check_subject(unverified_entity_statement(signed), entity_id)
                return entity_config, signed
            del self.config_cache[entity_id]

        signed = self.get_entity_configuration(entity_id)
        if not signed:
            return None, None
        entity_config = verify_self_signed_signature(signed)
        _check_subject(entity_config, entity_id)
        if time.time() >= entity_config["exp"]:
            raise FederationJwtPayloadError("Entity Configuration has expired")
        entity_config["_jws"] = signed
        self.config_cache[entity_id] = entity_config
        return entity_config, signed

    def get_federation_fetch_endpoint(self, intermediate: str) -> str:
        logger.debug(f'--get_federation_fetch_endpoint({intermediate})')
        entity_config, _ = self._get_cached_entity_configuration(intermediate)
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
                     max_superiors: Optional[int] = 1,
                     stop_at: Optional[str] = "") -> Optional[dict]:
        """
        Collect superiors one level at the time

        :param entity_id: The entity ID
        :param entity_configuration: Entity Configuration as a dictionary
        :param seen: A list of authorities that this process has seen. This to capture
            loops. Also used to control the allowed depth.
        :param max_superiors: The maximum number of superiors.
        :param stop_at: The ID of the trust anchor at which the trust chain should stop.
        :return: Dictionary of superiors
        """
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

        logger.debug(f"Authority_hints: {entity_configuration['authority_hints']}")
        for authority in entity_configuration['authority_hints']:
            logger.info(f"authority: {authority}")
            if authority in seen:  # loop ?!
                logger.warning(f"Loop detected at {authority}")
                continue
            try:
                superior[authority] = self.collect_branch(entity_id, authority, seen,
                                                          max_superiors, stop_at=stop_at)
            except (ValueError, WrongSubject, MissingPage, FailedConfigurationRetrieval,
                    WrongContentType, RequestException, SSLError):
                message = traceback.format_exception(*sys.exc_info())
                logger.error(message)
                continue

        return superior

    def _cached_entity_statement(self, entity, authority, refresh=False):
        _cache_key = cache_key(authority, entity)
        _time_key = time_key(authority, entity)
        entity_statement = self.entity_statement_cache[_cache_key]
        expiry = self.entity_statement_cache[_time_key]
        lead = max(0, self.allowed_delta) if refresh else 0
        if entity_statement is None or expiry is None or time.time() >= expiry - lead:
            for key in (_cache_key, _time_key):
                if key in self.entity_statement_cache:
                    del self.entity_statement_cache[key]
            return None
        _check_subject(unverified_entity_statement(entity_statement), entity)
        return entity_statement

    def _get_entity_statement(self, entity: str, authority: str,
                              fetch_endpoint: Optional[str] = None) -> Optional[str]:
        entity_statement = self._cached_entity_statement(entity, authority, refresh=True)
        if entity_statement is None:
            logger.debug(f"Have not seen '{authority}' before")
            fed_fetch_endpoint = (self.get_federation_fetch_endpoint(authority)
                                  if fetch_endpoint is None else fetch_endpoint)
            if not fed_fetch_endpoint:
                return None
            logger.debug(f"Federation fetch endpoint: '{fed_fetch_endpoint}' for '{authority}'")
            entity_statement = self.get_entity_statement(fed_fetch_endpoint, authority, entity)
            # entity_statement is a signed JWT
            statement = unverified_entity_statement(entity_statement)
            _check_subject(statement, entity)
            # This hint can reject stale material, never establish trust.
            if time.time() >= statement["exp"]:
                return None
            logger.debug(
                f"Unverified entity statement from {fed_fetch_endpoint} about {entity}: "
                f"{statement}")
            self.entity_statement_cache[cache_key(authority, entity)] = entity_statement
            self.entity_statement_cache[time_key(authority, entity)] = statement["exp"]

        _check_subject(unverified_entity_statement(entity_statement), entity)

        return entity_statement

    def collect_branch(self, entity, authority, seen=None, max_superiors=10, stop_at=""):
        """
        Collect an entity statement about an entity submitted by another entity, the authority.
        This consist of first finding the fed_fetch_endpoint URL for the authority and then
        asking the authority for its view of the entity.

        :param authority: An authority from the authority_hints
        :param stop_at: When this entity ID is reached stop processing
        :param entity: The ID of the entity
        :param seen: A list of authorities that this process has seen. This to capture
            loops. Also used to control the allowed depth.
        :param max_superiors: The maximum number of superiors allowed.
        :return:
        """

        logger.debug(f'Get view of "{entity}" from "{authority}"')
        # Should I stop when I reach the first trust anchor ?
        if entity == authority and entity in self.trust_anchors:
            return None

        if seen is None:
            _seen = []
        else:
            _seen = seen[:]

        _seen.append(authority)
        # if len(_seen) > max_superiors:
        #     logger.warning("Reached max superiors. The path here was {}".format(_seen))
        #     return None

        # Refresh authority discovery even when its subordinate JWT is cached.
        _entity_configuration, _ = self._get_cached_entity_configuration(authority)
        if _entity_configuration is None:
            return None
        entity_statement = self._get_entity_statement(
            entity, authority, fetch_endpoint=get_endpoint("fetch", _entity_configuration) or '')

        if entity_statement:
            _entity_configuration = self.config_cache[authority]
            return entity_statement, self.collect_tree(authority,
                                                       _entity_configuration,
                                                       stop_at=stop_at,
                                                       seen=_seen,
                                                       max_superiors=max_superiors)
        else:
            return None

    def too_old(self, statement):
        return time.time() >= statement["exp"] - max(0, self.allowed_delta)

    def __call__(self,
                 entity_id: str,
                 max_superiors: Optional[int] = 10,
                 seen: Optional[List[str]] = None,
                 stop_at: Optional[str] = ''):
        entity_config, signed_entity_config = self._get_cached_entity_configuration(entity_id)
        if entity_config is None:
            return None
        return self.collect_tree(entity_id, entity_config, seen=seen, max_superiors=max_superiors,
                                 stop_at=stop_at), signed_entity_config

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
