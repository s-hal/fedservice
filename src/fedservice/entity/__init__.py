__author__ = 'Roland Hedberg'

import json
import logging
import os
from copy import deepcopy
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.utils import b64d
from cryptojwt.utils import b64e
from cryptojwt.utils import importer
from idpyoidc.claims import Claims as ClaimsBase
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.exception import MissingPage
from idpyoidc.exception import OidcMsgError
from idpyoidc.key_import import import_jwks
from idpyoidc.node import Unit
from idpyoidc.server.util import execute
from idpyoidc.util import instantiate
from requests import request
from requests.exceptions import RequestException

from fedservice import message
from fedservice import get_payload
from fedservice.build_entity import _SIGNING_ALG_UNSET
from fedservice.build_entity import validate_publish_jwks_from_public_path
from fedservice.entity.context import FederationContext
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.exception import FailedConfigurationRetrieval
from fedservice.exception import WrongSubject
from fedservice.federation_jwt.errors import FederationJwtError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.payload_validation import _validate_entity_identifier
from fedservice.payload_validation import _validate_jwks

logger = logging.getLogger(__name__)


class FederationEntityClaims(ClaimsBase):
    _supports = {
        'organization_name': None,
        'contacts': None,
        'policy_uri': None,
        'logo_uri': None,
        'homepage_uri': None,
        'trust_mark_owners': None,
        'trust_mark_issuers': None
    }

    def metadata(self, supports):
        _info = {}
        for key in message.FederationEntity.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info

    def get_id(self, configuration: dict):
        return ''


class FederationEntity(Unit):
    name = "federation_entity"

    def __init__(self,
                 upstream_get: Optional[Callable] = None,
                 entity_id: str = "",
                 keyjar: Optional[KeyJar] = None,
                 key_conf: Optional[dict] = None,
                 client: Optional[dict] = None,
                 server: Optional[dict] = None,
                 function: Optional[dict] = None,
                 httpc: Optional[object] = None,
                 httpc_params: Optional[dict] = None,
                 preference: Optional[dict] = None,
                 authority_hints: Optional[Union[list, str, Callable]] = None,
                 persistence: Optional[dict] = None,
                 client_authn_methods: Optional[list] = None,
                 signing_alg=_SIGNING_ALG_UNSET,
                 publish_jwks_from_public_path=False,
                 **kwargs
                 ):

        self.publish_jwks_from_public_path = validate_publish_jwks_from_public_path(
            publish_jwks_from_public_path)

        if upstream_get is None and httpc is None:
            httpc = request

        if not keyjar and not key_conf:
            keyjar = False

        self.entity_id = entity_id
        Unit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                      httpc_params=httpc_params, key_conf=key_conf, issuer_id=entity_id)
        # Writable dependency initialization must finish before taking the snapshot.
        self._entity_configuration_jwks = (
            self._load_publication_jwks((key_conf or {}).get("public_path"))
            if self.publish_jwks_from_public_path else None)

        _args = {
            "upstream_get": self.unit_get,
            "httpc": self.httpc,
            "httpc_params": self.httpc_params,
            "entity_id": entity_id
        }

        self.client = self.server = self.function = None
        for key, val in [('client', client), ('server', server), ('function', function)]:
            if val:
                _kwargs = val["kwargs"].copy()
                _kwargs.update(_args)
                setattr(self, key, instantiate(val["class"], **_kwargs))

        _args = {}
        for claim in ["trust_mark_issuers", "trust_mark_owners"]:
            _val = kwargs.get(claim)
            if _val:
                _args[claim] = _val

        self.context = FederationContext(entity_id=entity_id, upstream_get=self.unit_get,
                                         authority_hints=authority_hints, keyjar=self.keyjar,
                                         preference=preference, signing_alg=signing_alg, **_args)

        if client_authn_methods:
            self.context.client_authn_methods = client_auth_setup(client_authn_methods)

        self.trust_chain = {}

        self.context.provider_info = self.context.claims.get_server_metadata(
            endpoints=self.server.endpoint.values(),
            metadata_schema=message.FederationEntity,
        )
        self.context.provider_info["issuer"] = self.context.entity_id
        self.context.metadata = self.context.provider_info

        resolve = self.get_endpoint("resolve")
        if getattr(resolve, "trust_mark_status_check", False) and (
                self.client is None or self.get_service("trust_mark_status") is None):
            raise ValueError("trust_mark_status_check requires the trust_mark_status client service")

        if persistence:
            _storage = execute(persistence["kwargs"]["storage"])
            _class = persistence["class"]
            kwargs = {"storage": _storage, "upstream_get": self.unit_get}
            if isinstance(_class, str):
                self.persistence = importer(_class)(**kwargs)
            else:
                self.persistence = _class(**kwargs)

    @staticmethod
    def _load_publication_jwks(path):
        def reject_constant(value):
            raise ValueError("Invalid JSON constant")

        try:
            if not path:
                raise ValueError("Missing public_path")
            with open(os.fspath(path)) as source:
                jwks = json.load(source, parse_constant=reject_constant)
            _validate_jwks(jwks)
            if not jwks["keys"]:
                raise ValueError("Empty public JWKS")
            for raw in jwks["keys"]:
                # Public-key conversion strips private fields; inspect the original first.
                if raw.get("kty") == "oct" or {
                        "k", "d", "p", "q", "dp", "dq", "qi", "di", "oth"
                }.intersection(raw):
                    raise ValueError("Non-public JWK")
                # Cryptojwt permits some falsey or coerced common-member values.
                for name in ("kid", "use", "alg", "crv", "x5u", "x5t", "x5t#S256"):
                    if name in raw and not isinstance(raw[name], str):
                        raise ValueError("Invalid public JWK member")
                for name in ("key_ops", "x5c"):
                    if name in raw and (not isinstance(raw[name], list) or any(
                            not isinstance(item, str) for item in raw[name])):
                        raise ValueError("Invalid public JWK member")
                key = key_from_jwk_dict(raw, private=False)
                if key.has_private_key() or key.public_key() is None or not key.verify():
                    raise ValueError("Invalid public JWK")
                # The integer decoder tolerates some invalid characters. Do not
                # publish encodings that only become valid after that conversion.
                for name in key.longs:
                    if name in raw:
                        encoded = raw[name].encode("ascii")
                        if not encoded or b64e(b64d(encoded)) != encoded:
                            raise ValueError("Invalid public JWK encoding")
            return jwks
        except Exception:
            raise ValueError(
                "publish_jwks_from_public_path requires a valid public JWKS at "
                "key_config.public_path {!r}".format(path)) from None

    def get_entity_configuration_jwks(self, **kwargs):
        """Copy the configured publication, rejecting conflicting per-call values."""
        jwks = self._entity_configuration_jwks
        if jwks is None:
            return None
        if (("jwks" in kwargs and kwargs["jwks"] != jwks)
                or ("keys" in kwargs and kwargs["keys"] != jwks["keys"])
                or not kwargs.get("include_jwks", True)):
            raise ValueError("EC arguments conflict with publish_jwks_from_public_path")
        return deepcopy(jwks)

    def verify_entity_configuration_publication(self, token, issuer):
        """Check the actual EC signer against isolated advertised public material."""
        if self._entity_configuration_jwks is None:
            return
        public_keys = KeyJar()
        # add_keys preserves absent kids; importing a JWKS can synthesize them.
        public_keys.add_keys(issuer, [key_from_jwk_dict(raw, private=False)
                                     for raw in self._entity_configuration_jwks["keys"]])
        try:
            verify_federation_jwt(ENTITY_CONFIGURATION, token, public_keys)
        except FederationJwtError:
            raise ValueError(
                "EC cannot verify against publish_jwks_from_public_path") from None

    def get_context(self, *arg):
        return self.context

    def get_federation_entity(self):
        return self

    def get_entity(self):
        return self

    def get_entity_type(self, entity_type):
        if entity_type == "federation_entity":
            return self
        else:
            return None

    def get_attribute(self, attr, *args):
        try:
            val = getattr(self, attr)
        except AttributeError:
            if self.upstream_get:
                return self.upstream_get('attribute', attr)
            else:
                return None
        else:
            if not val:
                if self.upstream_get:
                    return self.upstream_get('attribute', attr)
                else:
                    return None
            else:
                return val

    def get_function(self, function_name, *args):
        if self.function:
            try:
                return getattr(self.function, function_name)
            except AttributeError:
                return None

    def registration_metadata(self, entity_type="federation_entity", *args):
        _context = self.get_context()
        _claims = _context.claims

        metadata = _claims.get_server_metadata(endpoints=self.get_all_endpoints())

        # remove these from the metadata
        for item in ["jwks", "jwks_uri", "signed_jwks_uri"]:
            try:
                del metadata[item]
            except KeyError:
                pass

        # _issuer = getattr(self.server.context, "trust_mark_server", None)
        return {entity_type: metadata}

    def get_metadata(self, entity_type="federation_entity", *args):
        logger.debug(f"{self.name}:get_metadata")
        _context = self.get_context()
        _claims = _context.claims

        # The entity metadata for a Federation entity server
        metadata = _claims.get_server_metadata(endpoints=self.get_all_endpoints(),
                                               metadata_schema=message.FederationEntity)

        logger.debug(f"metadata:{entity_type} = {metadata}")
        return {entity_type: metadata}

    def get_preferences(self):
        preference = self.get_context().claims.prefer.copy()
        # collect endpoints
        preference.update(self.get_endpoint_claims())
        return {"federation_entity": preference}

    def get_all_endpoints(self, *arg):
        if self.server:
            return list(self.server.endpoint.values())
        else:
            return None

    def get_endpoint(self, endpoint_name, *arg):
        if self.server is None:
            return None

        try:
            return self.server.get_endpoint(endpoint_name)
        except KeyError:
            return None

    def get_service(self, service_name, *arg):
        try:
            return self.client.get_service(service_name)
        except KeyError:
            return None

    def get_all_services(self, *args):
        return list(self.client.service.db.keys())

    def get_authority_hints(self, *args):
        return self.context.get_authority_hints()

    def get_trusted_roots(self, *args):
        return self.context.get_trusted_roots()

    def get_context_attribute(self, attr, *args):
        _val = getattr(self.context, attr, None)
        if not _val and self.upstream_get:
            return self.upstream_get('context_attribute', attr)
        else:
            return _val

    def pick_trust_chain(self, trust_chains: list):
        """
        Pick one trust chain out of the list of possible trust chains

        :param trust_chains: A list of :py:class:`fedservice.entity_statement.statement.TrustChain
            instances
        :return: A :py:class:`fedservice.entity_statement.statement.TrustChain instance
        """
        if len(trust_chains) == 1:
            # If there is only one, then use it
            return trust_chains[0]
        elif self.context.tr_priority:
            # Go by priority
            for fid in self.context.tr_priority:
                for trust_chain in trust_chains:
                    if trust_chain.anchor == fid:
                        return trust_chain

        # Can only arrive here if the federations I got back and trust are not
        # in the priority list. So, just pick one
        return trust_chains[0]

    def pick_from_stored_trust_chains(self, entity_id):
        _trust_chains = self.context.trust_chain[entity_id]
        _tas = list(_trust_chains.keys())
        if len(_tas) == 1:
            return _trust_chains[_tas[0]]
        elif self.context.tr_priority:
            # Go by priority
            for ta_id in self.context.tr_priority:
                for ta_id in _tas:
                    return _trust_chains[ta_id]
        return _trust_chains[_tas[0]]

    # def get_payload(self, self_signed_statement):
    #     _jws = as_unicode(self_signed_statement)
    #     _jwt = factory(_jws)
    #     return _jwt.jwt.payload()

    def supported(self):
        _supports = self.context.supports()
        if self.server:
            _supports.update(self.server.context.supports())
        return _supports

    def get_endpoint_claims(self):
        return self.context.claims.get_endpoint_claims(self.get_all_endpoints())

    def get_trust_chains(self, entity_id):
        _trust_chains = self.trust_chain.get(entity_id, None)
        if _trust_chains is None:
            _trust_chains = get_verified_trust_chains(self, entity_id)
            if _trust_chains:
                self.store_trust_chain(entity_id, _trust_chains)
            else:
                return []

        return _trust_chains

    def store_trust_chain(self, entity_id, trust_chains):
        self.trust_chain[entity_id] = trust_chains

    def store_trust_chains(self, entity_id, chains):
        self.trust_chain[entity_id] = chains

    def get_verified_metadata(self, entity_id: str, *args):
        _trust_chains = self.trust_chain.get(entity_id)
        if _trust_chains is None:
            _trust_chains = get_verified_trust_chains(self, entity_id)
            if _trust_chains:
                self.store_trust_chain(entity_id, _trust_chains)

        if _trust_chains:
            return _trust_chains[0].metadata
        else:
            return None

    def get_federation_entity_metadata(self, entity_id: str, *args):
        metadata = self.get_verified_metadata(entity_id, *args)
        if metadata:
            return metadata["federation_entity"]
        else:
            return metadata

    def do_request(
            self,
            request_type: str,
            response_body_type: Optional[str] = "",
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
            **kwargs):
        return self.client.do_request(request_type=request_type,
                                      response_body_type=response_body_type,
                                      request_args=request_args, behaviour_args=behaviour_args,
                                      **kwargs)

    def trawl(self, superior, subordinate, entity_type):
        if subordinate in self.function.trust_chain_collector.config_cache:
            _ec = self.function.trust_chain_collector.config_cache[subordinate]
        else:
            _es = self.client.do_request("entity_statement", issuer=superior, subject=subordinate)

            # add subjects key/-s to keyjar
            _kj = self.get_federation_entity().keyjar
            _kj = import_jwks(_kj, _es["jwks"], _es["sub"])

            # Fetch Entity Configuration
            _ec = self.client.do_request("entity_configuration", entity_id=subordinate)

        if entity_type in _ec["metadata"]:
            _issuers = [_ec["sub"]]
        else:
            _issuers = []

        if "federation_list_endpoint" not in _ec["metadata"]["federation_entity"]:
            return _issuers

        # One step down the tree
        # All subordinates that are of a specific entity_type
        _added_issuers = self.client.do_request("list",
                                                entity_id=subordinate,
                                                entity_type=entity_type)
        if _added_issuers is None:
            pass
        else:
            _issuers.extend(_added_issuers)

        # All subordinates that are intermediates
        _intermediates = self.client.do_request("list",
                                                entity_id=subordinate,
                                                intermediate=True)

        # For all intermediates go further down the tree
        if _intermediates:
            for entity_id in _intermediates:
                _ids = self.trawl(subordinate, entity_id, entity_type)
                if _ids:
                    _issuers.extend(_ids)

        return _issuers

    def verify_trust_mark(self, trust_mark: str, check_with_issuer: Optional[bool] = True):
        """Verify locally and, by default, require one bound online status check."""
        try:
            issuer = get_payload(trust_mark)["iss"]
            _validate_entity_identifier(issuer, "Trust Mark issuer")
        except (AttributeError, KeyError, TypeError, ValueError):
            return None
        if issuer in self.trust_anchors:
            anchor = issuer
        else:
            try:
                chains = get_verified_trust_chains(self, issuer)
            except (FederationJwtError, OidcServiceError, OidcMsgError, MissingPage,
                    FailedConfigurationRetrieval, WrongSubject, RequestException, ValueError):
                return None
            if not chains:
                return None
            anchor = chains[0].anchor
        return self.function.trust_mark_verifier(
            trust_mark=trust_mark, trust_anchor=anchor, check_status=check_with_issuer)

    @property
    def trust_anchors(self):
        return self.get_function("trust_chain_collector").trust_anchors

    @trust_anchors.setter
    def trust_anchors(self, value):
        self.get_function("trust_chain_collector").trust_anchors = value

    def add_trust_anchor(self, entity_id, jwks):
        if self.keyjar:
            _keyjar = self.keyjar
        elif self.upstream_get:
            _keyjar = self.upstream_get('attribute', 'keyjar')
        else:
            raise ValueError("Missing keyjar")

        _keyjar = import_jwks(_keyjar, jwks, entity_id)
        self.trust_anchors[entity_id] = jwks

    def supports(self):
        res = {}
        for name, service in self.client.service.items():
            res.update(service.supports())

        for name, endp in self.server.endpoint.items():
            res.update(endp.supports())

        res.update(self.context.claims._supports)
        return res
