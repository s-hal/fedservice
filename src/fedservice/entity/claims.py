from copy import copy
from copy import deepcopy
from typing import Optional

from idpyoidc import alg_info
from idpyoidc.claims import Claims as ClaimsBase
from idpyoidc.client.claims import oauth2 as OAuth2ClientClaims
from idpyoidc.client.claims import oidc as OIDCClientClaims
from idpyoidc.message import Message
from idpyoidc.server.claims import oauth2 as OAUTH2ServerClaims
from idpyoidc.server.claims import oidc as OIDCServerClaims
from idpyoidc.transform import REGISTER2PREFERRED
from idpyoidc.transform import create_registration_request

from fedservice import message
from fedservice.payload_validation import _validate_auth_signing_alg_values


_AUTH_ALGORITHMS = "endpoint_auth_signing_alg_values_supported"


def _local_auth_algorithms(value, setting):
    _validate_auth_signing_alg_values(value, setting)
    supported = {alg for alg in alg_info.get_signing_algs() if not alg.startswith("HS")}
    if not set(value).issubset(supported):
        raise ValueError("{} contains unsupported asymmetric authentication algorithms: {!r}".format(
            setting, value))
    return list(value)


class OPClaims(OIDCServerClaims.Claims):
    _supports = OIDCServerClaims.Claims._supports.copy()
    _supports.update({
        'client_registration_types_supported': ['automatic', 'explicit'],
        'request_authentication_methods_supported': {
            "authorization_endpoint": [
                "request_object"
            ],
            "pushed_authorization_request_endpoint": [
                "request_object",
                "private_key_jwt"
            ]
        },
        'request_authentication_signing_alg_values_supported': alg_info.get_signing_algs,
        'federation_registration_endpoint': None
    })

    def provider_info(self, supports, schema: Optional[Message] = None):
        _info = {}
        if schema is None:
            schema = message.OPMetadata

        for key in schema.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info


class ASClaims(OAUTH2ServerClaims.Claims):
    _supports = OAUTH2ServerClaims.Claims._supports.copy()
    _supports.update({
        'client_registration_types_supported': ['automatic', 'explicit'],
        'request_authentication_methods_supported': {
            "authorization_endpoint": [
                "request_object"
            ],
            "pushed_authorization_request_endpoint": [
                "request_object",
                "private_key_jwt"
            ]
        },
        'request_authentication_signing_alg_values_supported': alg_info.get_signing_algs,
        'federation_registration_endpoint': None
    })

    def verify_rules(self, **kwargs):
        pass

    def provider_info(self, supports):
        _info = {}
        for key in message.AuthorizationServerMetadata.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info


class RPClaims(OIDCClientClaims.Claims):
    _supports = OIDCClientClaims.Claims._supports.copy()

    register2preferred = OIDCClientClaims.REGISTER2PREFERRED
    registration_response = message.OIDCRPRegistrationResponse
    registration_request = message.OIDCRPMetadata


class ClientClaims(OAuth2ClientClaims.Claims):
    _supports = OAuth2ClientClaims.Claims._supports.copy()

    register2preferred = REGISTER2PREFERRED
    registration_response = message.OauthClientInformationResponse
    registration_request = message.OauthClientMetadata


class FederationEntityClaims(ClaimsBase):
    _supports = {
        'organization_name': None,
        'contacts': None,
        'policy_uri': None,
        'logo_uri': None,
        'homepage_uri': None,
        'trust_mark_owners': None,
        'trust_mark_issuers': None,
        _AUTH_ALGORITHMS: None,
    }

    def get_endpoint_claims(self, endpoints):
        """Collect canonical authentication capabilities, rejecting local conflicts."""
        endpoints = list(endpoints or [])
        result = super().get_endpoint_claims(endpoints)
        for endpoint in endpoints:
            result.pop("{}_auth_signing_alg_values".format(endpoint.endpoint_name), None)
        selected = None
        source = "preference.{}".format(_AUTH_ALGORITHMS)
        if _AUTH_ALGORITHMS in self.prefer:
            selected = _local_auth_algorithms(self.prefer[_AUTH_ALGORITHMS], source)
        for endpoint in endpoints:
            if "private_key_jwt" not in (endpoint.client_authn_method or []):
                continue
            settings = []
            name = "{}.auth_signing_alg_values".format(endpoint.name)
            if hasattr(endpoint, "auth_signing_alg_values"):
                settings.append((name + " attribute", endpoint.auth_signing_alg_values))
            if "auth_signing_alg_values" in endpoint.kwargs:
                settings.append((name + " kwargs", endpoint.kwargs["auth_signing_alg_values"]))
            values = [(setting, _local_auth_algorithms(value, setting))
                      for setting, value in settings]
            if len(values) == 2 and set(values[0][1]) != set(values[1][1]):
                raise ValueError("{} conflicts with {}".format(values[0][0], values[1][0]))
            for setting, value in values:
                if not value:
                    continue
                if selected is None:
                    selected, source = value, setting
                elif set(selected) != set(value):
                    raise ValueError("{} conflicts with {}".format(source, setting))
        if selected is not None:
            result[_AUTH_ALGORITHMS] = selected
        return result

    def get_server_metadata(self, entity_type="", endpoints=None, metadata_schema=None,
                            extra_claims=None, **kwargs):
        """Publish without caching derived capabilities as explicit preferences."""
        # The dependency updates prefer in place and filters empty arrays. Use
        # an isolated view and restore only the explicitly supported empty list.
        view = copy(self)
        view.prefer = deepcopy(self.prefer)
        view.prefer.update(self.get_endpoint_claims(endpoints))
        metadata = ClaimsBase.get_server_metadata(
            view, metadata_schema=metadata_schema, extra_claims=extra_claims, **kwargs)
        if _AUTH_ALGORITHMS in view.prefer:
            metadata[_AUTH_ALGORITHMS] = list(view.prefer[_AUTH_ALGORITHMS])
        return {entity_type: metadata} if entity_type else metadata

    def metadata(self, supports):
        _info = {}
        for key in message.FederationEntity.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info

    def get_id(self, configuration: dict):
        return ''

    def create_registration_request(self):
        return create_registration_request(self.prefer, self.supports())
