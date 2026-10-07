""" Classes and functions used to describe information in an OpenID Connect Federation."""
from copy import copy
from copy import deepcopy
import json
import logging
import math
import re
from urllib.parse import parse_qs

from idpyoidc import message
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
from idpyoidc.message import msg_ser
from idpyoidc.message import oauth2 as OAuth2Message
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import OPTIONAL_MESSAGE
from idpyoidc.message import REQUIRED_LIST_OF_STRINGS
from idpyoidc.message import ser_any_list
from idpyoidc.message import SINGLE_OPTIONAL_INT
from idpyoidc.message import SINGLE_OPTIONAL_JSON
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message.oauth2 import ASConfigurationResponse
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import deserialize_from_one_of
from idpyoidc.message.oidc import dict_deser
from idpyoidc.message.oidc import msg_ser_json
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.message.oidc import SINGLE_OPTIONAL_BOOLEAN
from idpyoidc.message.oidc import SINGLE_OPTIONAL_DICT

from fedservice.exception import ConstraintError
from fedservice.exception import MetadataPolicyCritError
from fedservice.exception import UnknownCriticalExtension
from fedservice.exception import WrongSubject
from fedservice.payload_validation import _validate_entity_identifier
from fedservice.payload_validation import _validate_metadata
from fedservice.payload_validation import _require_entity_statement_claims
from fedservice.payload_validation import _validate_numeric_date
from fedservice.payload_validation import _validate_jwks
from fedservice.payload_validation import _validate_claim_placement
from fedservice.payload_validation import _validate_expected_issuer
from fedservice.payload_validation import _validate_entity_hints
from fedservice.payload_validation import _validate_critical_claims

SINGLE_REQUIRED_DICT = (dict, True, msg_ser_json, dict_deser, False)
SINGLE_REQUIRED_NUMERIC_DATE = ((int, float), True, None, None, False)

LOGGER = logging.getLogger(__name__)


class FederationPayloadMessage(Message):
    """Local base for Federation payload schemas.

    idpyoidc Message inheritance is retained for schema mechanics, but JWT
    container operations are intentionally unsupported here. Use
    fedservice.federation_jwt for Federation JWT parsing, signing, and
    verification.
    """

    @classmethod
    def validate_input(cls, payload, *, source_json=None):
        """Check decoded input without construction or establishing source trust."""
        if not isinstance(payload, dict):
            raise ValueError("Federation payload must be a JSON object")

    def from_jwt(self, *args, **kwargs):
        raise NotImplementedError(
            "Federation payload schemas do not parse JWT containers; use "
            "fedservice.federation_jwt for Federation JWT parsing and verification."
        )

    def to_jwt(self, *args, **kwargs):
        raise NotImplementedError(
            "Federation payload schemas do not sign JWT containers; use "
            "fedservice.federation_jwt for Federation JWT signing."
        )


def dict_list_deser(val, sformat="dict"):
    res = []
    if isinstance(val, list):
        for v in val:
            if isinstance(v, str):
                if sformat == "urlencoded":
                    res.append(parse_qs(v))
                else:
                    res.append(json.loads(v))
            elif isinstance(v, dict):
                res.append(v)
    else:
        if isinstance(val, str):
            if sformat == "urlencoded":
                res = [parse_qs(val)]
            else:
                res = [json.loads(val)]
        elif isinstance(val, dict):
            res = [val]

    return res


REQUIRED_LIST_OF_DICT = ([dict], True, ser_any_list, dict_list_deser, False)
OPTIONAL_LIST_OF_DICT = ([dict], False, ser_any_list, dict_list_deser, False)


class AuthorizationServerMetadata(Message):
    """Metadata for an OAuth2 Authorization Server. With Federation additions"""
    c_param = {
        "issuer": SINGLE_REQUIRED_STRING,
        "authorization_endpoint": SINGLE_OPTIONAL_STRING,
        "token_endpoint": SINGLE_OPTIONAL_STRING,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "registration_endpoint": SINGLE_OPTIONAL_STRING,
        "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
        "grant_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_auth_signing_algs_supported": OPTIONAL_LIST_OF_STRINGS,
        "service_documentation": SINGLE_OPTIONAL_STRING,
        "ui_locales_supported": OPTIONAL_LIST_OF_STRINGS,
        "op_policy_uri": SINGLE_OPTIONAL_STRING,
        "op_tos_uri": SINGLE_OPTIONAL_STRING,
        "revocation_endpoint": SINGLE_OPTIONAL_STRING,
        "revocation_auth_methods_supported": SINGLE_OPTIONAL_JSON,
        "revocation_auth_signing_algs_supported": SINGLE_OPTIONAL_JSON,
        "introspection_endpoint": SINGLE_OPTIONAL_STRING,
        "introspection_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "introspection_auth_signing_algs_supported": OPTIONAL_LIST_OF_STRINGS,
        "code_challenge_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        # below Federation additions
        'client_registration_types_supported': OPTIONAL_LIST_OF_STRINGS,
        'federation_registration_endpoint': SINGLE_OPTIONAL_STRING,
        'request_authentication_methods_supported': OPTIONAL_LIST_OF_STRINGS,
        'request_authentication_signing_alg_values_supported': OPTIONAL_LIST_OF_STRINGS,
    }


def auth_server_info_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into an AuthorizationServerMetadata."""
    return deserialize_from_one_of(val, AuthorizationServerMetadata, sformat)


OPTIONAL_AUTH_SERVER_METADATA = (Message, False, msg_ser, auth_server_info_deser, False)


_NAMING_CONSTRAINT_LABEL = re.compile(
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
)


def valid_naming_constraint(name):
    """Return whether a naming-constraint value is a valid domain name."""
    if not isinstance(name, str):
        return False
    host = name[1:] if name.startswith(".") else name
    return (0 < len(host) <= 253
            and all(_NAMING_CONSTRAINT_LABEL.fullmatch(label) for label in host.split(".")))


class NamingConstraints(Message):
    """Class representing naming constraints."""
    c_param = {
        "permitted": OPTIONAL_LIST_OF_STRINGS,
        "excluded": OPTIONAL_LIST_OF_STRINGS
    }

    def from_dict(self, dictionary, **kwargs):
        """Preserve original naming operands for deliberate validation."""
        for key, value in dictionary.items():
            if key in self.c_param:
                self[key] = value
            else:
                super().from_dict({key: value}, **kwargs)
        return self

    def __setitem__(self, key, value):
        if key in ("permitted", "excluded"):
            names = deepcopy(value)
            if not isinstance(names, list) or not all(
                    isinstance(name, str) for name in names):
                self._dict[key] = names
                return
            deserializer = self.c_param[key][3]
            if deserializer:
                names = deserializer(names, sformat="dict")
            if not isinstance(names, list) or not all(
                    isinstance(name, str) for name in names):
                raise ConstraintError(
                    "{} naming constraint deserializer must return an array of strings".format(
                        key
                    )
                )
            self._dict[key] = deepcopy(names)
        else:
            super().__setitem__(key, value)

    def verify(self, **kwargs):
        """Validate the current naming arrays and their domain syntax."""
        super().verify(**kwargs)
        for key in ("permitted", "excluded"):
            if key not in self:
                continue
            names = self[key]
            if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
                raise ConstraintError("{} naming constraint must be an array of strings".format(key))
            if not all(valid_naming_constraint(name) for name in names):
                raise ConstraintError("{} naming constraint contains an invalid domain".format(key))
        return True


def naming_constraints_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into an NamingConstraints."""
    return deserialize_from_one_of(val, NamingConstraints, sformat)


SINGLE_OPTIONAL_NAMING_CONSTRAINTS = (Message, False, msg_ser, naming_constraints_deser, False)


class InformationalMetadataExtensions(Message):
    c_param = {
        "organization_name": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "logo_url": SINGLE_OPTIONAL_STRING,
        "policy_url": SINGLE_OPTIONAL_STRING,
        "homepage_uri": SINGLE_OPTIONAL_STRING,
    }


class FederationEntity(InformationalMetadataExtensions):
    """Class representing Federation Entity metadata."""
    c_param = InformationalMetadataExtensions.c_param.copy()
    c_param.update({
        "federation_fetch_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_list_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_resolve_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_trust_mark_status_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_trust_mark_list_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_trust_mark_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_historical_keys_endpoint": SINGLE_OPTIONAL_STRING,
        "endpoint_auth_signing_alg_values_supported": SINGLE_OPTIONAL_JSON,
        # If it's a Trust Anchor
        # "trust_mark_owners": SINGLE_OPTIONAL_DICT,
        # "trust_mark_issuers": SINGLE_OPTIONAL_DICT,
        "federation_fetch_endpoint_auth_methods": OPTIONAL_LIST_OF_STRINGS,
        "federation_list_endpoint_auth_methods": OPTIONAL_LIST_OF_STRINGS,
        "federation_resolve_endpoint_auth_methods": OPTIONAL_LIST_OF_STRINGS,
        "federation_trust_mark_endpoint_auth_methods": OPTIONAL_LIST_OF_STRINGS,
        "federation_trust_mark_status_endpoint_auth_methods": OPTIONAL_LIST_OF_STRINGS,
        "federation_trust_mark_list_endpoint_auth_methods": OPTIONAL_LIST_OF_STRINGS,
        "federation_historical_keys_endpoint_auth_methods": OPTIONAL_LIST_OF_STRINGS,
    })


def federation_entity_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a FederationEntity."""
    return deserialize_from_one_of(val, FederationEntity, sformat)


OPTIONAL_FEDERATION_ENTITY_METADATA = (Message, False, msg_ser,
                                       federation_entity_deser, False)


class TrustMarkIssuer(Message):
    c_param = {
        "federation_status_endpoint": SINGLE_OPTIONAL_STRING
    }


def trust_mark_issuer_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a FederationEntity."""
    return deserialize_from_one_of(val, TrustMarkIssuer, sformat)


class OauthClientMetadata(OAuth2Message.OauthClientMetadata):
    """Metadata for an OAuth2 Client."""
    c_param = OAuth2Message.OauthClientMetadata.c_param.copy()
    c_param.update({
        "organization_name": SINGLE_OPTIONAL_STRING,
        "signed_jwks_uri": SINGLE_OPTIONAL_STRING,
    })


def oauth_client_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OauthClientMetadata."""
    return deserialize_from_one_of(val, OauthClientMetadata, sformat)


OPTIONAL_OAUTH_CLIENT_METADATA = (Message, False, msg_ser,
                                  oauth_client_metadata_deser, False)


class OauthClientInformationResponse(OauthClientMetadata):
    """The information returned by a OAuth2 Server about an OAuth2 client."""
    c_param = OauthClientMetadata.c_param.copy()
    c_param.update({
        "client_id": SINGLE_REQUIRED_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        "client_id_issued_at": SINGLE_OPTIONAL_INT,
        "client_secret_expires_at": SINGLE_OPTIONAL_INT
    })

    def verify(self, **kwargs):
        super(OauthClientInformationResponse, self).verify(**kwargs)

        if "client_secret" in self:
            if "client_secret_expires_at" not in self:
                raise MissingRequiredAttribute(
                    "client_secret_expires_at is a MUST if client_secret is present")


def oauth_client_registration_response_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OauthClientInformationResponse."""
    return deserialize_from_one_of(val, OauthClientInformationResponse, sformat)


OPTIONAL_OAUTH_CLIENT_REGISTRATION_RESPONSE = (
    Message, False, msg_ser, oauth_client_registration_response_deser, False)


class OAuthProtectedResourceMetadata(Message):
    c_param = {
        "resource": SINGLE_REQUIRED_STRING,
        "authorization_servers": OPTIONAL_LIST_OF_STRINGS,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "scopes_provided": OPTIONAL_LIST_OF_STRINGS,
        "bearer_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "resource_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "client_registration_types": OPTIONAL_LIST_OF_STRINGS,
        "organization_name": SINGLE_OPTIONAL_STRING,
    }


def oauth_protected_resource_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OAuthProtectedResourceMetadata."""
    return deserialize_from_one_of(val, OAuthProtectedResourceMetadata, sformat)


OPTIONAL_OAUTH_PROTECTED_RESOURCE_METADATA = (
    Message, False, msg_ser, oauth_protected_resource_deser, False)


class OIDCRPMetadata(RegistrationRequest):
    c_param = RegistrationRequest.c_param.copy()
    c_param.update({
        "client_registration_types": REQUIRED_LIST_OF_STRINGS
    })


def rp_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OIDCRPMetadata."""
    return deserialize_from_one_of(val, OIDCRPMetadata, sformat)


OPTIONAL_RP_METADATA = (
    Message, False, msg_ser, rp_metadata_deser, False)


class OIDCRPRegistrationResponse(RegistrationResponse):
    c_param = RegistrationResponse.c_param.copy()
    c_param.update({
        "client_registration_types": REQUIRED_LIST_OF_STRINGS
    })


def rp_registration_response_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OIDCRPRegistrationResponse."""
    return deserialize_from_one_of(val, OIDCRPRegistrationResponse, sformat)


OPTIONAL_RP_REGISTRATION_RESPONSE = (
    Message, False, msg_ser, rp_registration_response_deser, False)


class OPMetadata(ProviderConfigurationResponse):
    c_param = ProviderConfigurationResponse.c_param.copy()
    c_param.update({
        "client_registration_types_supported": REQUIRED_LIST_OF_STRINGS,
        "federation_registration_endpoint": SINGLE_OPTIONAL_STRING,
        "request_authentication_methods_supported": SINGLE_OPTIONAL_JSON,
        "request_authentication_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "organization_name": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "homepage_uri": SINGLE_OPTIONAL_STRING,
        "jwks": SINGLE_OPTIONAL_DICT,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "signed_jwks_uri": SINGLE_OPTIONAL_STRING
    })


class FedASConfigurationResponse(ASConfigurationResponse):
    c_param = ASConfigurationResponse.c_param.copy()
    c_param.update({
        "organization_name": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "homepage_uri": SINGLE_OPTIONAL_STRING,
        "jwks": SINGLE_OPTIONAL_DICT,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "signed_jwks_uri": SINGLE_OPTIONAL_STRING
    })


def op_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a ProviderConfigurationResponse."""
    return deserialize_from_one_of(val, OPMetadata, sformat)


OPTIONAL_OP_METADATA = (Message, False, msg_ser, op_metadata_deser, False)


class TrustMarkIssuerMetadata(Message):
    """Metadata for a Trust Mark Issuer."""
    c_param = {
        "status_endpoint": SINGLE_REQUIRED_STRING
    }


def trust_mark_issuer_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OauthClientMetadata."""
    return deserialize_from_one_of(val, TrustMarkIssuerMetadata, sformat)


OPTIONAL_TRUST_MARK_ISSUER_METADATA = (Message, False, msg_ser,
                                       trust_mark_issuer_metadata_deser, False)


class Metadata(Message):
    """The different types of metadata that an entity in a federation can belong to."""
    c_param = {
        'openid_relying_party': OPTIONAL_RP_METADATA,
        'openid_provider': OPTIONAL_OP_METADATA,
        "oauth_authorization_server": OPTIONAL_AUTH_SERVER_METADATA,
        "oauth_client": OPTIONAL_OAUTH_CLIENT_METADATA,
        "oauth_response_server": OPTIONAL_OAUTH_PROTECTED_RESOURCE_METADATA,
        "federation_entity": OPTIONAL_FEDERATION_ENTITY_METADATA,
        "trust_mark_issuer": OPTIONAL_TRUST_MARK_ISSUER_METADATA
    }

    def from_dict(self, dictionary, **kwargs):
        """Keep Entity Type containers visible, including invalid falsey values."""
        for key, value in dictionary.items():
            if key in self.c_param:
                self[key] = value
            elif isinstance(value, dict):
                original = deepcopy(value)
                filtered = {name: item for name, item in value.items()
                            if item is not None}
                super(Metadata, self).from_dict({key: filtered}, **kwargs)
                parsed = self[key]
                if isinstance(parsed, Message):
                    self._restore_filtered_values(parsed, original)
                else:
                    self._dict[key] = original
            else:
                self._dict[key] = deepcopy(value)
        return self

    def __setitem__(self, key, value):
        if key in self.c_param and isinstance(value, dict):
            # Let the existing protocol deserializer build its typed message and
            # defaults, but defer all immediate nulls to structural validation.
            super().__setitem__(key, {name: item for name, item in value.items()
                                     if item is not None})
            parsed = self[key]
            self._restore_filtered_values(parsed, value)
        else:
            self._dict[key] = value

    @staticmethod
    def _restore_filtered_values(parsed, original):
        """Restore filtered values without replacing declared callback output."""
        for name, item in original.items():
            if name in parsed:
                continue
            base_name = name.split("#")[0]
            extension = base_name not in parsed.c_param
            declared_empty_array = (
                type(item) is list and not item and not extension
                and isinstance(parsed.c_param[base_name][0], list)
            )
            if (item is None or declared_empty_array
                    or (extension and item in ("", [], [""]))):
                parsed.update({name: deepcopy(item)})

    def verify(self, **kwargs):
        """Check structure without requiring complete protocol metadata."""
        _validate_metadata(self)
        return super().verify(**kwargs)


def metadata_deser(val, sformat="json"):
    """Deserialize metadata using the existing typed Entity Type schemas."""
    return deserialize_from_one_of(val, Metadata, sformat)


SINGLE_REQUIRED_METADATA = (Message, True, msg_ser, metadata_deser, False)
SINGLE_OPTIONAL_METADATA = (Message, False, msg_ser, metadata_deser, False)


def _copy_policy_value(value, array_item=False):
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) is list:
        return [_copy_policy_value(item, array_item=True) for item in value]
    if array_item and type(value) is dict and all(isinstance(key, str) for key in value):
        return {key: _copy_policy_value(item, array_item=True) for key, item in value.items()}
    raise ValueError("Policy value/default must be a JSON scalar or array")


def policy_value_ser(value, sformat="dict"):
    """Serialize a policy scalar or array without sharing mutable values."""
    value = _copy_policy_value(value)
    return value if sformat == "dict" else json.dumps(value)


def policy_value_deser(value, sformat="dict"):
    """Deserialize a policy scalar or array without coercing its JSON type."""
    if sformat != "dict":
        value = json.loads(value)
    return _copy_policy_value(value)


SINGLE_OPTIONAL_POLICY_VALUE = (object, False, policy_value_ser, policy_value_deser, True)


class Policy(Message):
    """The metadata policy verbs."""
    _string_array_operators = ("subset_of", "one_of", "superset_of", "add")
    c_param = {
        "subset_of": OPTIONAL_LIST_OF_STRINGS,
        "one_of": OPTIONAL_LIST_OF_STRINGS,
        "superset_of": OPTIONAL_LIST_OF_STRINGS,
        "add": OPTIONAL_LIST_OF_STRINGS,
        "value": SINGLE_OPTIONAL_POLICY_VALUE,
        "default": SINGLE_OPTIONAL_POLICY_VALUE,
        "essential": SINGLE_OPTIONAL_BOOLEAN
    }

    def from_dict(self, dictionary, **kwargs):
        """Keep standard operands intact before dependency normalization."""
        for key, value in dictionary.items():
            if key in self.c_param:
                self[key] = value
                continue
            super().from_dict({key: value}, **kwargs)
            # Unknown non-critical operators are retained. The dependency
            # filters empty strings during normal delegation.
            if key not in self:
                self._dict[key] = deepcopy(value)
        return self

    def __setitem__(self, key, value):
        # Message._add_value cannot handle a scalar/array union (notably bool).
        if key in ("value", "default"):
            deserializer = self.c_param[key][3]
            self._dict[key] = deserializer(value, sformat="dict")
        elif key in self._string_array_operators:
            # Preserve malformed input for deliberate live validation instead
            # of allowing dependency coercion or falsey-value filtering.
            operand = deepcopy(value)
            if not isinstance(operand, list) or not all(
                    isinstance(item, str) for item in operand):
                self._dict[key] = operand
                return
            deserializer = self.c_param[key][3]
            if deserializer:
                operand = deserializer(operand, sformat="dict")
            if not isinstance(operand, list) or not all(
                    isinstance(item, str) for item in operand):
                raise ValueError(
                    "{} policy deserializer must return an array of strings".format(key)
                )
            self._dict[key] = deepcopy(operand)
        elif key == "essential":
            self._dict[key] = deepcopy(value)
        else:
            super().__setitem__(key, value)

    def verify(self, **kwargs):
        if "metadata_policy_crit" in kwargs:
            verify_metadata_policy_crit(kwargs["metadata_policy_crit"])
        for operator in self._string_array_operators:
            if operator in self:
                operand = self[operator]
                if not isinstance(operand, list) or not all(
                        isinstance(value, str) for value in operand):
                    raise ValueError("{} policy value must be an array of strings".format(operator))
        if "essential" in self and type(self["essential"]) is not bool:
            raise ValueError("essential policy value must be a boolean")
        for operator in ("value", "default"):
            if operator in self:
                _copy_policy_value(self[operator])
        if "default" in self and self["default"] is None:
            raise ValueError("default policy value must not be null")


def verify_metadata_policy_crit(critical):
    """Reject invalid declarations and unsupported additional policy operators."""
    if not isinstance(critical, (list, tuple)) or not critical:
        raise MetadataPolicyCritError("metadata_policy_crit must be a non-empty array")
    if not all(isinstance(name, str) and name for name in critical):
        raise MetadataPolicyCritError("metadata_policy_crit must contain operator names")
    if set(critical).intersection(Policy.c_param):
        raise MetadataPolicyCritError("Standard operators must not appear in metadata_policy_crit")
    # Naming an extension in known_policy_extensions does not implement it.
    # No additional operators currently have merge and application support.
    raise MetadataPolicyCritError("Unsupported critical metadata policy operator")


def policy_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a MetadataPolicy."""
    return deserialize_from_one_of(val, Policy, sformat)


SINGLE_REQUIRED_POLICY = (Message, True, msg_ser, policy_deser, False)
SINGLE_OPTIONAL_POLICY = (Message, False, msg_ser, policy_deser, False)


def _verify_metadata_policy(policy, **kwargs):
    if not isinstance(policy, (dict, Message)) or not policy:
        raise ValueError("metadata_policy must be a nonempty JSON object")
    for typ, parameters in policy.items():
        if not isinstance(parameters, (dict, Message)) or not parameters:
            raise ValueError("metadata_policy {} must be a nonempty JSON object".format(typ))
        for attr, item in parameters.items():
            if not isinstance(item, (dict, Message)) or not item:
                raise ValueError("metadata_policy {} parameter {} must be a nonempty JSON object".format(
                    typ, attr))
            if isinstance(item, Policy):
                item.verify(**kwargs)
            else:
                Policy(**item).verify(**kwargs)


class MetadataPolicy(Message):
    """The different types of metadata that an entity in a federation can belong to."""
    c_param = {
        'openid_relying_party': OPTIONAL_MESSAGE,
        'openid_provider': OPTIONAL_MESSAGE,
        "oauth_authorization_server": OPTIONAL_MESSAGE,
        "oauth_client": OPTIONAL_MESSAGE,
        "federation_entity": OPTIONAL_MESSAGE,
        "trust_mark_issuer": OPTIONAL_MESSAGE
    }

    def from_dict(self, dictionary, **kwargs):
        """Keep every Entity Type and parameter-policy container visible."""
        for key, value in dictionary.items():
            if key in self.c_param:
                self[key] = value
            elif isinstance(value, dict):
                original = deepcopy(value)
                super(MetadataPolicy, self).from_dict(
                    {key: deepcopy(value)}, **kwargs
                )
                parsed = self[key]
                if isinstance(parsed, Message):
                    self._restore_filtered_values(parsed, original)
                else:
                    self._dict[key] = original
            else:
                self._dict[key] = deepcopy(value)
        return self

    def __setitem__(self, key, value):
        if key in self.c_param and isinstance(value, dict):
            super().from_dict({key: value})
            # Generic Message parsing drops empty parameter values. They must
            # remain visible until the complete policy structure is validated.
            self._restore_filtered_values(self[key], value)
        else:
            self._dict[key] = value

    @staticmethod
    def _restore_filtered_values(parsed, original):
        """Restore filtered policy values without replacing callback output."""
        for attr, item in original.items():
            if attr not in parsed and item in ("", [""]):
                parsed.update({attr: deepcopy(item)})

    def verify(self, **kwargs):
        """Validate policy containers before the existing operator checks."""
        _verify_metadata_policy(self, **kwargs)


def metadata_policy_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a MetadataPolicy."""
    return deserialize_from_one_of(val, MetadataPolicy, sformat)


SINGLE_REQUIRED_METADATA_POLICY = (Message, True, msg_ser, metadata_policy_deser, False)
SINGLE_OPTIONAL_METADATA_POLICY = (Message, False, msg_ser, metadata_policy_deser, False)


class Constraints(Message):
    """The types of constraints that can be applied to a trust chain."""
    c_param = {
        "max_path_length": SINGLE_OPTIONAL_INT,
        "naming_constraints": SINGLE_OPTIONAL_NAMING_CONSTRAINTS,
        # Preserve []: unlike omission, it permits federation_entity only.
        "allowed_entity_types": OPTIONAL_LIST_OF_STRINGS[:-1] + (True,),
    }

    def from_dict(self, dictionary, **kwargs):
        """Preserve original constraint values before dependency coercion."""
        for key, value in dictionary.items():
            if key in self.c_param:
                self[key] = value
            else:
                super().from_dict({key: value}, **kwargs)
        return self

    def __setitem__(self, key, value):
        if key == "naming_constraints":
            if isinstance(value, NamingConstraints):
                self._dict[key] = value
            elif isinstance(value, dict):
                deserializer = self.c_param[key][3]
                self._dict[key] = deserializer(value, sformat="dict")
            else:
                self._dict[key] = value
        elif key == "allowed_entity_types":
            allowed = deepcopy(value)
            if not isinstance(allowed, list) or not all(
                    isinstance(entity_type, str) for entity_type in allowed):
                self._dict[key] = allowed
                return
            deserializer = self.c_param[key][3]
            if deserializer:
                allowed = deserializer(allowed, sformat="dict")
            if not isinstance(allowed, list) or not all(
                    isinstance(entity_type, str) for entity_type in allowed):
                raise ConstraintError(
                    "allowed_entity_types deserializer must return an array of strings"
                )
            self._dict[key] = deepcopy(allowed)
        elif key == "max_path_length":
            self._dict[key] = deepcopy(value)
        else:
            super().__setitem__(key, value)

    def verify(self, **kwargs):
        """Validate constraint values independently of a candidate chain."""
        super().verify(**kwargs)
        if "max_path_length" in self:
            path_length = self["max_path_length"]
            if type(path_length) is not int or path_length < 0:
                raise ConstraintError("max_path_length must be a non-negative integer")
        if "naming_constraints" in self:
            naming = self["naming_constraints"]
            if isinstance(naming, NamingConstraints):
                naming.verify(**kwargs)
            elif isinstance(naming, (dict, Message)):
                NamingConstraints().from_dict(naming).verify(**kwargs)
            else:
                raise ConstraintError("naming_constraints must be a JSON object")
        allowed = self.get("allowed_entity_types", [])
        if not isinstance(allowed, list) or not all(
                isinstance(entity_type, str) for entity_type in allowed):
            raise ConstraintError("allowed_entity_types must be an array of strings")
        if "federation_entity" in allowed:
            raise ConstraintError("federation_entity must not appear in allowed_entity_types")
        return True


def constrains_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a Constraints."""
    return deserialize_from_one_of(val, Constraints, sformat)


SINGLE_REQUIRED_CONSTRAINS = (Message, True, msg_ser, constrains_deser, False)
SINGLE_OPTIONAL_CONSTRAINS = (Message, False, msg_ser, constrains_deser, False)


class TrustMarks(Message):
    c_param = {}

    def verify(self, **kwargs):
        for _id, spec in self.items():
            if not spec.get("trust_mark"):
                raise MissingRequiredAttribute("trust_mark")
            if not spec.get("trust_mark_type"):
                raise MissingRequiredAttribute("trust_mark_type")


class TrustMarkIssuers(Message):
    c_param = {}

    def verify(self, **kwargs):
        for owner_id, spec in self.items():
            if not isinstance(spec, list):
                raise ValueError("issuers MUST be a list")


class TrustMarkOwners(Message):

    def verify(self, **kwargs):
        # Dictionary of Trust Mark Owner information
        for owner_id, spec in self.items():
            if "sub" in spec and "jwks" in spec:  # If there are other claims ignore them
                continue
            else:
                if "sub" not in spec:
                    raise MissingRequiredAttribute("sub")
                elif "jwks" not in spec:
                    raise MissingRequiredAttribute("jwks")


def _entity_statement_protocol_claims():
    """Return claims defined by the built-in Entity Statement schemas."""
    claims = set()
    for message_cls in (
            EntityStatement,
            EntityConfiguration,
            SubordinateStatement,
            ExplicitRegistrationResponse,
    ):
        claims.update(message_cls.c_param)
    return claims


class EntityStatement(FederationPayloadMessage):
    """The Entity Statement"""
    c_param = {
        'iss': SINGLE_REQUIRED_STRING,
        'sub': SINGLE_REQUIRED_STRING,
        'iat': SINGLE_REQUIRED_NUMERIC_DATE,
        'exp': SINGLE_REQUIRED_NUMERIC_DATE,
        'jwks': SINGLE_REQUIRED_DICT,
#        'aud': SINGLE_OPTIONAL_STRING,
#        "jti": SINGLE_OPTIONAL_STRING,
        'metadata': SINGLE_OPTIONAL_METADATA,
        "crit": OPTIONAL_LIST_OF_STRINGS,
#        "policy_language_crit": OPTIONAL_LIST_OF_STRINGS,
    }

    @classmethod
    def validate_input(cls, payload, *, source_json=None):
        """Check supplied common claims without imposing derivative requiredness."""
        super().validate_input(payload, source_json=source_json)
        for claim in ("iss", "sub"):
            if claim in payload:
                _validate_entity_identifier(payload[claim], claim)
        for claim in ("iat", "exp"):
            if claim in payload:
                _validate_numeric_date(payload[claim], claim)
        if "jwks" in payload:
            _validate_jwks(payload["jwks"])
        if "crit" in payload:
            _validate_critical_claims(payload, _entity_statement_protocol_claims())

    def from_dict(self, dictionary, **kwargs):
        """Preserve fields whose invalid input the dependency can normalize or drop."""
        preserved = ("jwks", "iss", "sub", "crit", "iat", "exp", "metadata")
        super().from_dict({key: value for key, value in dictionary.items()
                           if key not in preserved}, **kwargs)
        for key in preserved:
            if key in dictionary:
                self[key] = dictionary[key]
        # Unknown extensions can be referenced by crit supplied now or in a later update.
        protocol_claims = _entity_statement_protocol_claims()
        for key, value in dictionary.items():
            declared_empty_array = (
                key in self.c_param and value == []
                and isinstance(self.c_param[key][0], list)
            )
            if key not in protocol_claims and (
                    value in ("", [""]) or declared_empty_array):
                self[key] = value
        return self

    def __setitem__(self, key, value):
        if key == "metadata":
            if isinstance(value, dict):
                deserializer = self.c_param[key][3]
                self._dict[key] = deserializer(value, sformat="dict")
            else:
                self._dict[key] = value
        elif key == "crit":
            self._set_declared_string_list(key, value)
        elif key in ("jwks", "iss", "sub", "iat", "exp"):
            self._dict[key] = value
        elif self._set_declared_empty_array_extension(key, value):
            return
        else:
            super().__setitem__(key, value)

    def _set_declared_empty_array_extension(self, key, value):
        """Preserve an empty array for a declared non-protocol list extension."""
        if value != [] or key in _entity_statement_protocol_claims():
            return False
        try:
            value_type, _, _, deserializer, _ = self.c_param[key]
        except KeyError:
            return False
        if not isinstance(value_type, list):
            return False
        self._add_value(
            str(key), value_type, key, deepcopy(value), deserializer, True,
            sformat="dict",
        )
        parsed = self._dict[key]
        item_type = value_type[0]
        if not isinstance(parsed, list) or not all(
                isinstance(item, item_type) for item in parsed):
            raise ValueError(
                "{} deserializer must return the declared array type".format(key)
            )
        self._dict[key] = deepcopy(parsed)
        return True

    def _set_declared_string_list(self, key, value):
        """Dispatch a valid statement list while retaining malformed input."""
        items = deepcopy(value)
        if not isinstance(items, list) or not items or not all(
                isinstance(item, str) and item for item in items):
            self._dict[key] = items
            return
        deserializer = self.c_param[key][3]
        if deserializer:
            items = deserializer(items, sformat="dict")
        if not isinstance(items, list) or not items or not all(
                isinstance(item, str) and item for item in items):
            raise ValueError(
                "{} deserializer must return a nonempty array of strings".format(key)
            )
        self._dict[key] = deepcopy(items)

    def verify(self, **kwargs):
        zero_dates = []
        for claim in ("iat", "exp"):
            if claim not in self:
                raise MissingRequiredAttribute(claim)
            value = self[claim]
            _validate_numeric_date(value, claim)
            if value == 0:
                zero_dates.append(claim)
        for claim in ("iss", "sub"):
            if claim in self:
                _validate_entity_identifier(self[claim], claim)
        if "jwks" in self:
            _validate_jwks(self["jwks"])
        if "metadata" in self:
            metadata = self["metadata"]
            if isinstance(metadata, Metadata):
                metadata.verify(**kwargs)
            else:
                _validate_metadata(metadata)
        validation_view = self
        if zero_dates:
            # Presence/type were checked above. Avoid Message.verify's falsey-required
            # rejection only for these dates, without changing values or shared schemas.
            validation_view = copy(self)
            validation_view.c_param = self.c_param.copy()
            for claim in zero_dates:
                spec = self.c_param[claim]
                validation_view.c_param[claim] = (spec[0], False) + spec[2:]
        super(EntityStatement, validation_view).verify(**kwargs)

        _validate_expected_issuer(self, kwargs.get("iss"))

        if "crit" in self:
            names = _validate_critical_claims(self, _entity_statement_protocol_claims())
            unsupported = names.difference(kwargs.get("known_extensions") or ())
            if unsupported:
                raise UnknownCriticalExtension(unsupported)


class EntityConfiguration(EntityStatement):
    _hint_claims = ("authority_hints", "trust_anchor_hints")
    _subordinate_only_claims = (
        "metadata_policy", "metadata_policy_crit", "constraints", "source_endpoint",
    )
    c_param = EntityStatement.c_param.copy()
    c_param.update({
        'authority_hints': OPTIONAL_LIST_OF_STRINGS,
        'trust_anchor_hints': OPTIONAL_LIST_OF_STRINGS,
        'trust_marks': OPTIONAL_LIST_OF_DICT,
        'trust_mark_owners': SINGLE_OPTIONAL_JSON,
        'trust_mark_issuers': SINGLE_OPTIONAL_JSON,
        #
        'trust_anchor': SINGLE_OPTIONAL_STRING
    })

    @classmethod
    def validate_input(cls, payload, *, source_json=None):
        """Check original Entity Configuration claims before construction."""
        super().validate_input(payload, source_json=source_json)
        _require_entity_statement_claims(payload)
        _validate_claim_placement(payload, cls._subordinate_only_claims, "Subordinate Statements")
        _validate_expected_issuer(payload, payload["sub"])
        for claim in cls._hint_claims:
            if claim in payload:
                _validate_entity_hints(payload[claim], claim)

    def from_dict(self, dictionary, **kwargs):
        """Preserve hint representations and the presence of forbidden claims."""
        super().from_dict({key: value for key, value in dictionary.items()
                           if key not in self._hint_claims}, **kwargs)
        for claim in self._subordinate_only_claims:
            if claim in dictionary:
                self._dict[claim] = dictionary[claim]
        for claim in self._hint_claims:
            if claim in dictionary:
                self[claim] = dictionary[claim]
        return self

    def __setitem__(self, key, value):
        if key in self._hint_claims:
            self._set_declared_string_list(key, value)
        else:
            super().__setitem__(key, value)

    def verify(self, **kwargs):
        _validate_claim_placement(self, self._subordinate_only_claims, "Subordinate Statements")
        if self.get("sub") is not None:
            kwargs["iss"] = self["sub"]
        super(EntityConfiguration, self).verify(**kwargs)
        for claim in self._hint_claims:
            if claim in self:
                _validate_entity_hints(self[claim], claim)
        _trust_mark_issuers = self.get("trust_mark_issuers")
        if _trust_mark_issuers:
            _tmi = TrustMarkIssuers(**_trust_mark_issuers)
            _tmi.verify()

        _trust_mark_owners = self.get("trust_mark_owners")
        if _trust_mark_owners:
            _tmi = TrustMarkOwners(**_trust_mark_owners)
            _tmi.verify()

        # This does not verify the signature of the trust marks
        # It only checks that the necessary claims are present
        _trust_marks = self.get("trust_marks")
        if _trust_marks:
            for _tm in _trust_marks:
                _trust_mark = None
                if isinstance(_tm["trust_mark"], str):
                    _trust_mark = None
                elif isinstance(_tm["trust_mark"], dict):
                    if _tm["trust_mark"]["trust_mark_type"] != _tm["trust_mark_type"]:
                        raise ValueError("trust_mark_is values does not match")
                    _trust_mark = TrustMark(**_tm["trust_mark"])
                else:
                    raise ValueError("Trust mark has a format I didn't expect")

                if _trust_mark is not None:
                    _trust_mark.verify()

class SubordinateStatement(EntityStatement):
    _entity_configuration_only_claims = (
        "authority_hints", "trust_anchor_hints", "trust_marks",
        "trust_mark_issuers", "trust_mark_owners",
    )
    c_param = EntityStatement.c_param.copy()
    c_param.update({
        'constraints': SINGLE_OPTIONAL_CONSTRAINS,
        'metadata_policy': SINGLE_OPTIONAL_METADATA_POLICY,
        # Keep an empty declaration visible so validation can reject it.
        'metadata_policy_crit': OPTIONAL_LIST_OF_STRINGS[:-1] + (True,),
        "source_endpoint": SINGLE_OPTIONAL_STRING,
    })

    @classmethod
    def validate_input(cls, payload, *, source_json=None):
        """Check original Subordinate Statement claims before construction."""
        super().validate_input(payload, source_json=source_json)
        _require_entity_statement_claims(payload)
        _validate_claim_placement(payload, cls._entity_configuration_only_claims, "Entity Configurations")

    def from_dict(self, dictionary, **kwargs):
        """Preserve forbidden claims even when dependency parsing drops falsey values."""
        super().from_dict({key: value for key, value in dictionary.items()
                           if key not in ("constraints", "metadata_policy",
                                          "metadata_policy_crit")}, **kwargs)
        if "constraints" in dictionary:
            self["constraints"] = dictionary["constraints"]
        if "metadata_policy" in dictionary:
            self["metadata_policy"] = dictionary["metadata_policy"]
        if "metadata_policy_crit" in dictionary:
            self["metadata_policy_crit"] = dictionary["metadata_policy_crit"]
        for claim in self._entity_configuration_only_claims:
            if claim in dictionary:
                self._dict[claim] = dictionary[claim]
        return self

    def __setitem__(self, key, value):
        if key == "constraints":
            if isinstance(value, Constraints):
                self._dict[key] = value
            elif isinstance(value, dict):
                deserializer = self.c_param[key][3]
                self._dict[key] = deserializer(value, sformat="dict")
            else:
                self._dict[key] = value
        elif key == "metadata_policy":
            if isinstance(value, dict):
                deserializer = self.c_param[key][3]
                self._dict[key] = deserializer(value, sformat="dict")
            else:
                self._dict[key] = value
        elif key == "metadata_policy_crit":
            self._set_declared_string_list(key, value)
        else:
            super().__setitem__(key, value)

    def verify(self, **kwargs):
        _validate_claim_placement(self, self._entity_configuration_only_claims, "Entity Configurations")
        super(SubordinateStatement, self).verify(**kwargs)
        if "constraints" in self:
            constraints = self["constraints"]
            if isinstance(constraints, Constraints):
                constraints.verify(**kwargs)
            elif isinstance(constraints, (dict, Message)):
                Constraints().from_dict(constraints).verify(**kwargs)
            else:
                raise ConstraintError("constraints must be a JSON object")
        if 'metadata_policy_crit' in self:
            verify_metadata_policy_crit(self['metadata_policy_crit'])
        if 'metadata_policy' in self:
            policy = self['metadata_policy']
            if isinstance(policy, MetadataPolicy):
                policy.verify(**kwargs)
            else:
                _verify_metadata_policy(policy, **kwargs)


class TrustMarkDelegation(FederationPayloadMessage):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "trust_mark_type": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "exp": SINGLE_OPTIONAL_INT,
        "ref": SINGLE_OPTIONAL_STRING
    }

class TrustMark(FederationPayloadMessage):
    c_param = {
        "sub": SINGLE_REQUIRED_STRING,
        'iss': SINGLE_REQUIRED_STRING,
        'iat': SINGLE_REQUIRED_INT,
        "trust_mark_type": SINGLE_REQUIRED_STRING,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "exp": SINGLE_OPTIONAL_INT,
        "ref": SINGLE_OPTIONAL_STRING,
        "delegation": SINGLE_OPTIONAL_STRING
    }

    def verify(self, **kwargs):
        super(TrustMark, self).verify(**kwargs)

        entity_id = kwargs.get("entity_id")

        if entity_id is not None and entity_id != self["sub"]:
            raise WrongSubject("Mismatch between subject in trust mark and entity_id of entity")
       
        return True


class TrustMarkStatusRequest(FederationPayloadMessage):
    c_param = {
        "sub": SINGLE_OPTIONAL_STRING,
        "trust_mark_type": SINGLE_OPTIONAL_STRING,
        "iat": SINGLE_OPTIONAL_INT,
        "trust_mark": SINGLE_OPTIONAL_STRING
    }

    def verify(self, **kwargs):
        if 'trust_mark' not in self:
            if 'sub' not in self or 'trust_mark_type' not in self:
                raise AttributeError('Must have both "sub" and "trust_mark_type" or "trust_mark"')


class TrustMarkStatusResponse(FederationPayloadMessage):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "trust_mark": SINGLE_REQUIRED_STRING,
        "status": SINGLE_REQUIRED_STRING
    }

    def verify(self, **kwargs):
        super(TrustMarkStatusResponse, self).verify(**kwargs)
        allowed_status_values = {"active", "expired", "revoked", "invalid"}
        allowed_status_values.update(kwargs.get("allowed_extra_status_values") or ())
        if self["status"] not in allowed_status_values:
            raise ValueError("Unknown Trust Mark Status Response status value")
        return True


def trust_mark_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a Trust Mark."""
    if isinstance(val, list):
        return [trust_mark_deser(item, sformat=sformat) for item in val]
    return deserialize_from_one_of(val, TrustMark, sformat)


SINGLE_REQUIRED_TRUST_MARK = (Message, True, msg_ser, trust_mark_deser, False)
OPTIONAL_LIST_OF_TRUST_MARKS = ([Message], False, msg_ser, trust_mark_deser, False)


class ResolveRequest(FederationPayloadMessage):
    """Unauthenticated Resolve request with repeated query parameters."""

    c_param = {
        "sub": SINGLE_REQUIRED_STRING,
        # No list serializer/deserializer: each value is a separate query parameter.
        "trust_anchor": ([str], True, None, None, False),
        "entity_type": ([str], False, None, None, False),
    }


class ResolveResponse(FederationPayloadMessage):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "exp": SINGLE_REQUIRED_INT,
        "metadata": SINGLE_REQUIRED_METADATA,
        "trust_chain": REQUIRED_LIST_OF_STRINGS,
        "trust_marks": OPTIONAL_LIST_OF_TRUST_MARKS,
        "aud": SINGLE_OPTIONAL_STRING
    }


class ListRequest(FederationPayloadMessage):
    c_param = {
        "entity_type": SINGLE_OPTIONAL_STRING,
        "trust_marked": SINGLE_OPTIONAL_BOOLEAN,
        "trust_mark_type": SINGLE_OPTIONAL_STRING,
        "intermediate": SINGLE_OPTIONAL_BOOLEAN
    }


class ListResponse(FederationPayloadMessage):
    c_param = {
        "entity_id": REQUIRED_LIST_OF_STRINGS
    }


class ProviderConfigurationResponse(message.oidc.ProviderConfigurationResponse):
    c_param = message.oidc.ProviderConfigurationResponse.c_param.copy()
    c_param.update({
        'client_registration_types_supported': REQUIRED_LIST_OF_STRINGS,
        'federation_registration_endpoint': SINGLE_OPTIONAL_STRING,
        'request_authentication_methods_supported': SINGLE_OPTIONAL_JSON,
        'request_authentication_signing_alg_values_supported': OPTIONAL_LIST_OF_STRINGS,
        'organization_name': SINGLE_OPTIONAL_STRING,
        'signed_jwks_uri': SINGLE_OPTIONAL_STRING,
        'jwks': SINGLE_OPTIONAL_JSON
    })


class RegistrationRequest(message.oidc.RegistrationRequest):
    c_param = message.oidc.RegistrationRequest.c_param.copy()
    c_param.update({
        'client_registration_types': REQUIRED_LIST_OF_STRINGS,
        'organization_name': SINGLE_OPTIONAL_STRING,
        'signed_jwks_uri': SINGLE_OPTIONAL_STRING,
        'jwks': SINGLE_OPTIONAL_JSON,
        "claims_parameter_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_encryption_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_encryption_enc_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "code_challenge_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
        "claims_suppported": OPTIONAL_LIST_OF_STRINGS
    })


class RegistrationResponse(ResponseMessage):
    """
    Response to client_register registration requests
    """

    c_param = ResponseMessage.c_param.copy()
    c_param.update(
        {
            "client_id": SINGLE_REQUIRED_STRING,
            "client_secret": SINGLE_OPTIONAL_STRING,
            "registration_access_token": SINGLE_OPTIONAL_STRING,
            "registration_client_uri": SINGLE_OPTIONAL_STRING,
            "client_id_issued_at": SINGLE_OPTIONAL_INT,
            "client_secret_expires_at": SINGLE_OPTIONAL_INT,
        }
    )
    c_param.update(RegistrationRequest.c_param)


class ExplicitRegistrationResponse(EntityStatement):
    """Federation Explicit Registration Response payload."""

    c_param = EntityStatement.c_param.copy()
    c_param.update({
        "jwks": SINGLE_OPTIONAL_DICT,
        "aud": SINGLE_REQUIRED_STRING,
        "trust_anchor": SINGLE_REQUIRED_STRING,
        "authority_hints": REQUIRED_LIST_OF_STRINGS,
        "metadata": SINGLE_REQUIRED_METADATA,
    })

    def verify(self, **kwargs):
        super(ExplicitRegistrationResponse, self).verify(**kwargs)

        if len(self["authority_hints"]) != 1:
            raise ValueError(
                "Explicit Registration Response authority_hints must contain "
                "exactly one value"
            )
        if self["aud"] != self["sub"]:
            raise ValueError(
                "Explicit Registration Response aud must match sub"
            )


class HistoricalKeysResponse(FederationPayloadMessage):
    c_param = {
        'iss': SINGLE_REQUIRED_STRING,
        'iat': SINGLE_REQUIRED_INT,
        'jwks': SINGLE_REQUIRED_DICT
    }


class TrustMarkRequest(FederationPayloadMessage):
    c_param = {
        "trust_mark_type": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING
    }


class WhoRequest(FederationPayloadMessage):
    c_param = {
        "entity_type": SINGLE_OPTIONAL_STRING,
        "credential_type": SINGLE_OPTIONAL_STRING,
        "trust_mark_type": SINGLE_OPTIONAL_STRING
    }


class WhoResponse(FederationPayloadMessage):
    c_param = {
        "entities_to_use": REQUIRED_LIST_OF_STRINGS
    }


class JWKSet(FederationPayloadMessage):
    c_param = {
        'keys': REQUIRED_LIST_OF_DICT,
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "exp": SINGLE_OPTIONAL_INT,
        "iat": SINGLE_OPTIONAL_INT,
        # below should NOT be used
        "nbf": SINGLE_OPTIONAL_INT,
        "jti": SINGLE_OPTIONAL_STRING,
    }
