import logging
from typing import Callable
from typing import Optional

from cryptojwt.jwt import utc_time_sans_frac

from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.signing import sign_federation_jwt_with_keyjar

logger = logging.getLogger(__name__)


def create_entity_statement(iss, sub, key_jar, lifetime=86400, include_jwks=True,
                            signing_alg: Optional[str] = "RS256",
                            jws_headers=None, profile=None, kid=None, **kwargs):
    """

    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param lifetime: The lifetime of the signed JWT.
    :param include_jwks: Add JWKS
    :param signing_alg: Which signing algorithm that should be used
    :param kwargs: Additional arguments for the JSON object
    :return: A signed JSON Web Token
    """

    now = utc_time_sans_frac()
    msg = {'iss': iss, 'sub': sub, 'iat': now, 'exp': now + lifetime}

    if kwargs:
        msg.update(kwargs)

    if include_jwks:
        if "jwks" in kwargs:
            msg['jwks'] = kwargs['jwks']
        else:
            # The public signing keys of the subject
            msg['jwks'] = key_jar.export_jwks()

    if profile is None:
        profile = ENTITY_CONFIGURATION if iss == sub else SUBORDINATE_STATEMENT

    return sign_federation_jwt_with_keyjar(
        profile=profile,
        payload=msg,
        key_jar=key_jar,
        issuer=iss,
        alg=signing_alg,
        kid=kid,
        extra_protected_headers=jws_headers,
    )


def create_entity_configuration(iss, key_jar, metadata=None,
                                authority_hints=None, lifetime=86400, include_jwks=True,
                                signing_alg: Optional[str] = "RS256",
                                jws_headers=None, **kwargs):
    """

    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param metadata: The entity's metadata organised as a dictionary with the
        entity type as key
    :param lifetime: The lifetime of the signed JWT.
    :param include_jwks: Add JWKS
    :param signing_alg: Which signing algorithm that should be used
    :return: A signed JSON Web Token
    """

    msg = {}

    if metadata:
        msg["metadata"] = metadata

    if authority_hints:
        if isinstance(authority_hints, Callable):
            msg['authority_hints'] = authority_hints()
        else:
            msg['authority_hints'] = authority_hints

    if kwargs:
        msg.update(kwargs)

    return create_entity_statement(iss, iss, key_jar, lifetime=lifetime, include_jwks=include_jwks,
                                   signing_alg=signing_alg, jws_headers=jws_headers,
                                   profile=ENTITY_CONFIGURATION, **msg)


def create_resolve_response(iss, sub, key_jar, metadata, trust_chain,
                            lifetime=86400, signing_alg: Optional[str] = "RS256",
                            trust_marks=None, aud=None, kid=None):
    """Create a signed Resolve Response JWT using the Resolve profile."""
    now = utc_time_sans_frac()
    payload = {
        "iss": iss,
        "sub": sub,
        "iat": now,
        "exp": now + lifetime,
        "metadata": metadata,
        "trust_chain": trust_chain,
    }
    if trust_marks:
        payload["trust_marks"] = trust_marks
    if aud:
        payload["aud"] = aud

    return sign_federation_jwt_with_keyjar(
        profile=RESOLVE_RESPONSE,
        payload=payload,
        key_jar=key_jar,
        issuer=iss,
        alg=signing_alg,
        kid=kid,
    )


def create_subordinate_statement(iss, sub, key_jar, lifetime=86400, include_jwks=True, constraints=None,
                                 signing_alg: Optional[str] = "RS256", **kwargs):
    """

    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param lifetime: The lifetime of the signed JWT.
    :param include_jwks: Add JWKS
    :param signing_alg: Which signing algorithm that should be used
    :return: A signed JSON Web Token
    """

    if constraints:
        msg = {'constraints': constraints}
    else:
        msg = {}

    if kwargs:
        msg.update(kwargs)

    return create_entity_statement(iss, sub, key_jar, lifetime=lifetime, include_jwks=include_jwks,
                                   signing_alg=signing_alg, profile=SUBORDINATE_STATEMENT,
                                   **msg)
