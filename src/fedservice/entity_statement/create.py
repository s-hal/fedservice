import logging
from typing import Callable
from typing import Optional

from cryptojwt.jwt import utc_time_sans_frac

from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT

logger = logging.getLogger(__name__)


def create_entity_statement(iss, sub, key_jar, profile, lifetime=86400, include_jwks=True,
                            signing_alg: Optional[str] = "RS256",
                            extra_protected_headers=None, kid=None, **kwargs):
    """

    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param profile: The Federation JWT profile supplied by protocol context
    :param lifetime: The lifetime of the signed JWT.
    :param include_jwks: Add JWKS
    :param signing_alg: Which signing algorithm that should be used
    :param kwargs: Additional arguments for the JSON object
    :return: A signed JSON Web Token
    """

    msg = {'sub': sub}

    if kwargs:
        msg.update(kwargs)

    if include_jwks:
        if "jwks" in kwargs:
            msg['jwks'] = kwargs['jwks']
        else:
            # The public signing keys of the subject
            msg['jwks'] = key_jar.export_jwks()

    return sign_federation_jwt(
        profile=profile,
        payload=msg,
        key_jar=key_jar,
        issuer=iss,
        alg=signing_alg,
        kid=kid,
        lifetime=lifetime,
        extra_protected_headers=extra_protected_headers,
    )


def create_entity_configuration(iss, key_jar, metadata=None,
                                authority_hints=None, lifetime=86400, include_jwks=True,
                                signing_alg: Optional[str] = "RS256",
                                extra_protected_headers=None, **kwargs):
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

    return create_entity_statement(iss, iss, key_jar, ENTITY_CONFIGURATION,
                                   lifetime=lifetime, include_jwks=include_jwks,
                                   signing_alg=signing_alg,
                                   extra_protected_headers=extra_protected_headers,
                                   **msg)


def create_resolve_response(iss, sub, key_jar, metadata, trust_chain, expires_at,
                            signing_alg: Optional[str] = "RS256",
                            trust_marks=None, aud=None, kid=None):
    """Create a signed Resolve Response JWT using the Resolve profile."""
    now = utc_time_sans_frac()
    payload = {
        "sub": sub,
        "exp": expires_at,
        "metadata": metadata,
        "trust_chain": trust_chain,
    }
    if trust_marks:
        payload["trust_marks"] = trust_marks
    if aud:
        payload["aud"] = aud

    return sign_federation_jwt(
        profile=RESOLVE_RESPONSE,
        payload=payload,
        key_jar=key_jar,
        issuer=iss,
        alg=signing_alg,
        kid=kid,
        lifetime=0,
        iat=now,
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

    return create_entity_statement(iss, sub, key_jar, SUBORDINATE_STATEMENT,
                                   lifetime=lifetime, include_jwks=include_jwks,
                                   signing_alg=signing_alg,
                                   **msg)
