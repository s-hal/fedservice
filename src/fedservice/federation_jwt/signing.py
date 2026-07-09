"""Producer-side signing adapters for Federation JWT profiles."""

from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.jose import sign_federation_jwt


_RSA_ALGS = frozenset(["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])
_EC_ALGS = frozenset(["ES256", "ES384", "ES512"])
_OKP_ALGS = frozenset(["EdDSA"])


def _key_type_for_alg(alg):
    if alg in _RSA_ALGS:
        return "RSA"
    if alg in _EC_ALGS:
        return "EC"
    if alg in _OKP_ALGS:
        return "OKP"
    return ""


def _key_kid(key):
    return getattr(key, "kid", None) or ""


def _select_signing_key(key_jar, issuer, alg, kid=None):
    key_type = _key_type_for_alg(alg)
    try:
        keys = key_jar.get_signing_key(key_type=key_type, issuer_id=issuer, kid=kid)
    except Exception as err:
        raise FederationJwtKeyResolutionError(
            "Federation JWT signing key could not be selected."
        ) from err

    keys = list(keys or [])
    if not keys:
        raise FederationJwtKeyResolutionError(
            "No Federation JWT signing key available for issuer."
        )

    if kid is not None:
        for key in keys:
            if _key_kid(key) == kid:
                return key, kid
        raise FederationJwtKeyResolutionError(
            "No Federation JWT signing key matched the requested kid."
        )

    key = sorted(keys, key=_key_kid)[0]
    selected_kid = _key_kid(key)
    if not selected_kid:
        raise FederationJwtKeyResolutionError(
            "Federation JWT signing key must have a kid."
        )
    return key, selected_kid


def sign_federation_jwt_with_keyjar(
    profile,
    payload,
    key_jar,
    issuer,
    alg,
    kid=None,
    extra_protected_headers=None,
):
    """Sign a Federation JWT profile using local KeyJar signing material."""
    signing_key, selected_kid = _select_signing_key(
        key_jar=key_jar,
        issuer=issuer,
        alg=alg,
        kid=kid,
    )
    return sign_federation_jwt(
        profile=profile,
        payload=payload,
        signing_key=signing_key,
        alg=alg,
        kid=selected_kid,
        extra_protected_headers=extra_protected_headers,
    )
