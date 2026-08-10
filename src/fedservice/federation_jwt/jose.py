"""JOSE header validation, signing, and verification helpers."""

from collections.abc import Mapping as MappingABC
from typing import Mapping

from cryptojwt.exception import BadSignature
from cryptojwt.exception import IssuerNotFound
from cryptojwt.exception import KeyNotFound
from cryptojwt.exception import MissingKey
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.jwt import JWT
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.jws.exception import NoSuitableSigningKeys

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.federation_jwt.verified import create_verified_federation_jwt


def validate_protected_header(
    profile: FederationJwtProfile,
    protected_header: Mapping,
):
    """Validate a protected JOSE header against an explicit profile."""
    if not isinstance(protected_header, MappingABC):
        raise FederationJwtHeaderError("Protected JOSE header must be mapping-like.")

    header = dict(protected_header)

    missing_headers = [
        name for name in profile.required_headers
        if name not in header
    ]
    if missing_headers:
        raise FederationJwtHeaderError(
            "Protected JOSE header is missing required headers."
        )

    typ = header.get("typ")
    if not isinstance(typ, str):
        raise FederationJwtHeaderError("Protected JOSE header typ must be a string.")
    if not profile.accepts_typ(typ):
        raise FederationJwtHeaderError(
            "Protected JOSE header typ does not match profile."
        )

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise FederationJwtHeaderError(
            "Protected JOSE header kid must be a non-empty string."
        )

    _validate_algorithm(profile, header.get("alg"))
    _validate_optional_header_policy(profile, header)

    return header


def _validate_algorithm(profile, alg):
    if not isinstance(alg, str) or not alg:
        raise FederationJwtHeaderError(
            "Protected JOSE header alg must be a non-empty string."
        )
    if alg.lower() == "none":
        raise FederationJwtHeaderError("Protected JOSE header alg none is not allowed.")
    if alg not in profile.allowed_algs:
        raise FederationJwtHeaderError("Protected JOSE header alg is not allowed.")


def _validate_optional_header_policy(profile, header):
    forbidden_headers = set(profile.forbidden_headers).intersection(header)
    if forbidden_headers:
        raise FederationJwtHeaderError(
            "Protected JOSE header includes forbidden headers."
        )

    if "crit" in header:
        crit = header["crit"]
        if not isinstance(crit, (list, tuple)):
            raise FederationJwtHeaderError(
                "Protected JOSE header crit must be a list or tuple."
            )

        for entry in crit:
            if not isinstance(entry, str):
                raise FederationJwtHeaderError(
                    "Protected JOSE header crit entries must be strings."
                )
            if entry not in profile.allowed_crit_headers:
                raise FederationJwtHeaderError(
                    "Protected JOSE header crit entry is not allowed."
                )
            if entry not in header:
                raise FederationJwtHeaderError(
                    "Protected JOSE header crit entry names a missing header."
                )

    if "b64" in header:
        b64 = header["b64"]
        if not isinstance(b64, bool):
            raise FederationJwtHeaderError("Protected JOSE header b64 must be boolean.")
        if b64 is False and not profile.allow_b64_false:
            raise FederationJwtHeaderError(
                "Protected JOSE header b64=false is not allowed."
            )


def sign_federation_jwt(
    profile: FederationJwtProfile,
    payload,
    key_jar,
    issuer: str,
    alg: str,
    kid=None,
    lifetime=0,
    iat=None,
    extra_protected_headers=None,
):
    """Sign a Federation JWT with Cryptojwt for an explicit profile."""
    if not isinstance(payload, MappingABC):
        raise FederationJwtPayloadError("Federation JWT payload must be mapping-like.")

    if extra_protected_headers is None:
        extra_protected_headers = {}
    if not isinstance(extra_protected_headers, MappingABC):
        raise FederationJwtHeaderError(
            "Extra protected JOSE headers must be mapping-like."
        )
    extra_protected_headers = dict(extra_protected_headers)

    reserved_headers = {"alg", "kid", "typ"}
    if reserved_headers.intersection(extra_protected_headers):
        raise FederationJwtHeaderError(
            "Extra protected JOSE headers must not override reserved headers."
        )

    if kid is not None and (not isinstance(kid, str) or not kid):
        raise FederationJwtHeaderError(
            "Protected JOSE header kid must be a non-empty string."
        )

    _validate_algorithm(profile, alg)
    _validate_optional_header_policy(profile, extra_protected_headers)

    jws_headers = {"typ": profile.typ}
    jws_headers.update(extra_protected_headers)
    signer = JWT(
        key_jar=key_jar,
        iss=issuer,
        lifetime=lifetime,
        sign_alg=alg,
        allowed_sign_algs=list(profile.allowed_algs),
    )

    try:
        compact = signer.pack(
            payload=dict(payload),
            kid=kid or "",
            issuer_id=issuer,
            iat=iat,
            jws_headers=jws_headers,
        )
    except (KeyNotFound, MissingKey, NoSuitableSigningKeys) as err:
        raise FederationJwtKeyResolutionError(
            "Federation JWT signing key could not be resolved."
        ) from err
    except Exception as err:
        raise FederationJwtSignatureError(
            "Federation JWT could not be signed."
        ) from err

    try:
        parsed_jws = jws_factory(compact)
        if parsed_jws is None:
            raise FederationJwtHeaderError(
                "Signed Federation JWT is not a compact JWS."
            )
        validate_protected_header(
            profile=profile,
            protected_header=parsed_jws.jwt.headers,
        )
    except FederationJwtHeaderError as err:
        raise FederationJwtSignatureError(
            "Signed Federation JWT protected header is invalid."
        ) from err
    except Exception as err:
        raise FederationJwtSignatureError(
            "Signed Federation JWT protected header could not be parsed."
        ) from err

    return compact


def verify_federation_jwt(
    profile: FederationJwtProfile,
    token,
    key_jar,
    now=None,
):
    """Verify a compact Federation JWT for an explicit profile."""
    try:
        parsed_jws = jws_factory(token)
        if parsed_jws is None:
            raise ValueError("Input is not a compact JWS.")
        protected_header = validate_protected_header(
            profile=profile,
            protected_header=parsed_jws.jwt.headers,
        )
    except FederationJwtHeaderError:
        raise
    except Exception as err:
        raise FederationJwtHeaderError(
            "Compact JWS protected header could not be parsed."
        ) from err

    verifier = JWT(
        key_jar=key_jar,
        msg_cls=profile.message_cls,
        allowed_sign_algs=list(profile.allowed_algs),
    )

    try:
        parsed_message = verifier.unpack(token, timestamp=now)
    except (IssuerNotFound, KeyNotFound, MissingKey, NoSuitableSigningKeys) as err:
        raise FederationJwtKeyResolutionError(
            "Federation JWT verification key could not be resolved."
        ) from err
    except BadSignature as err:
        raise FederationJwtSignatureError(
            "Federation JWT signature verification failed."
        ) from err
    except Exception as err:
        raise FederationJwtPayloadError(
            "Federation JWT payload, message, or time validation failed."
        ) from err

    verified_payload = parsed_jws.jwt.payload()
    if not isinstance(verified_payload, MappingABC):
        raise FederationJwtPayloadError(
            "Federation JWT verified payload must be a JSON object."
        )
    verified_payload = dict(verified_payload)

    effective_now = now if now is not None else utc_time_sans_frac()
    for validator in profile.payload_validators:
        try:
            if validator(
                verified_payload,
                now=effective_now,
                skew=verifier.skew,
            ) is False:
                raise ValueError("Payload validator returned false.")
        except Exception as err:
            raise FederationJwtPayloadError(
                "Federation JWT payload validator failed."
            ) from err

    if isinstance(token, bytes):
        token_bytes = token
        token_text = token.decode("ascii")
    else:
        token_text = token
        token_bytes = token.encode("ascii")

    return create_verified_federation_jwt(
        profile=profile,
        token=token_text,
        token_bytes=token_bytes,
        protected_header=protected_header,
        payload_json=verified_payload,
        parsed_message=parsed_message,
        issuer=verified_payload.get("iss"),
        subject=verified_payload.get("sub"),
        issued_at=verified_payload.get("iat"),
        expires_at=verified_payload.get("exp"),
    )
