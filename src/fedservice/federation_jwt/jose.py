"""JOSE header validation, signing, and verification helpers."""

from collections.abc import Mapping as MappingABC
from typing import Mapping

from cryptojwt.jws.jws import JWSig

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.profile import FederationJwtProfile


def normalize_compact_token(token):
    """Normalize a compact token input to text."""
    if isinstance(token, str):
        return token

    if isinstance(token, bytes):
        try:
            return token.decode("ascii")
        except UnicodeDecodeError as err:
            raise FederationJwtHeaderError(
                "Compact JWS bytes must be ASCII."
            ) from err

    raise FederationJwtHeaderError("Compact JWS token must be str or bytes.")


def decode_protected_header(token):
    """Decode the protected JOSE header from a compact JWS."""
    normalized = normalize_compact_token(token)
    try:
        parsed = JWSig().unpack(normalized)
    except Exception as err:
        raise FederationJwtHeaderError(
            "Compact JWS protected header could not be decoded."
        ) from err

    # JWSig.unpack() decodes compact part 0 into headers without verifying the
    # signature. This is the narrow cryptojwt view of the protected JOSE header.
    header = parsed.headers
    if not isinstance(header, dict):
        raise FederationJwtHeaderError("Protected JOSE header must be a JSON object.")

    return dict(header)


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

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise FederationJwtHeaderError(
            "Protected JOSE header alg must be a non-empty string."
        )
    if alg.lower() == "none":
        raise FederationJwtHeaderError("Protected JOSE header alg none is not allowed.")
    if alg not in profile.allowed_algs:
        raise FederationJwtHeaderError("Protected JOSE header alg is not allowed.")

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

    return header


def decode_and_validate_protected_header(
    profile: FederationJwtProfile,
    token,
):
    """Decode and validate a compact JWS protected JOSE header."""
    return validate_protected_header(
        profile=profile,
        protected_header=decode_protected_header(token),
    )
