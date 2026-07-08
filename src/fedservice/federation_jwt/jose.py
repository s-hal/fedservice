"""JOSE header validation, signing, and verification helpers."""

from cryptojwt.jws.jws import JWSig

from fedservice.federation_jwt.errors import FederationJwtHeaderError


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
