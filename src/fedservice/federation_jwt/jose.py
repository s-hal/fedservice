"""JOSE header validation, signing, and verification helpers."""

import base64
import binascii
import json
import re
from dataclasses import dataclass

from fedservice.federation_jwt.errors import FederationJwtHeaderError


_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class CompactJwsParts:
    """The three dot-separated parts of a compact JWS."""

    protected: str
    payload: str
    signature: str


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


def split_compact_jws(token):
    """Split a compact JWS into protected, payload, and signature parts."""
    normalized = normalize_compact_token(token)
    parts = normalized.split(".")

    if len(parts) != 3:
        raise FederationJwtHeaderError("Compact JWS must contain exactly three parts.")

    protected, payload, signature = parts
    if not protected:
        raise FederationJwtHeaderError("Compact JWS protected-header part is empty.")
    if not payload:
        raise FederationJwtHeaderError("Compact JWS payload part is empty.")
    if not signature:
        raise FederationJwtHeaderError("Compact JWS signature part is empty.")

    return CompactJwsParts(
        protected=protected,
        payload=payload,
        signature=signature,
    )


def base64url_decode_segment(segment):
    """Decode an unpadded base64url JOSE segment."""
    if not isinstance(segment, str):
        raise FederationJwtHeaderError("JOSE segment must be a string.")
    if not _BASE64URL_RE.match(segment):
        raise FederationJwtHeaderError("JOSE segment is not valid base64url.")
    if len(segment) % 4 == 1:
        raise FederationJwtHeaderError("JOSE segment has invalid base64url length.")

    padded = segment + ("=" * (-len(segment) % 4))
    try:
        return base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as err:
        raise FederationJwtHeaderError("JOSE segment is not valid base64url.") from err


def decode_protected_header(token):
    """Decode the protected JOSE header from a compact JWS."""
    compact = split_compact_jws(token)
    header_bytes = base64url_decode_segment(compact.protected)

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise FederationJwtHeaderError(
            "Protected JOSE header is not valid JSON."
        ) from err

    if not isinstance(header, dict):
        raise FederationJwtHeaderError("Protected JOSE header must be a JSON object.")

    return header
