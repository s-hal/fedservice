"""HTTP content negotiation helpers for profile-backed Federation JWT endpoints."""

from typing import Optional

from fedservice.federation_jwt.errors import FederationJwtContentNegotiationError
from fedservice.federation_jwt.profile import FederationJwtProfile


def _parse_q(value):
    try:
        q = float(value)
    except (TypeError, ValueError):
        return None

    if q < 0 or q > 1:
        return None
    return q


def _parse_accept_member(member):
    parts = [part.strip() for part in member.split(";")]
    media_type = parts[0].lower()
    if not media_type or media_type.count("/") != 1:
        return None
    if any(char.isspace() for char in media_type):
        return None

    type_part, subtype_part = media_type.split("/", 1)
    if not type_part or not subtype_part:
        return None
    if any(char.isspace() for char in type_part + subtype_part):
        return None

    q = 1.0
    for parameter in parts[1:]:
        if not parameter:
            continue
        if "=" not in parameter:
            continue
        name, value = [part.strip() for part in parameter.split("=", 1)]
        if name.lower() == "q":
            parsed_q = _parse_q(value)
            if parsed_q is None:
                return None
            q = parsed_q

    return "{}/{}".format(type_part, subtype_part), q


def _iter_acceptable_media_ranges(accept_header):
    for member in accept_header.split(","):
        parsed = _parse_accept_member(member.strip())
        if parsed is None:
            continue
        media_type, q = parsed
        if q <= 0:
            continue
        yield media_type, q


def accepts_profile_response(
    *,
    accept_header: Optional[str],
    profile: FederationJwtProfile,
    allow_application_wildcard: bool = False,
) -> bool:
    """Return whether Accept permits the profile success media type."""
    if accept_header is None or not accept_header.strip():
        return True

    expected = profile.content_type.lower()
    accepted_ranges = tuple(_iter_acceptable_media_ranges(accept_header))
    if not accepted_ranges:
        return False

    for media_type, _q in accepted_ranges:
        if media_type == expected:
            return True
        if media_type == "*/*":
            return True
        if allow_application_wildcard and media_type == "application/*":
            return True

    return False


def require_acceptable_response(
    *,
    accept_header: Optional[str],
    profile: FederationJwtProfile,
) -> None:
    """Raise when Accept does not permit the profile success media type."""
    if not accepts_profile_response(accept_header=accept_header, profile=profile):
        raise FederationJwtContentNegotiationError(
            "Accept header does not allow {}.".format(profile.content_type)
        )
