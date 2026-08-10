"""Claim validation helpers for Federation JWT payloads."""


def validate_iat_not_in_future(payload, now, leeway):
    """Reject an iat later than the effective time plus profile leeway."""
    iat = payload.get("iat")
    if iat is None:
        return

    try:
        if iat > now + leeway:
            raise ValueError("Federation JWT iat is in the future.")
    except TypeError as err:
        raise ValueError("Federation JWT iat must be numeric.") from err
