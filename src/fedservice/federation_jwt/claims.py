"""Claim validation helpers for Federation JWT payloads."""


def validate_iat_not_in_future(payload, now, skew):
    """Reject an iat later than the effective time plus verifier skew."""
    iat = payload.get("iat")
    if iat is None:
        return

    try:
        if iat > now + skew:
            raise ValueError("Federation JWT iat is in the future.")
    except TypeError as err:
        raise ValueError("Federation JWT iat must be numeric.") from err


def validate_subordinate_statement_relationship(payload, now, skew):
    """Reject self-issued payloads when a Subordinate Statement is expected."""
    if payload.get("iss") == payload.get("sub"):
        raise ValueError("Subordinate Statement issuer and subject must differ.")
