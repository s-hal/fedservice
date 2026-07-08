"""Exception types for Federation JWT processing."""


class FederationJwtError(ValueError):
    """Base class for federation JWT processing errors."""


class FederationJwtHeaderError(FederationJwtError):
    """Invalid or unsupported JOSE header."""


class FederationJwtSignatureError(FederationJwtError):
    """Signature validation failed."""


class FederationJwtKeyResolutionError(FederationJwtError):
    """No acceptable verification key could be resolved."""


class FederationJwtPayloadError(FederationJwtError):
    """Payload deserialization or payload validation failed."""


class FederationJwtProfileError(FederationJwtError):
    """Profile configuration or profile usage error."""


class FederationJwtContentNegotiationError(FederationJwtError):
    """HTTP Accept negotiation failed for a profile-backed endpoint."""
