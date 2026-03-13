from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ResolveData:
    """Data required to produce a federation resolve response."""

    sub: str
    trust_anchor: str
    metadata: dict
    trust_chain: list[str]
    exp: int
    trust_marks: Optional[list[dict]] = None


class BaseBackend(ABC):
    """Abstract base class for federation data backend implementations."""

    @abstractmethod
    def get_entity_configuration(self, entity_id: str) -> Any:
        """Retrieve the entity configuration for the given entity ID."""
        pass

    @abstractmethod
    def get_entity_statement(self, issuer: str, subject: str) -> Any:
        """Retrieve the entity statement from issuer about subject."""
        pass

    @abstractmethod
    def get_resolve_data(
        self,
        sub: str,
        trust_anchor: str,
        entity_type: Optional[str] = None,
    ) -> ResolveData:
        """Return the data needed to produce a resolve response."""
        pass

    @abstractmethod
    def list_subordinates(
        self,
        issuer: str,
        entity_type: Optional[str] = None,
        intermediate: Optional[bool] = None,
    ) -> Any:
        """List subordinates of the issuer, optionally filtered."""
        pass
