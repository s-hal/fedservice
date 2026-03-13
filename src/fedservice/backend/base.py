from abc import ABC, abstractmethod
from typing import Any, Optional


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
    def list_subordinates(
        self,
        issuer: str,
        entity_type: Optional[str] = None,
        intermediate: Optional[bool] = None,
    ) -> Any:
        """List subordinates of the issuer, optionally filtered."""
        pass