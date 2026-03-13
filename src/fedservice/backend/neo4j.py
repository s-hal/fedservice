from typing import Any, Optional, Protocol

from .base import BaseBackend
from .base import ResolveData


class ResolveDataLoader(Protocol):
    def get_resolve_data(
        self,
        sub: str,
        trust_anchor: str,
        entity_type: Optional[str] = None,
    ) -> Optional[ResolveData]:
        ...


class Neo4jFederationBackend(BaseBackend):
    """Backend adapter for resolve data sourced from a Neo4j-backed repository."""

    def __init__(
        self,
        repository: Optional[ResolveDataLoader] = None,
        resolve_data_loader: Optional[ResolveDataLoader] = None,
    ):
        self.repository = repository
        self.resolve_data_loader = resolve_data_loader

    def get_entity_configuration(self, entity_id: str) -> Any:
        raise NotImplementedError()

    def get_entity_statement(self, issuer: str, subject: str) -> Any:
        raise NotImplementedError()

    def get_resolve_data(
        self,
        sub: str,
        trust_anchor: str,
        entity_type: Optional[str] = None,
    ) -> ResolveData:
        source = self.resolve_data_loader or self.repository
        if source is None:
            raise NotImplementedError("No Neo4j resolve data source is configured")

        if not hasattr(source, "get_resolve_data"):
            raise NotImplementedError("Repository does not expose a get_resolve_data method")

        resolve_data = source.get_resolve_data(
            sub=sub,
            trust_anchor=trust_anchor,
            entity_type=entity_type,
        )

        if resolve_data is None:
            raise LookupError(
                f"No resolve data found for sub={sub!r} and trust_anchor={trust_anchor!r}"
            )

        return resolve_data

    def list_subordinates(
        self,
        issuer: str,
        entity_type: Optional[str] = None,
        intermediate: Optional[bool] = None,
    ) -> Any:
        raise NotImplementedError()
