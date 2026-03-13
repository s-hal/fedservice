from typing import Any, Callable, Optional

from .base import BaseBackend


class Neo4jFederationBackend(BaseBackend):
    """Backend adapter for resolve data sourced from a Neo4j-backed repository."""

    def __init__(
        self,
        repository: Optional[Any] = None,
        resolve_data_loader: Optional[Callable[..., Any]] = None,
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
    ) -> Any:
        if self.resolve_data_loader is not None:
            return self.resolve_data_loader(
                sub=sub,
                trust_anchor=trust_anchor,
                entity_type=entity_type,
            )

        if self.repository is None:
            raise NotImplementedError("No Neo4j resolve data source is configured")

        if hasattr(self.repository, "get_resolve_data"):
            return self.repository.get_resolve_data(
                sub=sub,
                trust_anchor=trust_anchor,
                entity_type=entity_type,
            )

        if hasattr(self.repository, "resolve"):
            return self.repository.resolve(
                sub=sub,
                trust_anchor=trust_anchor,
                entity_type=entity_type,
            )

        raise NotImplementedError("Repository does not expose a resolve-data method")

    def list_subordinates(
        self,
        issuer: str,
        entity_type: Optional[str] = None,
        intermediate: Optional[bool] = None,
    ) -> Any:
        raise NotImplementedError()
