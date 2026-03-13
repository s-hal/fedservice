import pytest

from fedservice.backend import Neo4jFederationBackend
from fedservice.backend import ResolveData


class StaticLoader:
    def __init__(self, resolve_data):
        self.resolve_data = resolve_data
        self.calls = []

    def get_resolve_data(self, sub, trust_anchor, entity_type=None):
        self.calls.append(
            {
                "sub": sub,
                "trust_anchor": trust_anchor,
                "entity_type": entity_type,
            }
        )
        return self.resolve_data


class RaisingLoader:
    def get_resolve_data(self, sub, trust_anchor, entity_type=None):
        raise RuntimeError("boom")


def test_loader_returns_resolve_data():
    resolve_data = ResolveData(
        sub="https://leaf.example.org",
        trust_anchor="https://ta.example.org",
        metadata={"openid_relying_party": {"client_name": "leaf"}},
        trust_chain=["ec", "es1", "es2"],
        exp=1234,
    )
    loader = StaticLoader(resolve_data)
    backend = Neo4jFederationBackend(resolve_data_loader=loader)

    result = backend.get_resolve_data(
        sub="https://leaf.example.org",
        trust_anchor="https://ta.example.org",
        entity_type="openid_relying_party",
    )

    assert result is resolve_data
    assert loader.calls == [
        {
            "sub": "https://leaf.example.org",
            "trust_anchor": "https://ta.example.org",
            "entity_type": "openid_relying_party",
        }
    ]


def test_loader_returning_none_raises_lookup_error():
    loader = StaticLoader(None)
    backend = Neo4jFederationBackend(resolve_data_loader=loader)

    with pytest.raises(LookupError):
        backend.get_resolve_data(
            sub="https://leaf.example.org",
            trust_anchor="https://ta.example.org",
        )


def test_loader_exception_is_propagated():
    backend = Neo4jFederationBackend(resolve_data_loader=RaisingLoader())

    with pytest.raises(RuntimeError, match="boom"):
        backend.get_resolve_data(
            sub="https://leaf.example.org",
            trust_anchor="https://ta.example.org",
        )
