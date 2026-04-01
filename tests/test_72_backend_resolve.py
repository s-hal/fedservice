import pytest
from cryptojwt.jws.jws import factory

from fedservice.backend import Neo4jFederationBackend
from fedservice.backend import ResolveData
from tests.test_57_resolve import FEDERATION_CONFIG
from tests.test_57_resolve import IM_ID
from tests.test_57_resolve import RP_ID
from tests.test_57_resolve import TA_ID
from tests.build_federation import build_federation


class StaticLoader:
    def __init__(self, resolve_data, calls):
        self.resolve_data = resolve_data
        self.calls = calls

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
    def __init__(self, exc):
        self.exc = exc
        self.calls = []

    def get_resolve_data(self, sub, trust_anchor, entity_type=None):
        self.calls.append(
            {
                "sub": sub,
                "trust_anchor": trust_anchor,
                "entity_type": entity_type,
            }
        )
        raise self.exc


def _entity_configuration_jwt(entity):
    endpoint = entity["federation_entity"].server.get_endpoint("entity_configuration")
    return endpoint.process_request({})["response"]


def _subordinate_statement_jwt(issuer, subject):
    endpoint = issuer.server.get_endpoint("fetch")
    request = endpoint.parse_request({"iss": issuer.entity_id, "sub": subject})
    return endpoint.process_request(request)["response_msg"]


class TestBackendResolve:
    @pytest.fixture(autouse=True)
    def setup(self):
        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.im = federation[IM_ID]
        self.rp = federation[RP_ID]

    def _resolver_query(self):
        return {"sub": self.rp.entity_id, "trust_anchor": self.ta.entity_id}

    def _set_backend(self, loader):
        backend = Neo4jFederationBackend(resolve_data_loader=loader)
        self.ta.context.federation_backend = backend
        return self.ta.server.endpoint["resolve"]

    def test_resolve_uses_configured_backend(self):
        leaf_entity_configuration = _entity_configuration_jwt(self.rp)
        intermediate_statement = _subordinate_statement_jwt(self.im, self.rp.entity_id)
        trust_anchor_statement = _subordinate_statement_jwt(self.ta, self.im.entity_id)
        backend_subject = f"{self.rp.entity_id}#backend-subject"

        exp = min(
            factory(token).jwt.payload()["exp"]
            for token in [
                leaf_entity_configuration,
                intermediate_statement,
                trust_anchor_statement,
            ]
        )

        leaf_metadata = factory(leaf_entity_configuration).jwt.payload()["metadata"]
        resolve_data = ResolveData(
            sub=backend_subject,
            trust_anchor=self.ta.entity_id,
            metadata=leaf_metadata,
            trust_chain=[
                leaf_entity_configuration,
                intermediate_statement,
                trust_anchor_statement,
            ],
            exp=exp,
        )

        calls = []
        resolver = self._set_backend(StaticLoader(resolve_data, calls))

        response = resolver.process_request(self._resolver_query())

        assert response
        assert calls == [
            {
                "sub": self.rp.entity_id,
                "trust_anchor": self.ta.entity_id,
                "entity_type": None,
            }
        ]

        jws = factory(response["response_args"])
        assert jws.jwt.headers["typ"] == "resolve-response+jwt"

        payload = jws.jwt.payload()
        assert payload["sub"] == backend_subject
        assert payload["metadata"] == leaf_metadata
        assert payload["trust_chain"] == resolve_data.trust_chain

    def test_resolve_raises_lookup_error_when_backend_returns_none(self):
        calls = []
        resolver = self._set_backend(StaticLoader(None, calls))

        with pytest.raises(LookupError):
            resolver.process_request(self._resolver_query())

        assert calls == [
            {
                "sub": self.rp.entity_id,
                "trust_anchor": self.ta.entity_id,
                "entity_type": None,
            }
        ]

    def test_resolve_propagates_backend_lookup_error(self):
        loader = RaisingLoader(LookupError("missing resolve data"))
        resolver = self._set_backend(loader)

        with pytest.raises(LookupError, match="missing resolve data"):
            resolver.process_request(self._resolver_query())

        assert loader.calls == [
            {
                "sub": self.rp.entity_id,
                "trust_anchor": self.ta.entity_id,
                "entity_type": None,
            }
        ]

    def test_resolve_propagates_backend_runtime_error(self):
        loader = RaisingLoader(RuntimeError("boom"))
        resolver = self._set_backend(loader)

        with pytest.raises(RuntimeError, match="boom"):
            resolver.process_request(self._resolver_query())

        assert loader.calls == [
            {
                "sub": self.rp.entity_id,
                "trust_anchor": self.ta.entity_id,
                "entity_type": None,
            }
        ]
