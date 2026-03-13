import pytest
from cryptojwt.jws.jws import factory

from fedservice.backend import Neo4jFederationBackend
from fedservice.backend import ResolveData
from tests.test_57_resolve import FEDERATION_CONFIG
from tests.test_57_resolve import IM_ID
from tests.test_57_resolve import RP_ID
from tests.test_57_resolve import TA_ID
from tests.build_federation import build_federation


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

    def test_resolve_uses_configured_backend(self):
        leaf_entity_configuration = _entity_configuration_jwt(self.rp)
        intermediate_statement = _subordinate_statement_jwt(self.im, self.rp.entity_id)
        trust_anchor_statement = _subordinate_statement_jwt(self.ta, self.im.entity_id)

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
            sub=self.rp.entity_id,
            trust_anchor=self.ta.entity_id,
            metadata=leaf_metadata,
            trust_chain=[
                leaf_entity_configuration,
                intermediate_statement,
                trust_anchor_statement,
            ],
            exp=exp,
        )

        resolver = self.ta.server.endpoint["resolve"]
        calls = []
        backend = Neo4jFederationBackend(
            resolve_data_loader=lambda **kwargs: calls.append(kwargs) or resolve_data
        )
        self.ta.server.context.federation_backend = backend

        response = resolver.process_request(
            {"sub": self.rp.entity_id, "trust_anchor": self.ta.entity_id}
        )

        assert response
        assert calls == [
            {
                "sub": self.rp.entity_id,
                "trust_anchor": self.ta.entity_id,
                "entity_type": None,
            }
        ]

        payload = factory(response["response_args"]).jwt.payload()
        assert payload["sub"] == self.rp.entity_id
        assert payload["metadata"] == leaf_metadata
        assert payload["trust_chain"] == resolve_data.trust_chain
