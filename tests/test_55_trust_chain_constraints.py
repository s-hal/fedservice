import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES

from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.appclient import ClientEntity
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TA_ID = "https://ta.example.org"
LEAF_ID = "https://leaf.example.org"
IM_ID = "https://im.example.org"
RP_ID = "https://rp.example.org"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [IM_ID, LEAF_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    IM_ID: {
        "entity_type": "intermediate",
        "trust_anchors": [TA_ID],
        "subordinates": [RP_ID, LEAF_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
        }
    },
    LEAF_ID: {
        "entity_type": "federation_entity",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [IM_ID]
        }
    },
    RP_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [IM_ID],
            "entity_type_config": {
                "preference": {
                    "grant_types": ['authorization_code', 'refresh_token']
                }
            },
            "preference": {
                "organization_name": "The example federation RP operator",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com",
            }
        }
    }
}


@pytest.mark.parametrize("limits, accepted", [
    ([0], True),
    ([0, None], False),
    ([1, None], True),
    ([2, 1, None], True),
    ([None, None, 0], True),
    ([1, None, None], False),
    ([3, 0, None], False),
    ([2, 5, 0], True),
    ([None, None, None], True),
])
@pytest.mark.parametrize("naming_only", [False, True])
def test_signed_path_length(limits, accepted, naming_only):
    ids = [TA_ID] + ["https://ie{}.example.org".format(i)
                     for i in range(len(limits) - 1)] + [LEAF_ID]
    config = {}
    for index, entity_id in enumerate(ids):
        config[entity_id] = {
            "entity_type": "trust_anchor" if index == 0 else "federation_entity",
            "trust_anchors": [TA_ID],
            "kwargs": {"endpoints": ["entity_configuration", "fetch"]},
        }
        if index:
            config[entity_id]["kwargs"]["authority_hints"] = [ids[index - 1]]
        if index < len(ids) - 1:
            config[entity_id]["subordinates"] = [ids[index + 1]]
    federation = build_federation(config)
    for index, limit in enumerate(limits):
        constraints = {}
        if limit is not None:
            constraints["max_path_length"] = limit
        elif naming_only:
            constraints["naming_constraints"] = {
                "permitted": ["https://.example.org"], "excluded": [],
            }
        if constraints:
            federation[ids[index]].server.policy[ids[index + 1]] = {
                "constraints": constraints,
            }
    leaf = federation[LEAF_ID]
    messages = create_trust_chain_messages(
        leaf, *[federation[entity_id] for entity_id in reversed(ids[:-1])]
    )
    with responses.RequestsMock() as rsps:
        for url, token in messages.items():
            rsps.add("GET", url, body=token, status=200,
                     content_type=ENTITY_CONFIGURATION.content_type)
        chains, ec = collect_trust_chains(leaf, LEAF_ID)
    assert len(chains) == 1
    verified = verify_trust_chains(leaf, chains, ec)
    assert len(verified) == (1 if accepted else 0)
    if accepted:
        assert len(verified[0].verified_chain) == len(limits) + 1


class TestConstraints(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #          TA
        #          |
        #          IM
        #          |
        #       +--+--+
        #       |     |
        #      RP   LEAF

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.im = federation[IM_ID]
        self.leaf = federation[LEAF_ID]
        self.rp = federation[RP_ID]

        #########################
        # Policies
        # entity specific
        self.ta.server.policy[IM_ID] = {
            "metadata_policy": {
                "openid_relying_party": {
                    "application_type": {
                        "one_of": ["web", "native"]
                    },
                    "grant_types": {
                        "subset_of": ["authorization_code", "refresh_token"]
                    }
                },
                'federation_entity': {
                    "contacts": {
                        'add': ['ops@ta.example.com']
                    }
                }
            }
        }
        # entity type specific
        self.im.server.policy['openid_relying_party'] = {
            "metadata_policy": {
                "contacts": {
                    "add": ["ops@example.org", "ops@example.com"]
                },
                "grant_types": {
                    "subset_of": ["authorization_code", "refresh_token"]
                }
            },
            'metadata': {
                "application_type": "web",
                "organization_name": "EXAMPLE INC.",
                "logo_uri": "https://www.example.com/images/32x32.png",
            }
        }

    def test_intermediate(self):
        _endpoint = self.ta.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'iss': self.ta.entity_id, 'sub': self.im.entity_id})
        _jws = factory(_endpoint.process_request(_req)["response_msg"])
        _payload = _jws.jwt.payload()
        assert _payload
        assert 'metadata_policy' in _payload

        _msgs = create_trust_chain_messages(self.im, self.ta)

        assert len(_msgs) == 3

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": ENTITY_CONFIGURATION.content_type}, status=200)

            chains, leaf_ec = collect_trust_chains(self.leaf, IM_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.leaf, chains, leaf_ec)
        trust_chains = apply_policies(self.leaf, trust_chains)
        assert len(trust_chains) == 1
        assert 'ops@ta.example.com' in trust_chains[0].metadata['federation_entity']['contacts']

    def test_leaf(self):
        _endpoint = self.im.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'sub': self.leaf.entity_id})
        _jws = factory(_endpoint.process_request(_req)["response_msg"])
        _payload = _jws.jwt.payload()
        assert _payload
        # The intermediate has no specific policy for the leaf and none general for entity types
        assert 'metadata_policy' not in _payload and 'metadata' not in _payload

        _msgs = create_trust_chain_messages(self.leaf, self.im, self.ta)

        assert len(_msgs) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": ENTITY_CONFIGURATION.content_type}, status=200)

            chains, leaf_ec = collect_trust_chains(self.leaf, LEAF_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.leaf, chains, leaf_ec)
        trust_chains = apply_policies(self.leaf, trust_chains)
        assert len(trust_chains) == 1
        assert 'ops@ta.example.com' in trust_chains[0].metadata['federation_entity']['contacts']

    def test_rp(self):
        _endpoint = self.im.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'sub': self.rp.entity_id})
        _jws = factory(_endpoint.process_request(_req)["response_msg"])
        _payload = _jws.jwt.payload()
        assert _payload
        assert 'metadata_policy' in _payload and 'metadata' in _payload

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)

        assert len(_msgs) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": ENTITY_CONFIGURATION.content_type}, status=200)

            chains, rp_ec = collect_trust_chains(self.leaf, RP_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.leaf, chains, rp_ec)
        trust_chains = apply_policies(self.leaf, trust_chains)
        assert len(trust_chains) == 1
        _metadata = trust_chains[0].metadata

        assert 'ops@ta.example.com' in _metadata['federation_entity']['contacts']
        assert set(_metadata['openid_relying_party']['grant_types']) == {'authorization_code', 'refresh_token'}
