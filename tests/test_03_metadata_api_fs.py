import os
from copy import deepcopy
from pathlib import Path

from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory

from fedservice.fetch_entity_statement.fs2 import FSFetchEntityStatement
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.message import OIDCRPMetadata

BASE_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "base_data")


def test_config_information():
    fse = FSFetchEntityStatement(BASE_PATH, iss='foodle.uninett.no')
    _jwt = fse.create_entity_statement('foodle.uninett.no')
    _jws = factory(_jwt)
    assert _jws
    payload = _jws.jwt.payload()
    assert payload['iss'] == 'https://foodle.uninett.no'
    assert payload['sub'] == 'https://foodle.uninett.no'

    verified = verify_federation_jwt(ENTITY_CONFIGURATION, _jwt, fse.keyjar)
    assert verified.claims()['authority_hints'] == ('https://ntnu.no',)
    es = verified.message()
    _item = es['metadata']['openid_relying_party']
    assert isinstance(_item, OIDCRPMetadata)
    assert _item['response_types'] == ['code']


def test_make_entity_statement():
    fse = FSFetchEntityStatement(BASE_PATH, iss='ntnu.no')
    _statement = fse.create_entity_statement('foodle.uninett.no')
    _jws = factory(_statement)
    assert _jws
    payload = _jws.jwt.payload()
    assert payload['iss'] == 'https://ntnu.no'
    assert payload['sub'] == 'https://foodle.uninett.no'

    verified = verify_federation_jwt(SUBORDINATE_STATEMENT, _statement, fse.keyjar)
    assert 'authority_hints' not in verified.claims()
    es = verified.message()
    _item = es['metadata_policy']['openid_relying_party']
    assert _item['contacts'] == {"add": ['ops@ntnu.no']}


def test_repeated_filesystem_publication_preserves_ec_and_ss_data():
    directory = Path(BASE_PATH) / 'ntnu.no'
    files = {path: path.read_bytes() for path in directory.rglob('*.json')}
    fse = FSFetchEntityStatement(BASE_PATH, iss='ntnu.no')
    issuer = 'https://ntnu.no'
    subject = 'https://foodle.uninett.no'
    keys = KeyJar()
    keys.import_jwks(fse.keyjar.export_jwks(issuer_id=issuer), issuer)
    overrides = {
        'authority_hints': ['https://override.example.org'],
        'trust_anchor_hints': ['https://anchor.example.org'],
        'trust_marks': [], 'trust_mark_issuers': {}, 'trust_mark_owners': {},
        'metadata': {'openid_relying_party': {'client_name': 'Foodle'}},
    }
    before = deepcopy(overrides)
    ec_data = fse.gather_info('ntnu.no')
    ss_data = fse.gather_info('foodle.uninett.no')
    forbidden = set(overrides) - {'metadata'}
    for _ in range(2):
        for sub, profile in [('ntnu.no', ENTITY_CONFIGURATION),
                             ('foodle.uninett.no', SUBORDINATE_STATEMENT),
                             ('ntnu.no', ENTITY_CONFIGURATION)]:
            kwargs = overrides if profile is SUBORDINATE_STATEMENT else {}
            token = fse.create_entity_statement(sub, **kwargs)
            verified = verify_federation_jwt(profile, token, keys)
            claims = verified.claims()
            assert verified.raw_token() == token
            assert claims['iss'] == issuer
            expected_subject = issuer if profile is ENTITY_CONFIGURATION else subject
            assert claims['sub'] == expected_subject
            assert claims['jwks'] == deep_freeze(
                fse.keyjar.export_jwks(issuer_id=expected_subject))
            assert claims['jwks']['keys']
            if profile is ENTITY_CONFIGURATION:
                assert claims['authority_hints'] == deep_freeze(ec_data['authority_hints'])
                assert claims['metadata'] == deep_freeze(ec_data['metadata'])
            else:
                assert forbidden.isdisjoint(claims)
                assert claims['metadata_policy'] == deep_freeze(ss_data['metadata_policy'])
                assert claims['constraints'] == deep_freeze(ss_data['constraints'])
                assert claims['metadata'] == deep_freeze(overrides['metadata'])
    assert overrides == before
    assert fse.gather_info('ntnu.no') == ec_data
    assert fse.gather_info('foodle.uninett.no') == ss_data
    assert {path: path.read_bytes() for path in directory.rglob('*.json')} == files
