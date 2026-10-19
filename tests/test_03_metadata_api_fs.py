import json
import os
from copy import deepcopy
from pathlib import Path

from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar
import pytest

from fedservice.fetch_entity_statement import FetchEntityStatement
from fedservice.fetch_entity_statement.fs2 import FSFetchEntityStatement
from fedservice.fetch_entity_statement.fs2 import FSPublisher
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


@pytest.fixture
def publication_files(tmp_path):
    issuer = 'owner.example.org'
    subject = 'leaf.example.org'
    keys = init_key_jar(key_defs=[{'type': 'RSA', 'use': ['sig']},
                                {'type': 'EC', 'crv': 'P-256', 'use': ['sig']}],
                        issuer_id='https://' + issuer)
    for sub in (issuer, subject):
        directory = tmp_path / issuer / sub
        directory.mkdir(parents=True)
        (directory / 'jwks.json').write_text(json.dumps(
            keys.export_jwks(private=sub == issuer, issuer_id='https://' + issuer)))
        (directory / 'metadata.json').write_text(json.dumps(
            {'federation_entity': {'organization_name': sub}}))
        (directory / 'authority.json').write_text(json.dumps(['https://anchor.example.org']))
    return issuer, subject, keys


@pytest.mark.parametrize('alg', [None, 'ES256'], ids=['omitted', 'configured'])
def test_publisher_setting_reaches_repeated_ec_ss_publication(tmp_path, publication_files, alg):
    issuer, subject, keys = publication_files
    options = {} if alg is None else {'signing_alg': alg}
    expected = alg or 'RS256'
    fetch = FSFetchEntityStatement(str(tmp_path), iss=issuer, **options)
    publisher = FSPublisher(str(tmp_path), **options)
    assert fetch.signing_alg == publisher.signing_alg == expected
    before = {path: path.read_bytes() for path in tmp_path.rglob('*.json')}
    overrides = {'trust_marks': [], 'trust_mark_issuers': {}, 'trust_mark_owners': {},
                 'trust_anchor_hints': ['https://anchor.example.org'],
                 'metadata': {'federation_entity': {'organization_name': 'Override'}}}
    original = deepcopy(overrides)
    for sub, profile in [(issuer, ENTITY_CONFIGURATION), (subject, SUBORDINATE_STATEMENT),
                         (issuer, ENTITY_CONFIGURATION)]:
        direct = fetch.create_entity_statement(sub, **overrides)
        published = (publisher('GET', 'https://' + issuer + '/.well-known/openid-federation').text
                     if sub == issuer else publisher._create_entity_statement(subject, issuer))
        for token in (direct, published):
            verified = verify_federation_jwt(profile, token, keys)
            assert verified.raw_token() == token
            assert verified.header()['alg'] == expected
            assert verified.header()['typ'] == profile.typ
            assert verified.header()['kid'] in {key.kid for key in keys.get_signing_key(
                issuer_id='https://' + issuer, alg=expected)}
            claims = verified.claims()
            assert claims['iss'] == 'https://' + issuer
            assert claims['sub'] == 'https://' + sub
            assert 'signing_alg' not in claims
            if sub == issuer:
                assert claims['authority_hints'] == ('https://anchor.example.org',)
            else:
                assert {'authority_hints', 'trust_anchor_hints', 'trust_marks',
                        'trust_mark_issuers', 'trust_mark_owners'}.isdisjoint(claims)
        assert verify_federation_jwt(profile, direct, keys).claims()['metadata'] == deep_freeze(overrides['metadata'])
    assert overrides == original
    assert {path: path.read_bytes() for path in tmp_path.rglob('*.json')} == before


@pytest.mark.parametrize('value', [None, '', False, [], 'HS256'])
@pytest.mark.parametrize('kind', ['base', 'filesystem', 'publisher'])
def test_standalone_owner_rejects_invalid_setting(kind, value, tmp_path):
    constructors = {
        'base': lambda: FetchEntityStatement('owner.example.org', 'https://{}', signing_alg=value),
        'filesystem': lambda: FSFetchEntityStatement(str(tmp_path), signing_alg=value),
        'publisher': lambda: FSPublisher(str(tmp_path), signing_alg=value),
    }
    with pytest.raises(ValueError, match='signing_alg'):
        constructors[kind]()


@pytest.mark.parametrize('override', ['ES256', 'RS256', None])
def test_publisher_rejects_per_call_algorithms(tmp_path, publication_files, override):
    issuer, _, _ = publication_files
    fetch = FSFetchEntityStatement(str(tmp_path), iss=issuer, signing_alg='ES256')
    publisher = FSPublisher(str(tmp_path), signing_alg='ES256')
    before = {path: path.read_bytes() for path in tmp_path.rglob('*.json')}
    with pytest.raises(TypeError, match='signing_alg'):
        fetch.create_entity_statement(issuer, signing_alg=override)
    with pytest.raises(TypeError, match='signing_alg'):
        publisher.get('https://' + issuer + '/.well-known/openid-federation', signing_alg=override)
    with pytest.raises(TypeError, match='signing_alg'):
        publisher('GET', 'https://' + issuer + '/.well-known/openid-federation', signing_alg=override)
    assert {path: path.read_bytes() for path in tmp_path.rglob('*.json')} == before


@pytest.mark.parametrize('stored', ['ES256', 'RS256'])
def test_publisher_stored_controls_preserve_source(tmp_path, publication_files, monkeypatch, stored):
    issuer, _, keys = publication_files
    fetch = FSFetchEntityStatement(str(tmp_path), iss=issuer, signing_alg='ES256')
    data = fetch.gather_info(issuer)
    data['signing_alg'] = stored
    before = deepcopy(data)
    monkeypatch.setattr(fetch, 'gather_info', lambda sub: data)
    if stored == 'ES256':
        token = fetch.create_entity_statement(issuer)
        verified = verify_federation_jwt(ENTITY_CONFIGURATION, token, keys)
        assert verified.header()['alg'] == 'ES256'
        assert 'signing_alg' not in verified.claims()
    else:
        with pytest.raises(ValueError, match='signing_alg.*RS256'):
            fetch.create_entity_statement(issuer)
    assert data == before
