from urllib.parse import unquote_plus

from cryptojwt import KeyJar

from fedservice.entity_statement.create import create_entity_configuration
from fedservice.entity_statement.create import create_subordinate_statement


class FetchEntityStatement:

    def __init__(self, iss, entity_id_pattern):
        self.iss = iss
        self.keyjar = KeyJar()
        self.entity_id_pattern = entity_id_pattern
        self.url_prefix = ''
        self.fe_base_path = ""
        self.auth_base_path = ""
        self.conf = None
        self.federation_fetch_endpoint = ""

    def gather_info(self, sub):
        raise NotImplementedError()

    def load_jwks(self, sup, sub, sub_id):
        raise NotImplementedError()

    def make_entity_id(self, netloc):
        return self.entity_id_pattern.format(netloc)

    def create_entity_statement(self, sub, **kwargs):
        _info = self.gather_info(sub)
        _info.update(kwargs)
        _info['jwks'] = self.keyjar.export_jwks(issuer_id=self.make_entity_id(sub))
        issuer = self.make_entity_id(self.iss)
        if sub.startswith("https"):
            subject = unquote_plus(sub)
        else:
            subject = self.make_entity_id(sub)

        if subject == issuer:
            return create_entity_configuration(issuer, self.keyjar, **_info)

        # Apply the Fetch publication contract after assembling file data and overrides.
        for claim in ("authority_hints", "trust_anchor_hints", "trust_marks",
                      "trust_mark_issuers", "trust_mark_owners"):
            _info.pop(claim, None)
        return create_subordinate_statement(issuer, subject, self.keyjar, **_info)
