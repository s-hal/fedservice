from urllib.parse import unquote_plus

from cryptojwt import KeyJar

from fedservice.build_entity import _SIGNING_ALG_UNSET
from fedservice.build_entity import resolve_signing_alg
from fedservice.entity_statement.create import create_entity_configuration
from fedservice.entity_statement.create import create_subordinate_statement


class FetchEntityStatement:
    """Standalone statement publisher with one construction-time signing setting."""

    def __init__(self, iss, entity_id_pattern, *, signing_alg=_SIGNING_ALG_UNSET):
        self.signing_alg = resolve_signing_alg(signing_alg)
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
        """Publish with the instance algorithm while preserving gathered source data."""
        if "signing_alg" in kwargs:
            raise TypeError("create_entity_statement() does not accept signing_alg")
        _info = self.gather_info(sub).copy()
        _info.update(kwargs)
        stored_alg = _info.pop("signing_alg", self.signing_alg)
        if stored_alg != self.signing_alg:
            raise ValueError("Stored signing_alg {!r} conflicts with the publisher setting".format(stored_alg))
        _info['jwks'] = self.keyjar.export_jwks(issuer_id=self.make_entity_id(sub))
        issuer = self.make_entity_id(self.iss)
        if sub.startswith("https"):
            subject = unquote_plus(sub)
        else:
            subject = self.make_entity_id(sub)

        if subject == issuer:
            return create_entity_configuration(issuer, self.keyjar, signing_alg=self.signing_alg, **_info)

        # Apply the Fetch publication contract after assembling file data and overrides.
        for claim in ("authority_hints", "trust_anchor_hints", "trust_marks",
                      "trust_mark_issuers", "trust_mark_owners"):
            _info.pop(claim, None)
        return create_subordinate_statement(issuer, subject, self.keyjar, signing_alg=self.signing_alg, **_info)
