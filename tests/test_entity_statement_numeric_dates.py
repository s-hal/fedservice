"""NumericDate validation before trust-chain expiry calculation."""

import json

from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
import pytest

from fedservice.entity.function import verify_trust_chains
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.utils import make_federation_entity


ANCHOR = "https://anchor.example.org"
SUBJECT = "https://subject.example.org"


@pytest.fixture(scope="module")
def signing_keys():
    return {owner: new_ec_key(crv="P-256", kid=str(index), use="sig")
            for index, owner in enumerate((ANCHOR, SUBJECT))}


@pytest.mark.parametrize("case", ["ss-string-exp", "ec-string-exp", "integer", "fractional", "mixed"])
def test_chain_dates_fail_at_payload_boundary_or_remain_numeric(case, signing_keys):
    now = utc_time_sans_frac()
    public = {owner: {"keys": [key.serialize(private=False)]}
              for owner, key in signing_keys.items()}
    entity = make_federation_entity(
        "https://verifier.example.org",
        key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]},
        trust_anchors={ANCHOR: public[ANCHOR]}, endpoints=["entity_configuration"],
    )
    ss = {"iss": ANCHOR, "sub": SUBJECT, "iat": now - 10, "exp": now + 600,
          "jwks": public[SUBJECT]}
    ec = {"iss": SUBJECT, "sub": SUBJECT, "iat": now - 10, "exp": now + 500,
          "jwks": public[SUBJECT], "authority_hints": [ANCHOR]}
    if case == "ss-string-exp":
        ss["exp"] = str(ss["exp"])
    elif case == "ec-string-exp":
        ec["exp"] = str(ec["exp"])
    elif case in ("fractional", "mixed"):
        ec.update(iat=now - 10.25, exp=now + 500.75)
        if case == "fractional":
            ss.update(iat=now - 9.5, exp=now + 600.5)
    tokens = []
    for profile, payload in ((SUBORDINATE_STATEMENT, ss), (ENTITY_CONFIGURATION, ec)):
        token = JWS(json.dumps(payload), alg="ES256").sign_compact(
            [signing_keys[payload["iss"]]], protected={"typ": profile.typ},
        )
        decoded = factory(token).jwt.payload()
        assert decoded == payload
        for claim in ("iat", "exp"):
            assert type(decoded[claim]) is type(payload[claim])
        tokens.append(token)
    assert SUBJECT not in entity.keyjar.owners()
    if "string" in case:
        with pytest.raises(FederationJwtPayloadError) as error:
            verify_trust_chains(entity, [tokens])
        assert isinstance(error.value.__cause__, ValueError)
        assert "exp" in str(error.value.__cause__)
    else:
        chains = verify_trust_chains(entity, [tokens])
        assert len(chains) == 1
        assert chains[0].exp == min(ss["exp"], ec["exp"])
        assert chains[0].chain == tokens
        for verified, original in zip(chains[0].verified_chain, (ss, ec)):
            for claim in ("iat", "exp"):
                assert verified[claim] == original[claim]
                assert type(verified[claim]) is type(original[claim])
