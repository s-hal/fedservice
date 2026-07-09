"""Tests for Federation JWT payload-only message schemas."""

from pathlib import Path

import pytest

from idpyoidc.message.oidc import JsonWebToken

from fedservice.exception import UnknownCriticalExtension
from fedservice.exception import WrongSubject
from fedservice.message import EntityConfiguration
from fedservice.message import EntityStatement
from fedservice.message import ResolveResponse
from fedservice.message import SubordinateStatement
from fedservice.message import TrustMark
from fedservice.message import TrustMarkStatusResponse


def trust_mark_status_response_payload(status="active"):
    return {
        "iss": "https://issuer.example.org",
        "iat": 1700000000,
        "trust_mark": (
            "eyJhbGciOiJSUzI1NiJ9."
            "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLm9yZyJ9.signature"
        ),
        "status": status,
    }


def test_trust_mark_status_response_minimal_payload_verifies():
    message = TrustMarkStatusResponse(**trust_mark_status_response_payload())

    assert message.verify() is True


@pytest.mark.parametrize("status", ["active", "expired", "revoked", "invalid"])
def test_trust_mark_status_response_accepts_builtin_status_values(status):
    message = TrustMarkStatusResponse(**trust_mark_status_response_payload(status=status))

    assert message.verify() is True


def test_trust_mark_status_response_accepts_configured_extra_status_value():
    message = TrustMarkStatusResponse(
        **trust_mark_status_response_payload(status="pending")
    )

    assert message.verify(allowed_extra_status_values={"pending"}) is True


def test_trust_mark_status_response_rejects_unknown_status_value():
    message = TrustMarkStatusResponse(
        **trust_mark_status_response_payload(status="pending")
    )

    with pytest.raises(
        ValueError, match="Unknown Trust Mark Status Response status value"
    ):
        message.verify()


@pytest.mark.parametrize("claim", ["iss", "iat", "trust_mark", "status"])
def test_trust_mark_status_response_requires_core_claims(claim):
    payload = trust_mark_status_response_payload()
    payload.pop(claim)
    message = TrustMarkStatusResponse(**payload)

    with pytest.raises(Exception):
        message.verify()


def test_trust_mark_status_response_does_not_define_jwt_container_methods():
    assert "from_jwt" not in TrustMarkStatusResponse.__dict__
    assert "to_jwt" not in TrustMarkStatusResponse.__dict__


def resolve_response_payload(**overrides):
    payload = {
        "iss": "https://resolver.example.org",
        "sub": "https://subject.example.org",
        "iat": 1700000000,
        "exp": 1700000600,
        "metadata": {"federation_entity": {"contacts": ["ops@example.org"]}},
        "trust_chain": [
            "eyJhbGciOiJSUzI1NiJ9."
            "eyJpc3MiOiJodHRwczovL3N1YmplY3QuZXhhbXBsZS5vcmcifQ.signature"
        ],
    }
    payload.update(overrides)
    return payload


def test_resolve_response_minimal_payload_verifies():
    message = ResolveResponse(**resolve_response_payload())

    assert message.verify() is True


@pytest.mark.parametrize(
    "claim", ["iss", "sub", "iat", "exp", "metadata", "trust_chain"]
)
def test_resolve_response_requires_core_claims(claim):
    payload = resolve_response_payload()
    payload.pop(claim)
    message = ResolveResponse(**payload)

    with pytest.raises(Exception):
        message.verify()


def test_resolve_response_allows_absent_trust_marks():
    payload = resolve_response_payload()
    payload.pop("trust_marks", None)
    message = ResolveResponse(**payload)

    assert message.verify() is True


def test_resolve_response_allows_aud():
    message = ResolveResponse(**resolve_response_payload(aud="https://rp.example.org"))

    assert message.verify() is True


def test_resolve_response_does_not_define_jwt_container_methods():
    assert "from_jwt" not in ResolveResponse.__dict__
    assert "to_jwt" not in ResolveResponse.__dict__


def test_resolve_response_is_not_json_web_token_subclass():
    assert not issubclass(ResolveResponse, JsonWebToken)


def entity_statement_payload(**overrides):
    payload = {
        "iss": "https://issuer.example.org",
        "sub": "https://subject.example.org",
        "iat": 1700000000,
        "exp": 1700000600,
    }
    payload.update(overrides)
    return payload


def trust_mark_payload(**overrides):
    payload = {
        "sub": "https://subject.example.org",
        "iss": "https://trust-mark-issuer.example.org",
        "iat": 1700000000,
        "trust_mark_type": "https://trust.example.org/marks/member",
    }
    payload.update(overrides)
    return payload


def test_entity_statement_minimal_payload_verifies():
    message = EntityStatement(**entity_statement_payload())

    assert message.verify() is None


@pytest.mark.parametrize("claim", ["iss", "sub", "iat", "exp"])
def test_entity_statement_requires_core_claims(claim):
    payload = entity_statement_payload()
    payload.pop(claim)
    message = EntityStatement(**payload)

    with pytest.raises(Exception):
        message.verify()


def test_entity_statement_optional_payload_schema_fields_may_be_present():
    message = EntityStatement(
        **entity_statement_payload(
            jwks={"keys": []},
            metadata={"federation_entity": {"contacts": ["ops@example.org"]}},
            crit=["custom_extension"],
            custom_extension="value",
        )
    )

    assert message.verify(known_extensions=["custom_extension"]) is None


def test_entity_statement_crit_still_enforces_unknown_critical_extensions():
    message = EntityStatement(
        **entity_statement_payload(crit=["custom_extension"], custom_extension="value")
    )

    with pytest.raises(UnknownCriticalExtension):
        message.verify()


def test_entity_statement_crit_allows_known_critical_extensions():
    message = EntityStatement(
        **entity_statement_payload(crit=["custom_extension"], custom_extension="value")
    )

    assert message.verify(known_extensions=["custom_extension"]) is None


def test_trust_mark_minimal_payload_verifies():
    message = TrustMark(**trust_mark_payload())

    assert message.verify() is True


@pytest.mark.parametrize("claim", ["sub", "iss", "iat", "trust_mark_type"])
def test_trust_mark_requires_core_claims(claim):
    payload = trust_mark_payload()
    payload.pop(claim)
    message = TrustMark(**payload)

    with pytest.raises(Exception):
        message.verify()


def test_trust_mark_optional_payload_fields_may_be_absent():
    message = TrustMark(**trust_mark_payload())

    assert message.verify() is True


def test_trust_mark_optional_payload_fields_may_be_present():
    message = TrustMark(
        **trust_mark_payload(
            logo_uri="https://trust.example.org/logo.svg",
            exp=1700000600,
            ref="https://trust.example.org/marks/member",
        )
    )

    assert message.verify() is True


def test_trust_mark_verify_accepts_matching_entity_id():
    message = TrustMark(**trust_mark_payload())

    assert message.verify(entity_id="https://subject.example.org") is True


def test_trust_mark_verify_rejects_different_entity_id():
    message = TrustMark(**trust_mark_payload())

    with pytest.raises(WrongSubject):
        message.verify(entity_id="https://different.example.org")


@pytest.mark.parametrize(
    "message_cls",
    [EntityStatement, EntityConfiguration, SubordinateStatement, TrustMark],
)
def test_remaining_payload_schemas_are_not_json_web_token_subclasses(message_cls):
    assert not issubclass(message_cls, JsonWebToken)


@pytest.mark.parametrize(
    "message_cls",
    [EntityStatement, EntityConfiguration, SubordinateStatement, TrustMark],
)
def test_remaining_payload_schemas_do_not_define_jwt_container_methods(message_cls):
    assert "from_jwt" not in message_cls.__dict__
    assert "to_jwt" not in message_cls.__dict__


def test_message_module_no_longer_references_json_web_token():
    import fedservice.message as message_module

    source = Path(message_module.__file__).read_text()

    assert "JsonWebToken" not in source


def message_module_source():
    import fedservice.message as message_module

    return Path(message_module.__file__).read_text()


def test_message_module_no_longer_contains_unavailable_jwt_method_shim():
    source = message_module_source()

    assert "_UnavailableJwtContainerMethod" not in source
    assert "_UNAVAILABLE_JWT_CONTAINER_METHOD" not in source


def test_message_module_no_longer_contains_payload_from_jws_helper():
    source = message_module_source()

    assert "_payload_from_jws" not in source


def test_message_module_no_longer_imports_cryptojwt_jws_factory():
    source = message_module_source()

    assert "cryptojwt.jws.jws" not in source
    assert "factory" not in source


def test_entity_statement_and_trust_mark_do_not_define_jwt_container_methods():
    assert "from_jwt" not in EntityStatement.__dict__
    assert "to_jwt" not in EntityStatement.__dict__
    assert "from_jwt" not in TrustMark.__dict__
    assert "to_jwt" not in TrustMark.__dict__


def test_trust_marks_verify_does_not_parse_compact_jwt_strings():
    from fedservice.message import TrustMarks

    message = TrustMarks(
        **{
            "https://trust.example.org/marks/member": {
                "trust_mark_type": "https://trust.example.org/marks/member",
                "trust_mark": "not-a-compact-jwt",
            }
        }
    )

    assert message.verify() is None


def test_entity_configuration_verify_does_not_parse_compact_trust_mark_strings():
    message = EntityConfiguration(
        **entity_statement_payload(
            trust_marks=[
                {
                    "trust_mark_type": "https://trust.example.org/marks/member",
                    "trust_mark": "not-a-compact-jwt",
                }
            ]
        )
    )

    assert message.verify() is None


def test_trust_mark_verify_does_not_parse_compact_delegation_strings():
    message = TrustMark(**trust_mark_payload(delegation="not-a-compact-jwt"))

    assert message.verify() is True


def test_entity_configuration_preserves_dictionary_trust_mark_consistency_check():
    message = EntityConfiguration(
        **entity_statement_payload(
            trust_marks=[
                {
                    "trust_mark_type": "https://trust.example.org/marks/member",
                    "trust_mark": trust_mark_payload(
                        trust_mark_type="https://trust.example.org/marks/other"
                    ),
                }
            ]
        )
    )

    with pytest.raises(ValueError, match="trust_mark_is values does not match"):
        message.verify()
