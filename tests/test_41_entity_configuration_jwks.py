"""Entity-owned public-file publication without changing online signing keys."""

import builtins
import json
import traceback
from copy import deepcopy
from pathlib import Path

from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory
import pytest

from fedservice.build_entity import FederationEntityBuilder
from fedservice.entity import FederationEntity
from fedservice.entity.context import FederationContext
from fedservice.entity_statement.create import create_entity_configuration
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import TRUST_MARK
from fedservice.utils import build_entity_config
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity


OWNER = "https://owner.example.org"
OPTION = "publish_jwks_from_public_path"
OMITTED = object()
PATHS = ["entity", "direct", "normalized", "combo", "combo_plain"]


@pytest.fixture(scope="module")
def key_material():
    active = new_rsa_key(use="sig", kid="active")
    offline = new_ec_key(crv="P-256", use="sig", kid="offline")
    other = new_rsa_key(use="sig", kid="other")
    public = {"keys": [offline.serialize(), active.serialize()],
              "publication": {"labels": ["offline", "active"]}}
    public["keys"][0]["rollover_note"] = {"stages": ["next"]}
    public["keys"][1].pop("use")
    public["keys"][1]["key_ops"] = ["verify"]
    # Only the active RSA private key is written to runtime files.
    return active.serialize(private=True), public, other.serialize(private=True)


@pytest.fixture
def key_files(tmp_path, key_material):
    private, public, _ = deepcopy(key_material)
    private_path = tmp_path / "private.json"
    public_path = tmp_path / "public.json"
    private_path.write_text(json.dumps({"keys": [private]}))
    public_path.write_text(json.dumps(public))
    return {"private_path": str(private_path), "public_path": str(public_path),
            "read_only": True, "key_defs": [{"type": "RSA", "use": ["sig"]}]}


def construct(key_config, enabled=OMITTED, path="entity", **kwargs):
    options = dict(entity_id=OWNER, key_config=key_config, signing_alg="RS256",
                   endpoints=["entity_configuration"],
                   authority_hints=["https://superior.example.org"],
                   preference={"organization_name": "Public keys owner"})
    options.update(kwargs)
    if path == "direct":
        config = build_entity_config(**options)
        if enabled is not OMITTED:
            config[OPTION] = enabled
        return FederationEntity(**config)
    if enabled is not OMITTED:
        options[OPTION] = enabled
    if path == "normalized":
        return FederationEntity(**build_entity_config(**options))
    if path == "combo":
        return make_federation_combo(**options, entity_type={"application": {}})["federation_entity"]
    if path == "combo_plain":
        return make_federation_combo(**options)
    return make_federation_entity(**options)


def issue(entity, route="endpoint", **kwargs):
    if route == "context":
        return entity.context.create_entity_configuration(OWNER, **kwargs)
    return entity.get_endpoint("entity_configuration").process_request(kwargs)["response"]


def verify_advertised(token):
    # Unverified claims only prepare local key material, never establish acceptance.
    jwks = factory(token).jwt.payload()["jwks"]
    jar = KeyJar()
    jar.add_keys(OWNER, [key_from_jwk_dict(key, private=False) for key in jwks["keys"]])
    verified = verify_federation_jwt(ENTITY_CONFIGURATION, token, jar)
    assert verified.header()["alg"] == "RS256"
    assert verified.header()["kid"] == "active"
    return factory(verified.raw_token()).jwt.payload()


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("route", ["endpoint", "context"])
def test_complete_offline_public_set_is_published(key_files, key_material, path, route):
    entity = construct(key_files, True, path)
    token = issue(entity, route)
    claims = verify_advertised(token)
    assert claims["jwks"] == key_material[1]
    assert OPTION not in claims
    assert OPTION not in entity.get_metadata()["federation_entity"]


@pytest.mark.parametrize("path", PATHS)
def test_normalized_option_preserves_key_initialization(key_files, path, monkeypatch):
    import idpyoidc.node

    before = deepcopy(key_files)
    received = []
    initialize = idpyoidc.node.init_key_jar

    def record(**kwargs):
        received.append(deepcopy(kwargs))
        return initialize(**kwargs)

    monkeypatch.setattr(idpyoidc.node, "init_key_jar", record)
    builder = FederationEntityBuilder(OWNER, key_conf=key_files,
                                      publish_jwks_from_public_path=True)
    assert builder.conf[OPTION] is True
    assert builder.conf["key_conf"] == before
    config = build_entity_config(OWNER, key_config=key_files,
                                 publish_jwks_from_public_path=True)
    assert config[OPTION] is True
    assert OPTION not in config["key_conf"]
    entity = construct(key_files, True, path)
    assert entity.publish_jwks_from_public_path is True
    assert before in received
    assert all(OPTION not in args for args in received)
    assert key_files == before
    verify_advertised(issue(entity))


@pytest.mark.parametrize("path", PATHS + ["builder"])
@pytest.mark.parametrize("value", [None, 0, 1, "true", "false", [], {}])
def test_option_requires_boolean(key_files, path, value):
    with pytest.raises(ValueError, match=OPTION):
        if path == "builder":
            FederationEntityBuilder(OWNER, key_conf=key_files,
                                    publish_jwks_from_public_path=value)
        else:
            construct(key_files, value, path)


@pytest.mark.parametrize("enabled", [OMITTED, False], ids=["omitted", "false"])
@pytest.mark.parametrize("path", PATHS)
def test_disabled_mode_retains_export_and_explicit_arguments(key_files, key_material, enabled, path):
    entity = construct(key_files, enabled, path)
    exported = entity.keyjar.export_jwks()
    assert verify_advertised(issue(entity))["jwks"] == exported
    assert verify_advertised(issue(entity, "context"))["jwks"] == exported
    explicit = deepcopy(key_material[1])
    assert verify_advertised(issue(entity, "context", jwks=explicit))["jwks"] == explicit
    assert verify_advertised(issue(entity, "context", keys=explicit["keys"]))["jwks"] == {
        "keys": explicit["keys"]}
    # Disabled mode retains legacy omission and even non-self-verifying overrides.
    token = issue(entity, "context", include_jwks=False)
    assert "jwks" not in factory(token).jwt.payload()
    assert factory(issue(entity, "context", jwks={"keys": []})).jwt.payload()["jwks"] == {"keys": []}
    assert verify_advertised(issue(entity, "context", jwks=None))["jwks"] == exported


@pytest.mark.parametrize("enabled", [OMITTED, False], ids=["omitted", "false"])
@pytest.mark.parametrize("problem", ["missing", "malformed"])
def test_disabled_mode_does_not_read_public_file(key_files, enabled, problem, monkeypatch):
    path = Path(key_files["public_path"])
    if problem == "missing":
        path.unlink()
    else:
        path.write_text("not json")
    original_open = builtins.open

    def reject_public_read(filename, *args, **kwargs):
        assert str(filename) != str(path), "Disabled publication read public_path"
        return original_open(filename, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", reject_public_read)
    entity = construct(key_files, enabled)
    assert verify_advertised(issue(entity))["jwks"] == entity.keyjar.export_jwks()
    assert verify_advertised(issue(entity, "context"))["jwks"] == entity.keyjar.export_jwks()


@pytest.mark.parametrize("enabled", [True, False, OMITTED], ids=["true", "false", "omitted"])
def test_writable_initialization_still_rewrites_public_file(key_files, key_material, enabled):
    key_files["read_only"] = False
    private_before = Path(key_files["private_path"]).read_bytes()
    entity = construct(key_files, enabled)
    resulting = json.loads(Path(key_files["public_path"]).read_text())
    assert resulting == entity.keyjar.export_jwks()
    assert resulting != key_material[1]
    assert Path(key_files["private_path"]).read_bytes() == private_before
    assert key_files["read_only"] is False
    for route in ("endpoint", "context"):
        assert verify_advertised(issue(entity, route))["jwks"] == resulting


def test_issuance_preserves_keys_files_and_existing_claims(key_files, key_material):
    files_before = {name: Path(key_files[name]).read_bytes()
                    for name in ("private_path", "public_path")}
    entity = construct(key_files, True,
                       init_kwargs={"endpoint": {"entity_configuration": {"lifetime": 7200}}})
    keys_before = {issuer: (entity.keyjar.export_jwks(issuer_id=issuer),
                            entity.keyjar.export_jwks(private=True, issuer_id=issuer))
                   for issuer in entity.keyjar.owners()}
    mark = sign_federation_jwt(TRUST_MARK, {"sub": OWNER, "trust_mark_type": "https://mark.example.org"},
                               entity.keyjar, OWNER, alg="RS256", lifetime=7200)
    marks = [{"trust_mark_type": "https://mark.example.org", "trust_mark": mark}]
    entity.context.trust_marks = marks
    issuers = {"https://mark.example.org": [OWNER]}
    entity.context.trust_mark_issuers = issuers
    owners = {"https://mark.example.org": {"sub": OWNER, "jwks": entity.keyjar.export_jwks()}}
    entity.context.trust_mark_owners = owners
    endpoint = entity.get_endpoint("entity_configuration")
    result = endpoint.process_request({})
    assert ("Content-type", ENTITY_CONFIGURATION.content_type) in endpoint.do_response(**result)["http_headers"]
    metadata = {"federation_entity": {"organization_name": "Context metadata"}}
    context_token = issue(entity, "context", metadata=metadata, lifetime=600,
                          trust_mark_owners=owners)
    for token, lifetime, expected_metadata in (
            (result["response"], 7200, entity.get_metadata()),
            (context_token, 600, metadata)):
        claims = verify_advertised(token)
        assert claims["jwks"] == key_material[1]
        assert claims["exp"] - claims["iat"] == lifetime
        assert claims["metadata"] == expected_metadata
        assert claims["authority_hints"] == ["https://superior.example.org"]
        assert claims["trust_marks"] == marks
        assert claims["trust_mark_issuers"] == issuers
        assert claims["trust_mark_owners"] == owners
    for issuer, before in keys_before.items():
        assert (entity.keyjar.export_jwks(issuer_id=issuer),
                entity.keyjar.export_jwks(private=True, issuer_id=issuer)) == before
        assert {key.kid for key in entity.keyjar.get_signing_key(issuer_id=issuer)} == {"active"}
        assert entity.keyjar.get_signing_key(issuer_id=issuer, alg="ES256") == []
    for name, contents in files_before.items():
        assert Path(key_files[name]).read_bytes() == contents


@pytest.mark.parametrize("problem", ["absent", "empty", "missing", "unreadable", "malformed"])
def test_invalid_public_file_fails_construction(key_files, problem, monkeypatch):
    path = key_files["public_path"]
    if problem == "absent":
        key_files.pop("public_path")
    elif problem == "empty":
        key_files["public_path"] = ""
    elif problem == "missing":
        Path(path).unlink()
    elif problem == "malformed":
        Path(path).write_text("secret-sentinel invalid json")
    else:
        original_open = builtins.open

        def deny(filename, *args, **kwargs):
            if str(filename) == path:
                raise PermissionError("secret-sentinel")
            return original_open(filename, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", deny)
    with pytest.raises(ValueError, match=OPTION) as error:
        construct(key_files, True)
    assert "public_path" in str(error.value)
    assert "secret-sentinel" not in "".join(traceback.format_exception_only(type(error.value), error.value))
    assert error.value.__suppress_context__


@pytest.mark.parametrize("value", [None, [], {}, {"keys": None}, {"keys": {}},
                                   {"keys": []}, {"keys": ["not-a-key"]},
                                   {"keys": [{}]}, {"keys": [{"kty": "unknown"}]}])
def test_invalid_jwks_shapes_fail_construction(key_files, value):
    Path(key_files["public_path"]).write_text(json.dumps(value))
    with pytest.raises(ValueError, match=OPTION):
        construct(key_files, True)


@pytest.mark.parametrize("member,value", [("kid", None), ("kid", 0), ("use", False),
                                          ("alg", None), ("key_ops", "verify"),
                                          ("key_ops", [None]), ("x5c", None)])
def test_malformed_common_jwk_members_fail_at_construction(key_files, key_material, member, value):
    jwks = deepcopy(key_material[1])
    jwks["keys"][0][member] = value
    Path(key_files["public_path"]).write_text(json.dumps(jwks))
    with pytest.raises(ValueError, match=OPTION):
        construct(key_files, True)


def test_non_json_constant_is_not_published(key_files, key_material):
    jwks = deepcopy(key_material[1])
    jwks["publication"]["invalid"] = float("nan")
    Path(key_files["public_path"]).write_text(json.dumps(jwks))
    with pytest.raises(ValueError, match=OPTION):
        construct(key_files, True)


@pytest.mark.parametrize("member", ["k", "d", "p", "q", "dp", "dq", "qi", "di", "oth"])
def test_raw_private_members_rejected_before_conversion(key_files, key_material, member, monkeypatch):
    jwks = deepcopy(key_material[1])
    jwks["keys"][0][member] = "secret-sentinel"
    Path(key_files["public_path"]).write_text(json.dumps(jwks))

    def no_conversion(*args, **kwargs):
        pytest.fail("Private material reached public-key conversion")

    monkeypatch.setattr("fedservice.entity.key_from_jwk_dict", no_conversion)
    with pytest.raises(ValueError, match=OPTION) as error:
        construct(key_files, True)
    assert "secret-sentinel" not in str(error.value)
    assert error.value.__suppress_context__


def test_symmetric_secret_is_rejected(key_files, key_material):
    jwks = deepcopy(key_material[1])
    jwks["keys"].append({"kty": "oct", "k": "secret-sentinel"})
    Path(key_files["public_path"]).write_text(json.dumps(jwks))
    with pytest.raises(ValueError, match=OPTION) as error:
        construct(key_files, True)
    assert "secret-sentinel" not in str(error.value)


@pytest.mark.parametrize("change", ["missing-n", "bad-e", "bad-curve", "bad-point", "bad-encoding"])
def test_malformed_public_material_is_not_repaired(key_files, key_material, change):
    jwks = deepcopy(key_material[1])
    if change == "missing-n":
        jwks["keys"][1].pop("n")
    elif change == "bad-e":
        jwks["keys"][1]["e"] = "AA"
    elif change == "bad-curve":
        jwks["keys"][0]["crv"] = "secret-sentinel"
    elif change == "bad-point":
        jwks["keys"][0]["x"] = "AA"
    else:
        jwks["keys"][1]["n"] += "!"
    Path(key_files["public_path"]).write_text(json.dumps(jwks))
    with pytest.raises(ValueError, match=OPTION) as error:
        construct(key_files, True)
    assert "secret-sentinel" not in str(error.value)


@pytest.mark.parametrize("route", ["endpoint", "context"])
@pytest.mark.parametrize("problem", ["missing", "same-kid-wrong-material", "missing-kid", "wrong-kid"])
def test_actual_signer_must_be_advertised(key_files, key_material, route, problem):
    jwks = deepcopy(key_material[1])
    if problem == "missing":
        jwks["keys"].pop()
    elif problem == "same-kid-wrong-material":
        wrong = key_from_jwk_dict(key_material[2], private=False).serialize()
        wrong["kid"] = "active"
        jwks["keys"][1] = wrong
    elif problem == "missing-kid":
        jwks["keys"][1].pop("kid")
    else:
        jwks["keys"][1]["kid"] = "not-active"
    Path(key_files["public_path"]).write_text(json.dumps(jwks))
    entity = construct(key_files, True)
    before = deepcopy(entity.keyjar.export_jwks(private=True))
    with pytest.raises(ValueError, match=OPTION):
        issue(entity, route)
    assert entity.keyjar.export_jwks(private=True) == before
    assert json.loads(Path(key_files["public_path"]).read_text()) == jwks


@pytest.mark.parametrize("route", ["endpoint", "context"])
def test_publication_cannot_switch_to_an_advertised_alternative_signer(key_files, key_material, route):
    active, _, other = deepcopy(key_material)
    Path(key_files["private_path"]).write_text(json.dumps({"keys": [active, other]}))
    key_files["key_defs"] = []
    public = {"keys": [key_from_jwk_dict(other, private=False).serialize()]}
    Path(key_files["public_path"]).write_text(json.dumps(public))
    legacy = construct(key_files, False)
    assert factory(issue(legacy, route)).jwt.headers["kid"] == "active"
    entity = construct(key_files, True)
    assert {key.kid for key in entity.keyjar.get_signing_key(issuer_id=OWNER)} == {"active", "other"}
    with pytest.raises(ValueError, match=OPTION):
        issue(entity, route)
    # Existing explicit selection still works when that selected key is advertised.
    token = issue(entity, "context", kid="other")
    verified = verify_federation_jwt(ENTITY_CONFIGURATION, token, entity.keyjar)
    assert verified.header()["kid"] == "other"
    assert factory(verified.raw_token()).jwt.payload()["jwks"] == public


@pytest.mark.parametrize("route", ["endpoint", "context"])
def test_signer_changed_after_construction_is_checked_at_issuance(key_files, key_material, route):
    entity = construct(key_files, True)
    verify_advertised(issue(entity, route))
    replacement = KeyJar()
    replacement.add_keys(OWNER, [key_from_jwk_dict(key_material[2])])
    entity.keyjar = replacement
    with pytest.raises(ValueError, match=OPTION):
        issue(entity, route)


@pytest.mark.parametrize("route", ["endpoint", "context"])
@pytest.mark.parametrize("enabled", [False, True])
def test_missing_private_key_retains_signing_failure(key_files, key_material, route, enabled):
    config = build_entity_config(OWNER, key_config=key_files, signing_alg="RS256",
                                 publish_jwks_from_public_path=enabled)
    jar = KeyJar()
    jar.add_keys(OWNER, [key_from_jwk_dict(raw, private=False) for raw in key_material[1]["keys"]])
    entity = FederationEntity(keyjar=jar, **config)
    with pytest.raises(FederationJwtSignatureError):
        issue(entity, route)


@pytest.mark.parametrize("arguments", ["jwks", "keys", "both"])
def test_matching_explicit_arguments_are_copied(key_files, key_material, arguments):
    entity = construct(key_files, True)
    supplied = deepcopy(key_material[1])
    kwargs = {}
    if arguments in ("jwks", "both"):
        kwargs["jwks"] = supplied
    if arguments in ("keys", "both"):
        kwargs["keys"] = supplied["keys"]
    claims = verify_advertised(issue(entity, "context", **kwargs))
    assert claims["jwks"] == key_material[1]
    assert "keys" not in claims
    supplied["keys"].clear()
    claims["jwks"]["keys"].clear()
    exposed = entity.get_entity_configuration_jwks()
    exposed["keys"][0]["rollover_note"]["stages"].clear()
    for route in ("endpoint", "context"):
        assert verify_advertised(issue(entity, route))["jwks"] == key_material[1]


@pytest.mark.parametrize("kwargs", [{"jwks": None}, {"jwks": {}}, {"jwks": {"keys": []}},
                                    {"keys": None}, {"keys": []}, {"include_jwks": False}])
def test_conflicting_context_arguments_fail(key_files, kwargs):
    entity = construct(key_files, True)
    with pytest.raises(ValueError, match=OPTION):
        issue(entity, "context", **kwargs)


@pytest.mark.parametrize("conflict", ["keys", "jwks", "include_jwks"])
def test_matching_argument_does_not_mask_other_conflicts(key_files, key_material, conflict):
    entity = construct(key_files, True)
    kwargs = {"jwks": deepcopy(key_material[1]), "keys": deepcopy(key_material[1]["keys"])}
    kwargs[conflict] = False if conflict == "include_jwks" else None
    with pytest.raises(ValueError, match=OPTION):
        issue(entity, "context", **kwargs)


@pytest.mark.parametrize("enabled", [False, True])
def test_request_parameters_cannot_choose_publication(key_files, key_material, enabled):
    entity = construct(key_files, enabled)
    hostile = {OPTION: not enabled, "jwks": {"keys": []}, "keys": [], "include_jwks": False}
    endpoint = entity.get_endpoint("entity_configuration")
    token = endpoint.process_request(hostile, **hostile)["response"]
    assert verify_advertised(token)["jwks"] == (
        key_material[1] if enabled else entity.keyjar.export_jwks())


def test_snapshot_lifecycle_and_instance_isolation(key_files, key_material, monkeypatch):
    original = construct(key_files, True)
    disabled = construct(key_files, False)
    updated = deepcopy(key_material[1])
    updated["keys"][0]["use"] = "enc"
    updated["publication"]["labels"] = ["changed"]
    Path(key_files["public_path"]).write_text(json.dumps(updated))
    reconstructed = construct(key_files, True)
    key_files["public_path"] = "unused-after-construction.json"

    def no_polling(*args, **kwargs):
        pytest.fail("Issuance reread a startup file")

    monkeypatch.setattr(builtins, "open", no_polling)
    for route in ("endpoint", "context"):
        assert verify_advertised(issue(original, route))["jwks"] == key_material[1]
        assert verify_advertised(issue(reconstructed, route))["jwks"] == updated
        assert verify_advertised(issue(disabled, route))["jwks"] == disabled.keyjar.export_jwks()


def test_relative_public_path_uses_initialization_working_directory(key_files, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    key_files["private_path"] = "private.json"
    key_files["public_path"] = "public.json"
    verify_advertised(issue(construct(key_files, True)))


def test_standalone_creators_remain_independent(key_files, key_material):
    entity = construct(key_files, True)
    explicit = {"keys": [deepcopy(key_material[1]["keys"][1])]}
    context = FederationContext(entity_id=OWNER, signing_alg="RS256")
    tokens = [context.create_entity_configuration(OWNER, key_jar=entity.keyjar, jwks=explicit),
              create_entity_configuration(OWNER, entity.keyjar, jwks=explicit, signing_alg="RS256")]
    for token in tokens:
        assert verify_advertised(token)["jwks"] == explicit
