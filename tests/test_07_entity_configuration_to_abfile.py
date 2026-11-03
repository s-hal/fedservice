"""Real CLI record generation, replacement and Fetch lifetime inheritance."""

import json
from pathlib import Path
import subprocess
import sys

from idpyoidc.storage.abfile import AbstractFileSystem
import pytest

from tests.test_41_entity_statement_lifetimes import SUBJECT
from tests.test_41_entity_statement_lifetimes import clock
from tests.test_41_entity_statement_lifetimes import construct
from tests.test_41_entity_statement_lifetimes import issued_ss


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "script/entity_configuration_to_abfile.py"


@pytest.fixture
def source_ec():
    return {"sub": SUBJECT, "jwks": {"keys": []}, "iat": 100, "exp": 999999,
            "lifetime": 123, "metadata": {"federation_entity": {
                "federation_list_endpoint": SUBJECT + "/list"}, "openid_provider": {}}}


def run_cli(tmp_path, source_ec, args, stdin=False, target=None):
    """Run the actual script in the current interpreter, with isolated inputs."""
    source = tmp_path / "entity-configuration.json"
    source.write_text(json.dumps(source_ec), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), "-s", "-" if stdin else str(source),
         "-t", str(target or tmp_path / "records")] + args,
        input=json.dumps(source_ec) if stdin else None, text=True, capture_output=True,
        cwd=str(ROOT), check=False,
    )


def open_store(path):
    return AbstractFileSystem(str(path), key_conv="idpyoidc.util.Base64",
                              value_conv="idpyoidc.util.JSON")


@pytest.mark.parametrize("stdin", [False, True])
@pytest.mark.parametrize("lifetime", [None, 1, 604800])
@pytest.mark.parametrize("intermediate", [False, True])
def test_generated_record_preserves_fields_and_only_explicit_lifetime(
        tmp_path, source_ec, stdin, lifetime, intermediate):
    if not intermediate:
        source_ec["metadata"]["federation_entity"].clear()
    args = ["-u"] + ([] if lifetime is None else ["--lifetime", str(lifetime)])
    result = run_cli(tmp_path, source_ec, args, stdin=stdin)
    assert result.returncode == 0, result.stderr
    assert "1 entry written" in result.stdout
    store = open_store(tmp_path / "records")
    expected = {"jwks": source_ec["jwks"], "entity_types": list(source_ec["metadata"])}
    if intermediate:
        expected["intermediate"] = True
    if lifetime is not None:
        expected["lifetime"] = lifetime
    assert store[SUBJECT] == expected
    encoded = store.key_conv.serialize(SUBJECT)
    assert json.loads((tmp_path / "records" / encoded).read_text()) == expected
    assert json.loads((tmp_path / "entity-configuration.json").read_text()) == source_ec


def test_regeneration_replaces_override_and_changes_real_fetch_issuance(tmp_path, source_ec, clock):
    entity = construct(lifetime=3600, endpoint_name="fetch")
    for lifetime, expected in ((604800, 604800), (None, 3600), (7200, 7200)):
        args = ["-u"] + ([] if lifetime is None else ["--lifetime", str(lifetime)])
        result = run_cli(tmp_path, source_ec, args)
        assert result.returncode == 0, result.stderr
        entity.server.subordinate = open_store(tmp_path / "records")
        record = entity.server.subordinate[SUBJECT]
        if lifetime is None:
            assert "lifetime" not in record
        else:
            assert type(record["lifetime"]) is int and record["lifetime"] == lifetime
        claims = issued_ss(entity)
        assert claims["exp"] - claims["iat"] == expected
        assert entity.server.subordinate[SUBJECT] == record


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("args", [
    ["-u", "--lifetime", "0"], ["-u", "--lifetime", "-1"],
    ["-u", "--lifetime", "1.5"], ["-u", "--lifetime", "1e3"],
    ["-u", "--lifetime", "true"], ["-u", "--lifetime", "false"],
    ["-u", "--lifetime", "null"], ["-u", "--lifetime", "none"],
    ["-u", "--lifetime", "invalid"], ["-u", "--lifetime", ""],
    ["-r", "--lifetime", "604800"], ["-r", "-u", "--lifetime", "604800"],
    ["--lifetime", "604800"], ["-r", "-u"], [],
])
def test_invalid_options_do_not_mutate_target(tmp_path, source_ec, existing, args):
    target = tmp_path / "records"
    if existing:
        store = open_store(target)
        store[SUBJECT] = {"jwks": source_ec["jwks"], "lifetime": 7200}
    before = {path.name: path.read_bytes() for path in target.iterdir()} if existing else {}
    result = run_cli(tmp_path, source_ec, args)
    assert result.returncode == 2
    assert "error:" in result.stderr and "Traceback" not in result.stderr
    if existing:
        assert {path.name: path.read_bytes() for path in target.iterdir()} == before
    else:
        assert not target.exists()


@pytest.mark.parametrize("stdin", [False, True])
def test_trust_anchor_info_shape_is_unchanged(tmp_path, source_ec, stdin):
    result = run_cli(tmp_path, source_ec, ["-r"], stdin=stdin)
    assert result.returncode == 0, result.stderr
    assert open_store(tmp_path / "records")[SUBJECT] == source_ec["jwks"]


def test_help_describes_positive_subordinate_override_and_inheritance():
    result = subprocess.run([sys.executable, str(SCRIPT), "--help"], text=True,
                            capture_output=True, cwd=str(ROOT), check=False)
    assert result.returncode == 0
    help_text = " ".join(result.stdout.lower().split())
    assert "positive integer seconds" in help_text
    assert "subordinate mode (-u) only" in help_text
    assert "omit to inherit" in help_text
