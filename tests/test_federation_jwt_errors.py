"""Tests for Federation JWT exception types."""

import importlib
import sys


def test_federation_jwt_error_inherits_from_value_error():
    errors = importlib.import_module("fedservice.federation_jwt.errors")

    assert issubclass(errors.FederationJwtError, ValueError)


def test_federation_jwt_specific_errors_inherit_from_base_error():
    errors = importlib.import_module("fedservice.federation_jwt.errors")

    specific_errors = [
        errors.FederationJwtHeaderError,
        errors.FederationJwtSignatureError,
        errors.FederationJwtKeyResolutionError,
        errors.FederationJwtPayloadError,
        errors.FederationJwtProfileError,
        errors.FederationJwtContentNegotiationError,
    ]

    for error_cls in specific_errors:
        assert issubclass(error_cls, errors.FederationJwtError)


def test_errors_module_does_not_import_runtime_dependencies():
    forbidden_roots = {
        "cryptojwt",
        "fedservice.endpoint",
        "fedservice.federation_jwt.jose",
        "httpx",
        "requests",
        "urllib3",
    }

    for module_name in [
        "fedservice.federation_jwt.errors",
        *forbidden_roots,
    ]:
        sys.modules.pop(module_name, None)

    importlib.import_module("fedservice.federation_jwt.errors")

    assert forbidden_roots.isdisjoint(sys.modules)
