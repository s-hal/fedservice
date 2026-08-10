"""Import tests for the Federation JWT package skeleton."""

import importlib


def test_federation_jwt_package_modules_import():
    module_names = [
        "fedservice.federation_jwt",
        "fedservice.federation_jwt.errors",
        "fedservice.federation_jwt.profile",
        "fedservice.federation_jwt.registry",
        "fedservice.federation_jwt.jose",
        "fedservice.federation_jwt.verified",
        "fedservice.federation_jwt.trust_context",
        "fedservice.federation_jwt.content_negotiation",
        "fedservice.federation_jwt.claims",
    ]

    for module_name in module_names:
        assert importlib.import_module(module_name)
