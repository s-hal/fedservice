# fedservice
Implementation of the service layer using the new OIDC federation draft.

## Federation signing configuration

Set `entity.signing_alg` when passing an application's entity configuration to
`make_federation_entity(**conf["entity"])`:

```python
conf = {
    "entity": {
        "entity_id": "https://entity.example.org",
        "signing_alg": "ES256",
        "key_config": {
            "key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]
        },
    }
}
```

For an existing Combo component specification, put the same scalar value at
`federation_entity.kwargs.signing_alg`. Builders, direct `FederationEntity`
construction and `make_federation_combo()` also accept `signing_alg`.
The effective value is held in the owning `FederationContext.signing_alg` and
survives context persistence. Omission uses `DEFAULT_SIGNING_ALGORITHM`, which
remains `RS256`; null, empty and unsupported values are configuration errors.

The selected algorithm requires a compatible private signing key at issuance.
There is no algorithm fallback or automatic key generation on signing failure.
Standalone creation helpers use the same default, and trusted local helper
calls can explicitly override `signing_alg`. Protocol requests cannot select
an endpoint's signing algorithm, and conflicting stored producer settings are
reported as errors. This setting is not published as a metadata or JWT claim.
It does not restrict verification: ES256 issuers still accept supported RSA,
EC and EdDSA peer signatures when the appropriate verification keys are supplied.
