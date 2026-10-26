# The intermediates

This directory contains the configuration of the intermediates.
Each intermediate is represented by a configuration file and a 
directory with entity specific files.

Specific to each intermediate are _authority_hints_, _trusted_roots_ and 
_subordinates_ . The log file for the intermediate will also be written here. 

## Registration Policy publication

Use the existing per-subject `metadata_policy=` mapping to configure Fetch
publication. `make_federation_entity()` stores these records in `server.policy`;
`make_federation_combo()` supports the same input. For an already registered
subordinate whose public keys are supplied as `subordinate_jwks`:

```python
from fedservice.utils import make_federation_entity

subject = "https://subordinate.example.org"
intermediate = make_federation_entity(
    "https://intermediate.example.org",
    endpoints=["fetch"],
    subordinate={subject: {"jwks": subordinate_jwks}},
    metadata_policy={subject: {
        "registration_policy": ["urn:example:registration-policy:verified"],
        "constraints": {"registration_policy": [{
            "policy": ["urn:example:registration-policy:approved"],
            "entity_types": ["openid_provider"],
        }]},
    }},
)
```

The top-level claim records procedures the issuer has **already applied** to
that subject. Operators must perform those procedures before configuring the
claim; software does not infer it from a constraint. A constraint governs
lower Subordinate Statements, not the statement carrying the constraint.
Both fields are optional, and an empty outer array is valid. These are the
[Registration Policy 1.0](https://www.oidc.se/specifications/openid-federation-registration-policy-1_0.html)
claim and constraint, not metadata-policy operators.

Fetch gives per-subject policy records precedence over stored subordinate
fields. Its type-based fallback copies only `metadata` and `metadata_policy`,
so configure this extension per subject. No profile toggle is needed.
