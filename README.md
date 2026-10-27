# fedservice
Implementation of the service layer using the new OIDC federation draft.

## Trust-chain collection limits

The standard `TrustChainCollector` defaults to `max_superiors=10` and
`max_requests=100`. Override either setting through the existing component
configuration; omitted settings keep their library defaults:

```python
from fedservice.utils import make_federation_entity

entity = make_federation_entity(
    "https://resolver.example.org",
    init_kwargs={"function": {
        "trust_chain_collector": {"max_superiors": 4, "max_requests": 40},
    }},
)
```

`max_superiors` is a non-negative integer counting superior hops on each path,
including the Trust Anchor but excluding the starting subject. Zero disables
superior traversal, not retrieval of the subject's own Entity Configuration.
The optional per-call `max_superiors` argument overrides the instance setting
for that collection; omission or `None` uses the instance setting.

`max_requests` is a positive integer limiting collector-initiated HTTP client
calls per collection. The allowance is shared across recursive levels, sibling
candidates, refreshes, Fetch endpoint recovery and tenant-location fallback.
The initial subject EC request, unsuccessful calls and transport exceptions all
count. Supplied ECs and reused valid cache entries do not. Independent collections
receive fresh allowances. Neither setting accepts booleans or coerced values;
invalid configuration raises `ValueError` naming the setting.

The last permitted call finishes normally. If another call would exceed the
allowance, traversal stops while retaining already collected candidates for
normal verification and policy processing. Without an acceptable chain, Resolve
returns its existing `invalid_trust_chain` JSON error with HTTP 400.

These are local library limits, not specification-mandated numbers. They count
invocations of the configured HTTP client, not redirects or retries internal to
that client. They do not bound wall-clock time, response size, CPU, global rates
or raw wire requests, and do not replace signed `max_path_length` constraints.
