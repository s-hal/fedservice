from fedservice.entity.context import FederationContext


class DummyUnit:
    keyjar = None


def _upstream_get(item, *args):
    if item == "unit":
        return DummyUnit()
    if item == "attribute" and args[0] == "entity_id":
        return "https://example.org"
    raise KeyError(item)


def test_federation_backend_defaults_to_none():
    context = FederationContext(entity_id="https://example.org", upstream_get=_upstream_get)

    assert context.federation_backend is None


def test_federation_backend_can_be_set_from_constructor():
    backend = object()
    context = FederationContext(
        entity_id="https://example.org",
        upstream_get=_upstream_get,
        federation_backend=backend,
    )

    assert context.federation_backend is backend


def test_federation_backend_can_be_set_from_config():
    backend = object()
    context = FederationContext(
        config={"federation_backend": backend},
        entity_id="https://example.org",
        upstream_get=_upstream_get,
    )

    assert context.federation_backend is backend
