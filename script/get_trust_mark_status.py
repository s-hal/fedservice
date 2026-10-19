#!/usr/bin/env python3
import json

import requests

from fedservice.defaults import federation_services
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function.trust_anchor import get_verified_trust_anchor_statement
from fedservice.utils import make_federation_entity

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument("--trust-mark-file", required=True,
                        help="UTF-8 file containing the original compact Trust Mark JWT")
    parser.add_argument('-t', "--trust_anchors")
    parser.add_argument(dest="entity_id")
    args = parser.parse_args()

    with open(args.trust_mark_file, encoding="utf-8") as source:
        trust_mark = source.read().strip()
    if not trust_mark:
        parser.error("--trust-mark-file must contain a compact Trust Mark JWT")

    if not args.entity_id:
        print("Need an entity_id to work with")

    trust_anchors = json.loads(open(args.trust_anchors).read())

    federation_entity = make_federation_entity(entity_id="https://localhost",
                                               services=federation_services("entity_configuration", "trust_mark",
                                                                            "entity_statement", "trust_mark_status"),
                                               trust_anchors=trust_anchors)

    if args.insecure:
        _param = {"verify": False}
        federation_entity.keyjar.httpc_params = _param
        federation_entity.httpc_params = _param
        federation_entity.client.httpc_params = _param

    httpc = getattr(federation_entity, "httpc", None)
    if not httpc:
        httpc = requests

    # Use the authenticated issuer EC, never policy-adjusted or SS metadata.
    if args.entity_id in federation_entity.trust_anchors:
        issuer_ec = get_verified_trust_anchor_statement(federation_entity, args.entity_id)
    else:
        chains = get_verified_trust_chains(federation_entity, args.entity_id)
        chains = [chain for chain in chains if chain.anchor in federation_entity.trust_anchors]
        if not chains:
            raise ValueError("No verified chain to the Trust Mark issuer")
        issuer_ec = chains[0].verified_chain[-1]
    if issuer_ec["iss"] != args.entity_id or issuer_ec["sub"] != args.entity_id:
        raise ValueError("Authenticated Entity Configuration does not match the issuer")
    endpoint = issuer_ec.get("metadata", {}).get("federation_entity", {}).get(
        "federation_trust_mark_status_endpoint")
    if not endpoint:
        raise ValueError("Issuer Entity Configuration has no Trust Mark Status endpoint")

    # federation_entity.client.context.issuer = args.entity_id
    _response = federation_entity.client.do_request("trust_mark_status",
                                                    request_args={"trust_mark": trust_mark},
                                                    entity_id=args.entity_id,
                                                    endpoint=endpoint)
    #result = _service.parse_response(response)
    print(f"Trust mark status: {_response}")
