#!/usr/bin/env python3
import argparse
import json
import sys

from idpyoidc.storage.abfile import AbstractFileSystem


def positive_seconds(value):
    """Parse a CLI issuance duration without accepting zero or non-integer text."""
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("lifetime must be positive integer seconds")
    if seconds <= 0:
        raise argparse.ArgumentTypeError("lifetime must be positive integer seconds")
    return seconds


def parse_args():
    parser = argparse.ArgumentParser(description="Load Entity Configuration into an AbstractFileSystem store.")
    parser.add_argument("-s", "--source", required=True, help="Path to JSON file or '-' for stdin")
    parser.add_argument("-t", "--target", required=True, help="AbstractFilesystem target directory")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-r", "--trust_anchor_info", action="store_true", help="Store Trust Anchor")
    mode.add_argument("-u", "--subordinate_info", action="store_true", help="Store Subordinate info")
    parser.add_argument("--lifetime", type=positive_seconds, metavar="SECONDS",
                        help="Positive integer seconds; subordinate mode (-u) only. "
                             "Omit to inherit the issuer's node/default SS lifetime.")

    args = parser.parse_args()
    if args.lifetime is not None and not args.subordinate_info:
        parser.error("--lifetime is only valid in subordinate mode (-u)")
    return args


def read_json(source: str):
    if source == "-":
        return json.load(sys.stdin)
    with open(source, "r", encoding="utf-8") as fp:
        return json.load(fp)


def main():
    args = parse_args()

    entity_configuration = read_json(args.source)

    info = None
    if args.trust_anchor_info:
        info = {entity_configuration["sub"]: entity_configuration["jwks"]}
    else:
        _md = entity_configuration.get("metadata", {})
        _sub_info = {
            "entity_types": list(_md.keys()),
            "jwks": entity_configuration["jwks"],
        }

        # Publishing the list endpoint makes this an intermediate
        _fe_md = _md.get("federation_entity", {})
        if isinstance(_fe_md, dict) and "federation_list_endpoint" in _fe_md:
            _sub_info["intermediate"] = True
        if args.lifetime is not None:
            _sub_info["lifetime"] = args.lifetime

        info = {entity_configuration["sub"]: _sub_info}

    store = AbstractFileSystem(
        fdir=args.target,
        key_conv="idpyoidc.util.Base64",
        value_conv="idpyoidc.util.JSON",
    )

    wrote = 0
    for key, val in info.items():
        store[key] = val
        wrote += 1

    print(f"Done. {wrote} entr{'y' if wrote == 1 else 'ies'} written to {args.target}.")


if __name__ == "__main__":
    main()
