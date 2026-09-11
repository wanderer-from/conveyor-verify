"""`conveyor-verify` command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from conveyor_verify.verify import parse_ndjson, verify_bundle, verify_log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="conveyor-verify",
        description="Offline verification of Conveyor integrity exports and evidence bundles",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser(
        "log", help="verify an NDJSON log export (envelopes, chain, signatures) and anchor bundles"
    )
    p.add_argument("export", help="NDJSON file (GET /integrity/v1/log or an anchor bundle's log-full.ndjson)")
    p.add_argument(
        "--anchors",
        action="append",
        default=[],
        help="anchor directory (tree_size subdirectories with root.txt)",
    )
    p.add_argument("--keys", help="JSON key chain (GET /integrity/v1/keys) when the export lacks key rows")
    p.add_argument(
        "--offline",
        action="store_true",
        default=True,
        help="never touch the network (default; Rekor lookups arrive with phase B)",
    )
    b = sub.add_parser(
        "bundle", help="verify an evidence bundle zip (GET /integrity/v1/records/{slug}/proof)"
    )
    b.add_argument("zip")
    args = parser.parse_args(argv)
    if args.command == "log":
        extra = json.loads(Path(args.keys).read_text()) if args.keys else None
        report = verify_log(
            parse_ndjson(Path(args.export).read_bytes()), [Path(a) for a in args.anchors], extra
        )
    else:
        report = verify_bundle(Path(args.zip).read_bytes())
    print(report.to_json())
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
