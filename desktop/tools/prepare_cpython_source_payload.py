"""Closed conventional-source copier entry; never build or run the candidate."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("_mrk_source_payload", Path(__file__).with_name("prepare_cpython_static_payload.py"))
P = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(P)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stage", "output-inventory", "receipts", "components", "notices", "notice-inventory",
                 "host-inputs", "output", "report"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        result = P.prepare_source(args.stage, args.output_inventory, args.receipts, args.components,
            args.notices, args.notice_inventory, args.host_inputs, args.output, args.report)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        parser.exit(1, "Source CPython copy refused/failed; preserve inputs and partial output. "
                       "No native, supply, installation or legal qualification was performed.\n")


if __name__ == "__main__":
    main()
