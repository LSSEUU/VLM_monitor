"""Generate or verify committed JSON Schema snapshots."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from labcourt.schema_export import export_schemas  # noqa: E402
from labcourt.schema_registry import SCHEMA_MODELS  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "schemas")
    args = parser.parse_args()
    errors = export_schemas(args.output.resolve(), check=args.check)
    if errors:
        for error in errors:
            print(error)
        return 1
    action = "verified" if args.check else "exported"
    print(f"{action} {len(SCHEMA_MODELS)} schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
