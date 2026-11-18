"""Export ReasonCode enum members to frontend/src/data/reason_codes.generated.json."""

from __future__ import annotations

import json
from pathlib import Path

from firewall.decision import ReasonCode


def main() -> None:
    codes = [rc.value for rc in ReasonCode]
    out_path = Path(__file__).resolve().parent.parent / "frontend" / "src" / "data" / "reason_codes.generated.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sorted(codes), indent=2), encoding="utf-8")
    print(f"Exported {len(codes)} reason codes to {out_path}")


if __name__ == "__main__":
    main()
