"""Score frozen held-out-v2 segments with unchanged v1 rules and PIGuard, offline."""
from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.filter_v2_common import V2_RESULTS, get_segments, load_heldout

OUTPUT = V2_RESULTS / "filter_v2_heldout_scored.json"
META = V2_RESULTS / "filter_v2_heldout_score_metadata.json"


def _deny_network(*args, **kwargs):
    raise RuntimeError("Network access is disabled for the rules-v2 experiment")


def main() -> int:
    # Block Hub/network fallback as well as any accidental external socket call.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    socket.create_connection = _deny_network
    socket.socket.connect = _deny_network

    labels, _ = load_heldout()
    segments = get_segments(labels)
    from layers.instruction_rules import instruction_signals
    from layers.piguard_scorer import PIGuardScorer

    scorer = PIGuardScorer()
    piguard = scorer.score([row["text"] for row in segments])
    if len(piguard) != len(segments):
        raise RuntimeError("PIGuard returned a different number of rows than segments")
    results = []
    for segment, guard in zip(segments, piguard):
        reasons = instruction_signals(segment["text"])
        results.append({
            **segment,
            "is_instruction_like": bool(reasons),
            "instruction_reasons": reasons,
            **guard,
        })
    V2_RESULTS.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    META.write_text(json.dumps({
        "segments": len(results),
        "segmenter": {"window": 3, "stride": 1},
        "rules": "v1 unchanged",
        "piguard_model": "leolee99/PIGuard",
        "piguard_threshold": 0.5,
        "network_calls": 0,
        "heldout_hashes_verified": True,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Scored {len(results)} held-out segments with v1 rules/PIGuard; network calls: 0.")
    print(f"Saved {OUTPUT} and {META}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
