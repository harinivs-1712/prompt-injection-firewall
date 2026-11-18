"""Call every read-only endpoint on a running firewall_server and print status codes without leaking tokens."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = p.parse_args(argv)

    token = os.environ.get("FIREWALL_VIEWER_TOKEN", "")
    if len(token) < 24:
        print("Error: FIREWALL_VIEWER_TOKEN is missing or too short (< 24 chars).", file=sys.stderr)
        return 1

    headers = {"Authorization": f"Bearer {token}"}
    endpoints = [
        "/health",
        "/api/v1/summary",
        "/api/v1/sessions",
        "/api/v1/audit/verify",
        "/api/v1/review/items",
        "/api/v1/policy",
        "/api/v1/config",
        "/api/v1/eval/results",
    ]

    all_ok = True
    with httpx.Client(timeout=5.0) as client:
        for ep in endpoints:
            req_headers = headers if ep != "/health" else {}
            try:
                res = client.get(args.base_url + ep, headers=req_headers)
                print(f"{ep:35} -> {res.status_code}")
                if res.status_code != 200:
                    all_ok = False
            except Exception as exc:
                print(f"{ep:35} -> ERROR: {type(exc).__name__}")
                all_ok = False

        # If sessions exist, test session detail and events
        try:
            sessions_res = client.get(args.base_url + "/api/v1/sessions", headers=headers)
            if sessions_res.status_code == 200:
                items = sessions_res.json().get("items", [])
                if items:
                    sid = items[0]["session_id"]
                    res_s = client.get(f"{args.base_url}/api/v1/sessions/{sid}", headers=headers)
                    print(f"{'/api/v1/sessions/{id}':35} -> {res_s.status_code}")
                    res_e = client.get(f"{args.base_url}/api/v1/sessions/{sid}/events", headers=headers)
                    print(f"{'/api/v1/sessions/{id}/events':35} -> {res_e.status_code}")
        except Exception:
            pass

        # If review items exist, test review item detail
        try:
            review_res = client.get(args.base_url + "/api/v1/review/items", headers=headers)
            if review_res.status_code == 200:
                items = review_res.json().get("items", [])
                if items:
                    item_id = items[0]["id"]
                    res_r = client.get(f"{args.base_url}/api/v1/review/items/{item_id}", headers=headers)
                    print(f"{'/api/v1/review/items/{id}':35} -> {res_r.status_code}")
        except Exception:
            pass

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
