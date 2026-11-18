"""Call every read-only and broker endpoint on a running firewall_server and print status codes without leaking tokens."""
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

    viewer_token = os.environ.get("FIREWALL_VIEWER_TOKEN", "")
    reviewer_token = os.environ.get("FIREWALL_REVIEWER_TOKEN", "")
    agent_token = os.environ.get("FIREWALL_AGENT_TOKEN", "")

    if len(viewer_token) < 24:
        print("Error: FIREWALL_VIEWER_TOKEN is missing or too short (< 24 chars).", file=sys.stderr)
        return 1

    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    reviewer_headers = {"Authorization": f"Bearer {reviewer_token}"} if len(reviewer_token) >= 24 else viewer_headers
    agent_headers = {"Authorization": f"Bearer {agent_token}", "Content-Type": "application/json"} if len(agent_token) >= 24 else None

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
            req_headers = viewer_headers if ep != "/health" else {}
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
            sessions_res = client.get(args.base_url + "/api/v1/sessions", headers=viewer_headers)
            if sessions_res.status_code == 200:
                items = sessions_res.json().get("items", [])
                if items:
                    sid = items[0]["session_id"]
                    res_s = client.get(f"{args.base_url}/api/v1/sessions/{sid}", headers=viewer_headers)
                    print(f"{'/api/v1/sessions/{id}':35} -> {res_s.status_code}")
                    res_e = client.get(f"{args.base_url}/api/v1/sessions/{sid}/events", headers=viewer_headers)
                    print(f"{'/api/v1/sessions/{id}/events':35} -> {res_e.status_code}")
        except Exception:
            pass

        # If review items exist, test review item detail and view
        try:
            review_res = client.get(args.base_url + "/api/v1/review/items", headers=viewer_headers)
            if review_res.status_code == 200:
                items = review_res.json().get("items", [])
                if items:
                    item_id = items[0]["id"]
                    res_r = client.get(f"{args.base_url}/api/v1/review/items/{item_id}", headers=viewer_headers)
                    print(f"{'/api/v1/review/items/{id}':35} -> {res_r.status_code}")
                    res_v = client.get(f"{args.base_url}/api/v1/review/items/{item_id}/view", headers=viewer_headers)
                    print(f"{'/api/v1/review/items/{id}/view':35} -> {res_v.status_code}")
        except Exception:
            pass

        # Test broker and approvals if agent and reviewer tokens are available
        if agent_headers and len(reviewer_token) >= 24:
            try:
                # 1. Create approval request
                req_payload = {
                    "session_id": "smoke-test-session",
                    "tool": "send_email",
                    "reason_codes": ["ASK_TEST"],
                    "explanation": "Smoke test approval request",
                    "values_preview": {"recipient": "user@example.com"},
                    "ttl_seconds": 60.0,
                }
                res_create = client.post(f"{args.base_url}/api/v1/broker/requests", headers=agent_headers, json=req_payload)
                print(f"{'POST /api/v1/broker/requests':35} -> {res_create.status_code}")
                if res_create.status_code == 200:
                    data = res_create.json()
                    req_id = data["request_id"]

                    # 2. Agent poll decision
                    res_poll = client.get(f"{args.base_url}/api/v1/broker/requests/{req_id}/decision?wait_seconds=0", headers={"Authorization": agent_headers["Authorization"]})
                    print(f"{'GET /api/v1/broker/.../decision':35} -> {res_poll.status_code}")

                    # 3. Reviewer list approvals
                    res_list = client.get(f"{args.base_url}/api/v1/approvals", headers=reviewer_headers)
                    print(f"{'GET /api/v1/approvals':35} -> {res_list.status_code}")

                    # 4. Reviewer get detail and request_hash
                    res_detail = client.get(f"{args.base_url}/api/v1/approvals/{req_id}", headers=reviewer_headers)
                    print(f"{'GET /api/v1/approvals/{id}':35} -> {res_detail.status_code}")
                    req_hash = res_detail.json().get("request_hash", "")

                    # 5. Reviewer decision (approve)
                    res_decide = client.post(
                        f"{args.base_url}/api/v1/approvals/{req_id}/decision",
                        headers={"Authorization": f"Bearer {reviewer_token}", "Content-Type": "application/json"},
                        json={"decision": "approve", "request_hash": req_hash, "confirm": True},
                    )
                    print(f"{'POST /api/v1/approvals/{id}/decision':35} -> {res_decide.status_code}")

                    # 6. Approvals stats
                    res_stats = client.get(f"{args.base_url}/api/v1/approvals/stats", headers=reviewer_headers)
                    print(f"{'GET /api/v1/approvals/stats':35} -> {res_stats.status_code}")

            except Exception as exc:
                print(f"{'Broker / Approvals flow':35} -> ERROR: {type(exc).__name__}")
                all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
