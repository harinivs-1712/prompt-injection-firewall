"""Demonstration script for Layer 3 Day 13 approval broker flow."""
from __future__ import annotations

import argparse
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
import uvicorn

from firewall.api import Firewall
from firewall.audit import SQLiteAuditStore
from firewall.session import Session
from firewall_server.app import create_app
from firewall_server.broker_client import BrokerApprovalCallback
from firewall_server.settings import Settings


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def auto_reviewer_worker(base_url: str, reviewer_token: str, stop_event: threading.Event):
    headers = {"Authorization": f"Bearer {reviewer_token}"}
    decided_actions = ["approve", "deny"]
    decision_index = 0

    with httpx.Client(timeout=5.0) as client:
        while not stop_event.is_set() and decision_index < len(decided_actions):
            try:
                res = client.get(f"{base_url}/api/v1/approvals?status=pending", headers=headers)
                if res.status_code == 200:
                    items = res.json().get("items", [])
                    for item in items:
                        req_id = item["id"]
                        detail_res = client.get(f"{base_url}/api/v1/approvals/{req_id}", headers=headers)
                        if detail_res.status_code == 200:
                            req_hash = detail_res.json().get("request_hash")
                            if req_hash:
                                action = decided_actions[decision_index]
                                confirm_val = True if action == "approve" else False
                                client.post(
                                    f"{base_url}/api/v1/approvals/{req_id}/decision",
                                    headers={**headers, "Content-Type": "application/json"},
                                    json={"decision": action, "request_hash": req_hash, "confirm": confirm_val},
                                )
                                decision_index += 1
                                if decision_index >= len(decided_actions):
                                    break
            except Exception:
                pass
            time.sleep(0.2)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manual", action="store_true", help="Manual mode: print curl commands and wait for human input.")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        audit_db = tmp_path / "audit.db"
        review_db = tmp_path / "review.db"
        policy_file = ROOT / "policies" / "example_agent.yaml"

        # Initialize audit and review stores
        store = SQLiteAuditStore(audit_db)
        store.record_session("demo-init", "1", "demo", "task")

        # Tokens
        if args.manual:
            viewer_tok = os.environ.get("FIREWALL_VIEWER_TOKEN") or ("viewer-" + secrets.token_hex(16))
            reviewer_tok = os.environ.get("FIREWALL_REVIEWER_TOKEN") or ("reviewer-" + secrets.token_hex(16))
            agent_tok = os.environ.get("FIREWALL_AGENT_TOKEN") or ("agent-" + secrets.token_hex(16))
        else:
            viewer_tok = "viewer-" + secrets.token_hex(16)
            reviewer_tok = "reviewer-" + secrets.token_hex(16)
            agent_tok = "agent-" + secrets.token_hex(16)

        port = get_free_port()
        base_url = f"http://127.0.0.1:{port}"

        settings = Settings(
            audit_db=audit_db,
            review_db=review_db,
            policy=policy_file,
            viewer_token=viewer_tok,
            reviewer_token=reviewer_tok,
            agent_token=agent_tok,
            enable_broker=True,
            host="127.0.0.1",
            port=port,
            cors_origins=("http://localhost:5173", "http://127.0.0.1:5173"),
            store_text=True,
        )

        app = create_app(settings)
        server_config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(server_config)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()

        # Wait for server readiness
        ready = False
        with httpx.Client(timeout=2.0) as client:
            for _ in range(50):
                try:
                    r = client.get(f"{base_url}/health")
                    if r.status_code == 200:
                        ready = True
                        break
                except Exception:
                    time.sleep(0.1)

        if not ready:
            print("Failed to start review server", file=sys.stderr)
            return 1

        timeout_sec = 60.0 if args.manual else 10.0
        callback = BrokerApprovalCallback(
            base_url=base_url,
            agent_token=agent_tok,
            poll_wait=0.5,
            request_timeout=3.0,
        )

        firewall = Firewall(
            policy=policy_file,
            approval_callback=callback,
            audit_sink=store,
        )

        stop_reviewer = threading.Event()
        if not args.manual:
            rev_thread = threading.Thread(
                target=auto_reviewer_worker,
                args=(base_url, reviewer_tok, stop_reviewer),
                daemon=True,
            )
            rev_thread.start()
        else:
            print(f"Server started at {base_url}")
            print("Use the following curl commands in another terminal:")
            print(f"  curl -H \"Authorization: Bearer <reviewer_token>\" {base_url}/api/v1/approvals")
            print(f"  curl -X POST -H \"Authorization: Bearer <reviewer_token>\" -H \"Content-Type: application/json\" -d '{{\"decision\":\"approve\",\"request_hash\":\"<HASH>\",\"confirm\":true}}' {base_url}/api/v1/approvals/<ID>/decision")
            print()

        session = Session(session_id="session-demo-day13", user_task="Execute payments")
        store.record_session(session.session_id, firewall.policy.policy_version, "example_agent", session.user_task)

        # Scenario 1: Approved call
        tool_1 = "make_payment"
        args_1 = {"account": "ACCT-0001", "amount": "50.00"}
        dec_1 = firewall.authorize_tool_call(session, tool_1, args_1)
        exec_1 = dec_1.action == "ALLOW"
        print(f"tool: {tool_1} | decision: {dec_1.action} | executed: {exec_1}")

        # Scenario 2: Denied call
        tool_2 = "make_payment"
        args_2 = {"account": "ACCT-0002", "amount": "100.00"}
        dec_2 = firewall.authorize_tool_call(session, tool_2, args_2)
        exec_2 = dec_2.action == "ALLOW"
        print(f"tool: {tool_2} | decision: {dec_2.action} | executed: {exec_2}")

        stop_reviewer.set()
        server.should_exit = True
        return 0 if (exec_1 and not exec_2) else 1


if __name__ == "__main__":
    raise SystemExit(main())
