"""Purge expired review-store entries."""
from __future__ import annotations
import argparse
from firewall_server.review_store import ReviewStore

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--review-db", required=True); args=p.parse_args(argv)
    print(f"Purged {ReviewStore(args.review_db).purge_expired()} expired review item(s).")
    return 0
if __name__ == "__main__": raise SystemExit(main())
