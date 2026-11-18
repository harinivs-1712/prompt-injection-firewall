"""Run the local Layer 3 backend."""
from __future__ import annotations

import sys
import uvicorn

from firewall_server.app import create_app
from firewall_server.settings import from_args


def main(argv=None) -> int:
    try: settings = from_args(argv)
    except ValueError as exc:
        print(f"Startup refused: {exc}", file=sys.stderr); return 1
    if settings.allow_remote and settings.host not in {"127.0.0.1","localhost","::1"}:
        print("WARNING: remote binding requires TLS and a reverse proxy.", file=sys.stderr)
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, access_log=False)
    return 0


if __name__ == "__main__": raise SystemExit(main())
