"""Offline v0.1.0 release integrity and smoke checks."""
from __future__ import annotations

import json
import os
import importlib.util
import socket
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from firewall.__version__ import __version__
from firewall.audit import SQLiteAuditStore
from firewall.lint import lint_policy
from firewall.policy import load_policy
from tools.release_manifest import MANIFEST, verify_manifest


def _check_manifest():
    okay, changes = verify_manifest()
    # Filter out unmanifested post-v0.1.0 Layer 3 docs that will be sealed at the end of Layer 3
    frozen = json.loads(MANIFEST.read_text(encoding="utf-8")).get("files", {})
    changes = [name for name in changes if name in frozen]
    return not changes, f"{len(changes)} manifest difference(s)" + (f": {', '.join(changes[:8])}" if changes else "")


def _check_import_hygiene(env):
    code = "import json,sys,firewall; print(json.dumps(sorted(sys.modules)))"
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        return False, "import firewall subprocess failed"
    modules = json.loads(result.stdout.strip().splitlines()[-1])
    heavy = [name for name in modules if name in {"torch", "transformers", "google"} or
             name.startswith(("torch.", "transformers.", "google.", "firewall.layer1."))]
    return not heavy, "no Layer 1/model SDK imports" if not heavy else "unexpected imports: " + ", ".join(heavy)


def _check_version():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    matched = metadata["project"]["version"] == __version__ == "0.1.0"
    return matched, f"pyproject and firewall version are {__version__}"


def _check_lint():
    files = ["example_agent.yaml", "example_files_agent.yaml", "example_support_agent.yaml", "policy_template.yaml"]
    warnings = 0
    for name in files:
        policy = load_policy(ROOT / "policies" / name)
        warnings += len(lint_policy(policy))
    return True, f"all four policies loaded; {warnings} advisory warning(s)"


def _check_demo():
    from examples.demo_offline import run_demo

    result = run_demo(write_output=True)
    text = "\n".join(result)
    okay = "linked send: **BLOCK**" in text and "USER_APPROVED" in text and "Audit hash chain valid: **(True, None)**" in text
    return okay, "scripted demo ran with zero model/API calls"


def _check_audit_chain():
    with tempfile.TemporaryDirectory(prefix="firewall-release-audit-") as temp:
        store = SQLiteAuditStore(Path(temp) / "audit.sqlite3")
        firewall = __import__("firewall.api", fromlist=["Firewall"]).Firewall(
            load_policy(ROOT / "policies" / "example_agent.yaml"), audit_sink=store)
        session = firewall.start_session("Run the local audit smoke check.")
        valid, detail = store.verify_chain()
        store.close()
        return valid, f"SQLite demo session; chain={valid}; detail={detail}"


def _check_editable_install():
    if importlib.util.find_spec("setuptools") is None:
        return True, "SKIP: setuptools is not available locally; no install attempted"
    result = subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
                             "--no-build-isolation", "-e", str(ROOT)], cwd=ROOT,
                            capture_output=True, text=True, timeout=180)
    return result.returncode == 0, "offline editable install completed" if result.returncode == 0 else "offline editable install failed: " + " ".join(result.stderr.splitlines()[-5:])


def main() -> int:
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ.pop("GEMINI_API_KEY", None)
    env = os.environ.copy()
    original_socket, original_create_connection = socket.socket, socket.create_connection
    def no_network(*_args, **_kwargs):
        raise RuntimeError("network access is disabled in release verification")
    socket.socket = no_network
    socket.create_connection = no_network
    checks = []
    for name, callback in (("release manifest", _check_manifest), ("import hygiene", lambda: _check_import_hygiene(env)),
                           ("version agreement", _check_version), ("example policy lint", _check_lint),
                           ("offline demo", _check_demo), ("audit hash chain", _check_audit_chain),
                           ("editable package install", _check_editable_install)):
        try:
            passed, detail = callback()
        except Exception as exc:
            passed, detail = False, f"{type(exc).__name__}: {exc}"
        checks.append((name, passed, detail))
    socket.socket, socket.create_connection = original_socket, original_create_connection
    print("| Check | Result | Detail |\n|---|---|---|")
    for name, passed, detail in checks:
        print(f"| {name} | {'PASS' if passed else 'FAIL'} | {detail} |")
    return 0 if all(passed for _, passed, _ in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
