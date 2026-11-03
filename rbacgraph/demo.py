"""
Environment helper for the live-cluster workflow.

Kind clusters can stop after a reboot or hit a Windows port clash, and the
remediation workflow deletes bindings by design. This module provides a single
command to return the throwaway test cluster to a known-good state.

Usage:
    python -m rbacgraph.demo status        # check Docker + cluster + RBAC
    python -m rbacgraph.demo reset-rbac    # just re-load the vulnerable RBAC
    python -m rbacgraph.demo reset          # full: recreate cluster if needed, load RBAC

All actions are idempotent and affect only the throwaway 'rbac-test' cluster
and the 'app' namespace.
"""

import os
import shutil
import subprocess
import sys

CLUSTER = "rbac-test"
CONTEXT = "kind-rbac-test"

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_PKG_DIR)
RBAC_FILE = os.path.join(_ROOT, "samples", "vulnerable_rbac.yaml")


def _have(tool):
    return shutil.which(tool) is not None


def _run(cmd, capture=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if capture:
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        return r.returncode, ""
    except FileNotFoundError:
        return 127, f"{cmd[0]} not found"


def _docker_ok():
    code, _ = _run(["docker", "info"], capture=True)
    return code == 0


def _cluster_reachable():
    code, _ = _run(["kubectl", "--context", CONTEXT, "get", "nodes"], capture=True)
    return code == 0


def _cluster_exists():
    code, out = _run(["kind", "get", "clusters"], capture=True)
    return code == 0 and CLUSTER in out.split()


def check_prereqs():
    missing = [t for t in ("docker", "kubectl", "kind") if not _have(t)]
    if missing:
        print("  Missing tools on PATH:", ", ".join(missing))
        print("  Install them, then re-run.")
        return False
    if not _docker_ok():
        print("  Docker Desktop is not running. Start it, wait for the whale")
        print("  icon to go steady, then re-run.")
        return False
    return True


def status():
    print("Demo status")
    print("-" * 40)
    print("docker running :", "yes" if _docker_ok() else "NO - start Docker Desktop")
    print("cluster exists :", "yes" if _cluster_exists() else "no")
    print("cluster ready  :", "yes" if _cluster_reachable() else "no")
    if _cluster_reachable():
        code, out = _run(["kubectl", "--context", CONTEXT, "get",
                          "serviceaccounts", "-n", "app"], capture=True)
        loaded = all(x in out for x in ("frontend", "deployer", "binder"))
        print("RBAC loaded    :", "yes" if loaded else "no - run: reset-rbac")


def reset_rbac():
    if not _cluster_reachable():
        print("  Cluster not reachable. Run a full reset instead:")
        print("      python -m rbacgraph.demo reset")
        return False
    _run(["kubectl", "--context", CONTEXT, "create", "namespace", "app"], capture=True)
    code, out = _run(["kubectl", "--context", CONTEXT, "apply", "-f", RBAC_FILE], capture=True)
    print(out.strip())
    if code == 0:
        print("  RBAC reloaded. The vulnerable setup is back.")
    return code == 0


def reset(full=True):
    if not check_prereqs():
        return False

    if not _cluster_reachable():
        print("  Cluster not reachable - recreating it (this takes ~1 min)...")
        if _cluster_exists():
            _run(["kind", "delete", "cluster", "--name", CLUSTER], capture=True)
        code, out = _run(["kind", "create", "cluster", "--name", CLUSTER], capture=True)
        if code != 0:
            print("  Failed to create cluster:\n", out)
            return False
        print("  Cluster created.")

    return reset_rbac()


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status":
        status()
    elif cmd == "reset-rbac":
        reset_rbac()
    elif cmd == "reset":
        reset()
    else:
        print("Unknown command. Use: status | reset-rbac | reset")


if __name__ == "__main__":
    main()
