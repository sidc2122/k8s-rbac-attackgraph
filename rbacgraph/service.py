"""
Service layer: one clean place that runs the full pipeline and returns plain
dictionaries (JSON-friendly). Both the web app and the CLI can call these, so
the engine is never duplicated.

A scan result looks like:
{
  "subjects": 65,
  "pods": 10,
  "total_found": 2,
  "hidden": 0,
  "paths": [
     {"severity": "HIGH", "risk": 33.33, "impact": 100, "effort": 3,
      "entry": "sa:app/frontend", "target": "TARGET:cluster-admin",
      "hops": 2, "steps": ["sa:app/frontend  ->  Read secrets: ...", ...],
      "nodes": ["sa:app/frontend", "sa:app/binder", "TARGET:cluster-admin"]},
     ...
  ]
}
"""

from typing import List, Optional

from .extractor import build_cluster
from .graph import build_graph, describe_path, entry_points, find_paths
from .ranking import rank
from .rules import generate_edges
from .advice import generate_fixes

_SYSTEM_NAMESPACES = ("kube-system", "kube-public", "kube-node-lease")


def _is_system_entry(entry: str) -> bool:
    if entry.startswith(("user:system:", "group:system:")):
        return True
    if entry.startswith("sa:"):
        ns = entry[3:].split("/", 1)[0]
        return ns in _SYSTEM_NAMESPACES
    return False


def _run(cluster, include_system=True, live=False) -> dict:
    edges = generate_edges(cluster)
    graph = build_graph(edges)
    entries = entry_points(cluster, graph)
    ranked = rank(find_paths(graph, entries))

    paths = []
    for rp in ranked:
        if live and not include_system and _is_system_entry(rp.path[0]):
            continue
        paths.append({
            "severity": rp.severity,
            "risk": rp.risk,
            "impact": rp.impact,
            "effort": rp.effort,
            "entry": rp.path[0],
            "target": rp.path[-1],
            "hops": len(rp.path) - 1,
            "steps": describe_path(graph, rp.path),
            "nodes": rp.path,
            "fixes": generate_fixes(cluster, graph, rp.path),
        })

    result = {
        "subjects": len(cluster.subjects()),
        "pods": len(cluster.pods),
        "total_found": len(ranked),
        "hidden": len(ranked) - len(paths),
        "paths": paths,
    }
    if not cluster.bindings and not cluster.pods:
        result["warning"] = ("No Kubernetes RBAC objects (RoleBindings, "
                             "ClusterRoleBindings or Pods) were found in the input.")
    return result


def scan_yaml(paths: List[str]) -> dict:
    return _run(build_cluster(paths))


def _friendly_cluster_error(exc) -> str:
    msg = str(exc)
    low = msg.lower()
    if "not installed" in low or "no module named 'kubernetes'" in low:
        return ("The Kubernetes client isn't installed. Run:  "
                "python -m pip install kubernetes")
    if any(k in low for k in ("max retries", "refused", "newconnectionerror",
                              "connection", "timed out", "10061")):
        return ("Could not reach the cluster. Docker Desktop may be off or the "
                "cluster may be stopped. Start Docker, then run:  "
                "python -m rbacgraph.demo reset")
    if "not found" in low and "context" in low:
        return ("That cluster/context was not found in your kubeconfig. "
                "Check the dropdown or run:  kubectl config get-contexts")
    if "not exist" in low or "no configuration" in low or "kube_config" in low:
        return ("No kubeconfig found. Create a cluster first, e.g.:  "
                "kind create cluster --name rbac-test")
    return f"Could not scan the cluster: {msg}"


def scan_live(context: Optional[str] = None, include_system: bool = False) -> dict:
    from .live import build_cluster_live
    try:
        cluster = build_cluster_live(context=context)
    except SystemExit as exc:            # kubernetes client missing
        raise RuntimeError(_friendly_cluster_error(exc))
    except Exception as exc:
        raise RuntimeError(_friendly_cluster_error(exc))
    return _run(cluster, include_system=include_system, live=True)


def compare(before: list, after: list) -> dict:
    """Diff two scans' path lists (before-fix vs after-fix). See remediation."""
    from .remediation import diff
    return diff(before, after)


def list_contexts() -> dict:
    """Return the kubectl contexts (clusters) the user can scan."""
    try:
        from kubernetes import config
    except ImportError:
        return {"contexts": [], "active": None,
                "error": "kubernetes client not installed (pip install kubernetes)"}
    try:
        contexts, active = config.list_kube_config_contexts()
        return {
            "contexts": [c["name"] for c in contexts],
            "active": active["name"] if active else None,
        }
    except Exception:
        return {"contexts": [], "active": None,
                "error": "No clusters found. Is Docker running and a cluster started?"}
