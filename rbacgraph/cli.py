"""
Command-line entry point that runs the full pipeline.

Usage:
    # From YAML files:
    python -m rbacgraph.cli analyze samples/vulnerable_rbac.yaml

    # From a live cluster (uses the current kubectl context):
    python -m rbacgraph.cli analyze --live
    python -m rbacgraph.cli analyze --live --context kind-rbac-test

By default a live scan hides Kubernetes' built-in system accounts to keep the
report focused on application workloads. --include-system shows all accounts.
"""

import argparse
import sys
from typing import List

from .extractor import build_cluster
from .graph import build_graph, describe_path, entry_points, find_paths
from .ranking import rank
from .rules import generate_edges

# System namespaces hidden by default on a live scan. These accounts are
# legitimately privileged and would otherwise bury application-level findings.
# This is a display filter only and does not affect analysis.
_SYSTEM_NAMESPACES = ("kube-system", "kube-public", "kube-node-lease")


def _build(args):
    if args.live:
        from .live import build_cluster_live
        return build_cluster_live(context=args.context)
    return build_cluster(args.paths)


def analyse(args):
    cluster = _build(args)
    edges = generate_edges(cluster)
    graph = build_graph(edges)
    entries = entry_points(cluster, graph)
    found = find_paths(graph, entries)
    ranked = rank(found)
    return cluster, graph, ranked


def _is_system_entry(entry: str) -> bool:
    if entry.startswith(("user:system:", "group:system:")):
        return True
    if entry.startswith("sa:"):
        ns = entry[3:].split("/", 1)[0]
        return ns in _SYSTEM_NAMESPACES
    return False


def print_report(cluster, graph, ranked, include_system=False, live=False):
    shown = ranked
    hidden = 0
    if live and not include_system:
        shown = [rp for rp in ranked if not _is_system_entry(rp.path[0])]
        hidden = len(ranked) - len(shown)

    print("=" * 70)
    print("RBAC ATTACK PATH REPORT" + ("  (LIVE CLUSTER)" if live else ""))
    print("=" * 70)
    print(f"Subjects analysed : {len(cluster.subjects())}")
    print(f"Pods analysed     : {len(cluster.pods)}")
    print(f"Attack paths found: {len(shown)}")
    if hidden:
        print(f"(+{hidden} paths from built-in system accounts hidden; "
              f"use --include-system to show)")
    print()

    if not shown:
        print("No attack paths to cluster-admin were found for your workloads.")
        return

    for i, rp in enumerate(shown, 1):
        print(f"[{rp.severity}] Path #{i}  "
              f"risk={rp.risk}  (impact={rp.impact} / effort={rp.effort})")
        hops = len(rp.path) - 1
        print(f"    {rp.path[0]} can reach cluster-admin in {hops} step(s):")
        print("    " + "\n    ".join(describe_path(graph, rp.path)))
        from .advice import generate_fixes
        fx = generate_fixes(cluster, graph, rp.path)
        if fx["steps"] and fx["recommended"] is not None:
            rec = fx["steps"][fx["recommended"]]["recommended"]
            print(f"    FIX (recommended): {rec['approach']}")
            if rec.get("commands"):
                print(f"      {rec['commands'][0]}")
        print()


def main():
    parser = argparse.ArgumentParser(description="RBAC attack path analyser")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="analyse YAML file(s) or a live cluster")
    p.add_argument("paths", nargs="*", help="one or more YAML files")
    p.add_argument("--live", action="store_true",
                   help="read RBAC from the live cluster (current kubectl context)")
    p.add_argument("--context", default=None,
                   help="kubectl context to use with --live (e.g. kind-rbac-test)")
    p.add_argument("--include-system", action="store_true",
                   help="on a live scan, also show built-in system accounts")

    v = sub.add_parser("validate",
                       help="compare before-fix vs after-fix and show what changed")
    v.add_argument("--before", required=True, help="RBAC YAML before the fix")
    v.add_argument("--after", required=True, help="RBAC YAML after the fix")

    args = parser.parse_args()

    if args.command == "analyze":
        if not args.live and not args.paths:
            parser.error("provide YAML file(s) or use --live")
        cluster, graph, ranked = analyse(args)
        print_report(cluster, graph, ranked,
                     include_system=args.include_system, live=args.live)
    elif args.command == "validate":
        from . import service
        before = service.scan_yaml([args.before])["paths"]
        after = service.scan_yaml([args.after])["paths"]
        d = service.compare(before, after)
        s = d["summary"]
        print("=" * 70)
        print("REMEDIATION VALIDATION")
        print("=" * 70)
        print(f"Paths before fix : {s['before']}")
        print(f"Paths after fix  : {s['after']}")
        print(f"Eliminated       : {s['eliminated']}")
        print(f"Still present    : {s['remaining']}")
        print(f"Newly introduced : {s['introduced']}")
        print()
        for label, key in (("ELIMINATED (fixed)", "eliminated"),
                           ("STILL PRESENT", "remaining"),
                           ("NEWLY INTRODUCED", "introduced")):
            if d[key]:
                print(f"-- {label} --")
                for p in d[key]:
                    print(f"   [{p['severity']}] {p['entry']} -> cluster-admin "
                          f"({p['hops']} steps, risk {p['risk']})")
                print()


if __name__ == "__main__":
    sys.exit(main())
