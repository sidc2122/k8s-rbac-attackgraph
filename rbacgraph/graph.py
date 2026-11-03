"""
Attack graph construction (pipeline stage 3).

Takes the capability edges from the rule engine and builds a directed graph
with NetworkX, then finds every path from a low-privilege entry point to a
high-value target (cluster-admin).
"""

from typing import List

import networkx as nx

from .extractor import Cluster
from .rules import CLUSTER_ADMIN, Edge


def build_graph(edges: List[Edge]) -> nx.DiGraph:
    g = nx.DiGraph()
    for e in edges:
        # If two edges connect the same pair, keep the cheaper one.
        if g.has_edge(e.src, e.dst) and g[e.src][e.dst]["effort"] <= e.effort:
            continue
        g.add_edge(e.src, e.dst, effort=e.effort, technique=e.technique,
                   rule_id=getattr(e, "rule_id", ""))
    return g


def path_edges(graph: nx.DiGraph, path: List[str]):
    """Yield (src, dst, technique, rule_id) for each hop in a path."""
    out = []
    for i in range(len(path) - 1):
        u, v = path[i], path[i + 1]
        d = graph[u][v]
        out.append((u, v, d.get("technique", ""), d.get("rule_id", "")))
    return out


def entry_points(cluster: Cluster, graph: nx.DiGraph) -> List[str]:
    """
    Entry points = ServiceAccounts an attacker could plausibly land on first.
    For a v1 model we treat every SA attached to a pod as a possible entry
    point (an attacker who compromises the workload gets that SA's token).
    """
    entries = set()
    for pod in cluster.pods:
        label = f"sa:{pod.namespace}/{pod.service_account}"
        if label in graph:
            entries.add(label)
    # Fall back to all subjects if no pods were defined.
    if not entries:
        entries = {n for n in graph.nodes if not n.startswith("TARGET:")}
    return sorted(entries)


def find_paths(graph: nx.DiGraph, sources: List[str], target: str = CLUSTER_ADMIN,
               per_source: int = 3, max_len: int = 8, max_total: int = 1000):
    """
    For each source, find up to `per_source` shortest attack paths to target,
    ordered by effort (cheapest first).

    This uses k-shortest-paths (Yen's algorithm) instead of enumerating every
    possible route. On a densely connected cluster the number of *all* routes
    is astronomical, but the few *shortest* routes per entry point are what
    matter for security, and they are cheap to compute. This keeps analysis
    fast and bounded even on very large clusters.

    max_len   - ignore paths longer than this many hops (defensive).
    max_total - overall safety cap on how many paths to collect.
    """
    results = []
    if target not in graph:
        return results

    for src in sources:
        if src not in graph or src == target:
            continue
        if not nx.has_path(graph, src, target):
            continue
        try:
            gen = nx.shortest_simple_paths(graph, src, target, weight="effort")
        except nx.NetworkXNoPath:
            continue

        count = 0
        for path in gen:
            if len(path) - 1 > max_len:
                break  # further paths are only longer
            effort = sum(
                graph[path[i]][path[i + 1]]["effort"]
                for i in range(len(path) - 1)
            )
            results.append((path, effort))
            count += 1
            if count >= per_source:
                break
        if len(results) >= max_total:
            break

    return results


def describe_path(graph: nx.DiGraph, path: List[str]) -> List[str]:
    """Human-readable step list for a path."""
    steps = []
    for i in range(len(path) - 1):
        technique = graph[path[i]][path[i + 1]]["technique"]
        steps.append(f"{path[i]}  ->  {technique}")
    return steps
