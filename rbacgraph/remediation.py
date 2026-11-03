"""
Remediation validation (pipeline stage 6).

Answers "did my fix actually work?" by comparing the attack paths found
BEFORE a fix against those found AFTER it. Works on the plain path
dictionaries produced by rbacgraph.service, so it applies equally to a live
cluster (scan, patch, re-scan) or two YAML files (before vs after).

Three outcomes:
  eliminated - path existed before, gone after        (the fix worked)
  remaining  - path existed before AND after          (fix didn't remove it)
  introduced - new path that only exists after         (the fix backfired)
"""

from typing import List


def path_signature(path: dict):
    """A stable identity for a path: its exact sequence of nodes."""
    return tuple(path.get("nodes", []))


def diff(before: List[dict], after: List[dict]) -> dict:
    before_by_sig = {path_signature(p): p for p in before}
    after_by_sig = {path_signature(p): p for p in after}

    eliminated = [before_by_sig[s] for s in before_by_sig if s not in after_by_sig]
    remaining = [after_by_sig[s] for s in after_by_sig if s in before_by_sig]
    introduced = [after_by_sig[s] for s in after_by_sig if s not in before_by_sig]

    # Sort each group most-severe first (by risk).
    key = lambda p: p.get("risk", 0)
    eliminated.sort(key=key, reverse=True)
    remaining.sort(key=key, reverse=True)
    introduced.sort(key=key, reverse=True)

    return {
        "eliminated": eliminated,
        "remaining": remaining,
        "introduced": introduced,
        "summary": {
            "before": len(before),
            "after": len(after),
            "eliminated": len(eliminated),
            "remaining": len(remaining),
            "introduced": len(introduced),
        },
    }
