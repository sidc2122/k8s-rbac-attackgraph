"""
Risk ranking (pipeline stage 4).

Scores each discovered attack path with the formula:

    Risk = Impact / Effort

Impact  = value of the destination the path reaches.
Effort  = total cost of the steps (already summed during path finding),
          with a small floor to avoid division by zero.

The formulation is intentionally simple and transparent so that every score is
explainable. The effort/impact prioritisation approach follows the general
principle of countermeasure ranking (cf. TriAssetRank, Tchimwa Bouom et al.,
2024), adapted here to Kubernetes RBAC.
"""

from dataclasses import dataclass
from typing import List

from .rules import CLUSTER_ADMIN

# Impact value per target node. Additional targets can be added here
# (e.g. TARGET:kube-system-secrets).
IMPACT = {
    CLUSTER_ADMIN: 100,
}
DEFAULT_IMPACT = 40   # reaching another ServiceAccount still has some value


@dataclass
class RankedPath:
    path: List[str]
    effort: int
    impact: int
    risk: float
    severity: str


def _severity(risk: float) -> str:
    if risk >= 50:
        return "CRITICAL"
    if risk >= 25:
        return "HIGH"
    if risk >= 10:
        return "MEDIUM"
    return "LOW"


def rank(paths) -> List[RankedPath]:
    ranked = []
    for path, effort in paths:
        target = path[-1]
        impact = IMPACT.get(target, DEFAULT_IMPACT)
        effort = max(effort, 1)
        risk = round(impact / effort, 2)
        ranked.append(RankedPath(path, effort, impact, risk, _severity(risk)))
    ranked.sort(key=lambda r: r.risk, reverse=True)
    return ranked
