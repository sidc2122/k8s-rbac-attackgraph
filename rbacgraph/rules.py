"""
Attack rule engine (pipeline stage 2).

This is the core of the project. It turns raw RBAC permissions into
*attacker capabilities*, expressed as directed graph edges.

Every rule below is a documented Kubernetes privilege-escalation primitive.
Sources for the encoded techniques:
  - Kubernetes RBAC Good Practices (official hardening guide)
  - PaloAltoNetworks/rbac-police policy set
  - OWASP Kubernetes Top Ten - K03: Overly Permissive RBAC
  - Yang et al. (2023), "Take Over the Whole Cluster" (your CA reference)

An Edge means: "starting as `src`, an attacker can move to `dst` using
`technique`, at roughly `effort` cost". Chaining edges = a multi-step attack
path, which is exactly what single-finding scanners miss.

Special target node:
    CLUSTER_ADMIN - full control of the cluster (highest value)

To extend the tool, add another rule block below. Keep the comment that says
which documented technique it models, for traceability.
"""

from dataclasses import dataclass
from typing import List

from .extractor import Cluster, can
from .models import Subject

CLUSTER_ADMIN = "TARGET:cluster-admin"

# Effort scale: 1 = one direct step to admin; 2 = a typical single hop;
# 3 = a more involved / indirect step. Kept coarse and defensible on purpose.
E_DIRECT = 1
E_HOP = 2
E_INDIRECT = 3


@dataclass
class Edge:
    src: str
    dst: str
    technique: str      # plain-language description of the attacker move
    effort: int         # see scale above
    rule_id: str = ""   # which rule produced this edge (for the report)


# Verbs/resources that let a subject create workloads. Any of these ultimately
# lets an attacker run a pod, and a pod can auto-mount another SA's token.
# (K8s docs: "permission to create workloads ... implicitly grants access to
#  ... Secrets ... that can be mounted".)
_WORKLOAD_RESOURCES = [
    ("", "pods"),
    ("apps", "deployments"),
    ("apps", "daemonsets"),
    ("apps", "statefulsets"),
    ("apps", "replicasets"),
    ("apps", "replicationcontrollers"),
    ("batch", "jobs"),
    ("batch", "cronjobs"),
]


def _cluster_wide(granted_rules) -> bool:
    return any(g.scope_namespace is None for g in granted_rules)


def _namespaces_of(granted_rules) -> set:
    return {g.scope_namespace for g in granted_rules}


def _victims_in_scope(all_sas, hits, subject):
    """
    Given the grants (`hits`) that enable a capability, return the SAs an
    attacker could pivot to. Cluster-wide grants reach every SA; namespaced
    grants only reach SAs in the same namespace(s).
    """
    if _cluster_wide(hits):
        victims = list(all_sas)
    else:
        namespaces = _namespaces_of(hits)
        victims = [sa for sa in all_sas if sa.namespace in namespaces]
    return [v for v in victims if v != subject]


def generate_edges(cluster: Cluster) -> List[Edge]:
    edges: List[Edge] = []
    all_sas = cluster.service_accounts()

    for subject in cluster.subjects():
        src = subject.label()

        # ---- Rule 1: wildcard permissions == cluster-admin --------------
        # Source: OWASP K03, rbac-police "cluster-admin". A subject bound to
        # the built-in cluster-admin role resolves here too (see extractor).
        if can(cluster, subject, "*", "*", "*"):
            edges.append(Edge(src, CLUSTER_ADMIN,
                              "Holds wildcard (*) permissions / cluster-admin",
                              E_DIRECT, "wildcard-admin"))
            continue  # already all-powerful; no need to chain

        # ---- Rule 2: can create/modify RBAC bindings -------------------
        # Source: rbac-police "can-bind-*", K8s docs. Creating a
        # (cluster)rolebinding lets a subject grant itself a privileged role.
        for res in ("rolebindings", "clusterrolebindings"):
            hits = []
            for verb in ("create", "update", "patch"):
                hits += can(cluster, subject, "rbac.authorization.k8s.io", res, verb)
            if hits:
                edges.append(Edge(src, CLUSTER_ADMIN,
                                  f"Can create/modify {res}: bind self to a privileged role",
                                  E_DIRECT, "create-binding"))
                break

        # ---- Rule 3: escalate / bind verb on roles ---------------------
        # Source: K8s docs "privilege escalation prevention". These verbs
        # bypass the built-in guard that prevents granting rights not held.
        for res in ("roles", "clusterroles"):
            for verb in ("escalate", "bind"):
                if can(cluster, subject, "rbac.authorization.k8s.io", res, verb):
                    edges.append(Edge(src, CLUSTER_ADMIN,
                                      f"Has '{verb}' on {res}: grant self higher privileges",
                                      E_DIRECT, "escalate-verb"))

        # ---- Rule 4: impersonation -------------------------------------
        # Source: K8s docs, Aqua. Impersonating the system:masters group (or a
        # privileged SA) yields cluster-admin immediately.
        for res in ("users", "groups", "serviceaccounts"):
            if can(cluster, subject, "", res, "impersonate"):
                edges.append(Edge(src, CLUSTER_ADMIN,
                                  f"Can impersonate {res} (e.g. system:masters)",
                                  E_HOP, "impersonate"))

        # ---- Rule 5: certificatesigningrequests -> mint admin cert ------
        # Source: K8s docs. create CSR + update on .../approval lets an
        # attacker issue a client cert authenticating as any user/group.
        can_create_csr = can(cluster, subject, "certificates.k8s.io",
                             "certificatesigningrequests", "create")
        can_approve_csr = can(cluster, subject, "certificates.k8s.io",
                             "certificatesigningrequests/approval", "update")
        if can_create_csr and can_approve_csr:
            edges.append(Edge(src, CLUSTER_ADMIN,
                              "Can create and approve CSRs: mint a cluster-admin client cert",
                              E_DIRECT, "csr-mint"))

        # ---- Rule 6: mutating/validating webhooks ----------------------
        # Source: rbac-police. Control of admission webhooks lets an attacker
        # read or mutate any object admitted to the cluster.
        for res in ("mutatingwebhookconfigurations", "validatingwebhookconfigurations"):
            for verb in ("create", "update", "patch"):
                if can(cluster, subject, "admissionregistration.k8s.io", res, verb):
                    edges.append(Edge(src, CLUSTER_ADMIN,
                                      f"Can modify {res}: intercept/mutate any cluster object",
                                      E_HOP, "webhook"))
                    break

        # ---- Rule 7: mint tokens via TokenRequest ----------------------
        # Source: rbac-police. create on serviceaccounts/token issues a valid
        # token for a target SA, letting the attacker become that SA.
        token_hits = can(cluster, subject, "", "serviceaccounts/token", "create")
        if token_hits:
            for victim in _victims_in_scope(all_sas, token_hits, subject):
                edges.append(Edge(src, victim.label(),
                                  f"Mint a token for {victim.label()} (TokenRequest API)",
                                  E_HOP, "token-request"))

        # ---- Rule 8: read secrets -> steal SA tokens -------------------
        # Source: K8s docs, OWASP K03. get/list/WATCH on secrets exposes SA
        # tokens (list/watch return full contents), so the attacker steals them.
        secret_hits = (can(cluster, subject, "", "secrets", "get")
                       + can(cluster, subject, "", "secrets", "list")
                       + can(cluster, subject, "", "secrets", "watch"))
        if secret_hits:
            for victim in _victims_in_scope(all_sas, secret_hits, subject):
                edges.append(Edge(src, victim.label(),
                                  f"Read secrets: steal token of {victim.label()}",
                                  E_HOP, "read-secrets"))

        # ---- Rule 9: create secrets -> forge SA token ------------------
        # Source: rbac-police. create/modify secrets lets an attacker mint a
        # legacy token secret bound to a target SA.
        make_secret = (can(cluster, subject, "", "secrets", "create")
                       + can(cluster, subject, "", "secrets", "update")
                       + can(cluster, subject, "", "secrets", "patch"))
        if make_secret:
            for victim in _victims_in_scope(all_sas, make_secret, subject):
                edges.append(Edge(src, victim.label(),
                                  f"Create a token secret bound to {victim.label()}",
                                  E_INDIRECT, "create-secret-token"))

        # ---- Rule 10: create workloads -> run pod as another SA --------
        # Source: K8s docs, Certitude, SCHUTZWERK. Any workload-create verb
        # permits specifying a more privileged SA in the pod spec.
        workload_hits = []
        for api_group, resource in _WORKLOAD_RESOURCES:
            workload_hits += can(cluster, subject, api_group, resource, "create")
        if workload_hits:
            for victim in _victims_in_scope(all_sas, workload_hits, subject):
                edges.append(Edge(src, victim.label(),
                                  f"Create workload mounting {victim.label()}'s token",
                                  E_HOP, "create-workload"))

        # ---- Rule 11: exec / attach into pods --------------------------
        # Source: rbac-police. create pods/exec (or pods/attach) runs code in
        # an existing pod and inherits that pod's SA.
        exec_hits = (can(cluster, subject, "", "pods/exec", "create")
                     + can(cluster, subject, "", "pods/attach", "create"))
        if exec_hits:
            _pod_pivots(edges, cluster, subject, exec_hits,
                       "Exec into pod '{pod}': use {victim}", "pods-exec")

        # ---- Rule 12: update/patch pods or ephemeralcontainers ---------
        # Source: rbac-police. Patching a pod or adding an ephemeral container
        # gains code execution inside an existing (possibly powerful) pod.
        mutate_pod = (can(cluster, subject, "", "pods", "update")
                      + can(cluster, subject, "", "pods", "patch")
                      + can(cluster, subject, "", "pods/ephemeralcontainers", "update")
                      + can(cluster, subject, "", "pods/ephemeralcontainers", "patch"))
        if mutate_pod:
            _pod_pivots(edges, cluster, subject, mutate_pod,
                       "Inject/patch pod '{pod}': use {victim}", "mutate-pod")

    return _dedupe(edges)


def _pod_pivots(edges, cluster, subject, hits, template, rule_id):
    """Add edges from `subject` to the SAs of running pods it can execute in."""
    cluster_wide = _cluster_wide(hits)
    namespaces = _namespaces_of(hits)
    for pod in cluster.pods:
        if cluster_wide or pod.namespace in namespaces:
            victim = Subject("ServiceAccount", pod.service_account, pod.namespace)
            if victim == subject:
                continue
            edges.append(Edge(
                subject.label(), victim.label(),
                template.format(pod=pod.name, victim=victim.label()),
                E_HOP, rule_id))


def _dedupe(edges: List[Edge]) -> List[Edge]:
    """Keep the cheapest edge between any pair of nodes."""
    best = {}
    for e in edges:
        key = (e.src, e.dst)
        if key not in best or e.effort < best[key].effort:
            best[key] = e
    return list(best.values())
