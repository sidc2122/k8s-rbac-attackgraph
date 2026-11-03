"""
Live-cluster input (the optional live path for stage 1).

Instead of reading RBAC from YAML files, this connects to a running cluster's
API server (using your kubectl config) and pulls RBAC in real time. It builds
the SAME `Cluster` object the YAML path builds, then runs the SAME resolver,
so the rule engine / graph / ranking downstream are completely unchanged.

Requires the kubernetes client:  pip install kubernetes
It reads your current kubectl context (e.g. kind-rbac-test), so whatever
cluster `kubectl` talks to is what this analyses. Read-only: it only lists.
"""

from typing import List, Optional

from .extractor import Cluster, _inject_builtin_roles, resolve_permissions
from .models import Binding, Pod, PolicyRule, Role, Subject


def _rules_from_api(api_rules) -> List[PolicyRule]:
    rules = []
    for r in api_rules or []:
        rules.append(
            PolicyRule(
                api_groups=tuple(r.api_groups or [""]),
                resources=tuple(r.resources or []),
                verbs=tuple(r.verbs or []),
                resource_names=tuple(r.resource_names or []),
            )
        )
    return rules


def _subjects_from_api(api_subjects) -> List[Subject]:
    subjects = []
    for s in api_subjects or []:
        subjects.append(
            Subject(kind=s.kind, name=s.name, namespace=getattr(s, "namespace", None))
        )
    return subjects


def build_cluster_live(context: Optional[str] = None) -> Cluster:
    try:
        from kubernetes import client, config
    except ImportError as exc:
        raise SystemExit(
            "The kubernetes client is not installed.\n"
            "Install it with:  pip install kubernetes"
        ) from exc

    # Load kubectl config (~/.kube/config). context=None uses the current one.
    config.load_kube_config(context=context)
    rbac = client.RbacAuthorizationV1Api()
    core = client.CoreV1Api()

    cluster = Cluster()
    _inject_builtin_roles(cluster)

    # Roles (namespaced)
    for r in rbac.list_role_for_all_namespaces().items:
        role = Role(r.metadata.name, r.metadata.namespace, "Role",
                    _rules_from_api(r.rules))
        cluster.roles[role.key] = role

    # ClusterRoles
    for r in rbac.list_cluster_role().items:
        role = Role(r.metadata.name, None, "ClusterRole", _rules_from_api(r.rules))
        cluster.roles[role.key] = role

    # RoleBindings
    for b in rbac.list_role_binding_for_all_namespaces().items:
        cluster.bindings.append(
            Binding(
                name=b.metadata.name,
                namespace=b.metadata.namespace,
                kind="RoleBinding",
                role_ref_kind=b.role_ref.kind,
                role_ref_name=b.role_ref.name,
                subjects=_subjects_from_api(b.subjects),
            )
        )

    # ClusterRoleBindings
    for b in rbac.list_cluster_role_binding().items:
        cluster.bindings.append(
            Binding(
                name=b.metadata.name,
                namespace=None,
                kind="ClusterRoleBinding",
                role_ref_kind=b.role_ref.kind,
                role_ref_name=b.role_ref.name,
                subjects=_subjects_from_api(b.subjects),
            )
        )

    # Pods (to know which SA each running app carries)
    for p in core.list_pod_for_all_namespaces().items:
        sa = p.spec.service_account_name or "default"
        cluster.pods.append(Pod(p.metadata.name, p.metadata.namespace, sa))

    resolve_permissions(cluster)
    return cluster
