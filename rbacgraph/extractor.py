"""
RBAC data extraction (pipeline stage 1).

Reads one or more Kubernetes YAML files, pulls out every RBAC object, and
resolves the key question: for each subject (ServiceAccount / User / Group),
what can it actually do, and in which namespace?

Output: a `Cluster` object holding roles, bindings, pods, and a resolved
mapping   subject -> list[GrantedRule].

Live-cluster support (python kubernetes client) can be added later by
producing the same objects from the API instead of from YAML. The rest of
the pipeline won't change.
"""

from collections import defaultdict
from typing import Dict, List, Tuple

import yaml

from .models import (
    Binding,
    GrantedRule,
    PolicyRule,
    Pod,
    Role,
    Subject,
)


class Cluster:
    """Everything we extracted, plus the resolved permission map."""

    def __init__(self):
        self.roles: Dict[tuple, Role] = {}          # keyed by Role.key
        self.bindings: List[Binding] = []
        self.pods: List[Pod] = []
        # subject -> list of GrantedRule
        self.permissions: Dict[Subject, List[GrantedRule]] = defaultdict(list)

    def service_accounts(self) -> List[Subject]:
        """All ServiceAccount subjects we have seen (via bindings or pods)."""
        sas = set()
        for subj in self.permissions:
            if subj.kind == "ServiceAccount":
                sas.add(subj)
        for pod in self.pods:
            sas.add(Subject("ServiceAccount", pod.service_account, pod.namespace))
        return sorted(sas, key=lambda s: s.label())

    def subjects(self) -> List[Subject]:
        return sorted(self.permissions.keys(), key=lambda s: s.label())


def _parse_rules(raw_rules) -> List[PolicyRule]:
    rules = []
    if not isinstance(raw_rules, list):
        return rules
    for r in raw_rules:
        if not isinstance(r, dict):
            continue
        rules.append(
            PolicyRule(
                api_groups=tuple(_as_list(r.get("apiGroups", [""]))),
                resources=tuple(_as_list(r.get("resources", []))),
                verbs=tuple(_as_list(r.get("verbs", []))),
                resource_names=tuple(_as_list(r.get("resourceNames", []))),
            )
        )
    return rules


def _parse_subjects(raw_subjects) -> List[Subject]:
    subjects = []
    if not isinstance(raw_subjects, list):
        return subjects
    for s in raw_subjects:
        if not isinstance(s, dict):
            continue
        subjects.append(
            Subject(
                kind=str(s.get("kind", "")),
                name=str(s.get("name", "")),
                namespace=s.get("namespace"),
            )
        )
    return subjects


def _as_list(v):
    """Coerce a value to a list of strings, tolerating scalars or junk."""
    if isinstance(v, list):
        return [str(x) for x in v]
    if v is None:
        return []
    return [str(v)]


class InvalidInputError(ValueError):
    """Raised when an uploaded file can't be read as Kubernetes YAML."""


def load_documents(paths: List[str]) -> List[dict]:
    """
    Load every YAML document from every file. Only mapping (dict) documents are
    kept; anything else (plain text, lists, nulls) is ignored. Raises
    InvalidInputError with a clear message when a file isn't usable YAML.
    """
    docs = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = list(yaml.safe_load_all(fh))
        except UnicodeDecodeError:
            raise InvalidInputError(
                "This file isn't a text/YAML file (it looks binary). "
                "Please upload a Kubernetes RBAC YAML file.")
        except yaml.YAMLError as exc:
            detail = getattr(exc, "problem", None) or "invalid YAML syntax"
            raise InvalidInputError(f"This file isn't valid YAML: {detail}.")

        for doc in loaded:
            if isinstance(doc, dict):
                docs.append(doc)
            # non-dict docs (strings, lists, None) are silently skipped

    return docs


# Built-in ClusterRoles that Kubernetes ships with. They are never present in
# a user's YAML, but bindings frequently reference them. The most important is
# cluster-admin, which is a wildcard-everything role. Binding any subject to it
# is the most common real-world RBAC misconfiguration (OWASP K03), so it
# model it explicitly.
BUILTIN_CLUSTER_ROLES = {
    "cluster-admin": [
        PolicyRule(api_groups=("*",), resources=("*",), verbs=("*",)),
    ],
}


def _inject_builtin_roles(cluster: "Cluster"):
    for name, rules in BUILTIN_CLUSTER_ROLES.items():
        key = ("ClusterRole", None, name)
        if key not in cluster.roles:
            cluster.roles[key] = Role(name, None, "ClusterRole", list(rules))


def build_cluster(paths: List[str]) -> Cluster:
    cluster = Cluster()
    docs = load_documents(paths)
    _inject_builtin_roles(cluster)

    # First pass: collect roles, bindings, pods.
    for doc in docs:
        kind = doc.get("kind")
        meta = doc.get("metadata")
        if not isinstance(meta, dict):
            meta = {}
        name = str(meta.get("name", "") or "")
        namespace = meta.get("namespace")

        if kind == "Role":
            role = Role(name, namespace, "Role", _parse_rules(doc.get("rules")))
            cluster.roles[role.key] = role

        elif kind == "ClusterRole":
            role = Role(name, None, "ClusterRole", _parse_rules(doc.get("rules")))
            cluster.roles[role.key] = role

        elif kind == "RoleBinding":
            ref = doc.get("roleRef")
            if not isinstance(ref, dict):
                ref = {}
            cluster.bindings.append(
                Binding(
                    name=name,
                    namespace=namespace,
                    kind="RoleBinding",
                    role_ref_kind=str(ref.get("kind", "") or ""),
                    role_ref_name=str(ref.get("name", "") or ""),
                    subjects=_parse_subjects(doc.get("subjects")),
                )
            )

        elif kind == "ClusterRoleBinding":
            ref = doc.get("roleRef")
            if not isinstance(ref, dict):
                ref = {}
            cluster.bindings.append(
                Binding(
                    name=name,
                    namespace=None,
                    kind="ClusterRoleBinding",
                    role_ref_kind=str(ref.get("kind", "") or ""),
                    role_ref_name=str(ref.get("name", "") or ""),
                    subjects=_parse_subjects(doc.get("subjects")),
                )
            )

        elif kind == "Pod":
            spec = doc.get("spec")
            if not isinstance(spec, dict):
                spec = {}
            sa = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
            cluster.pods.append(Pod(name, namespace or "default", str(sa)))

    resolve_permissions(cluster)
    return cluster


def resolve_permissions(cluster: Cluster) -> Cluster:
    """
    Second pass: turn (bindings + roles) into a per-subject permission map.

    Shared by both the YAML path (build_cluster) and the live-cluster path
    (rbacgraph.live), so the exact same resolution logic runs either way.
    """
    for binding in cluster.bindings:
        role = _lookup_role(cluster, binding)
        if role is None:
            # Referenced role not present; skip quietly.
            continue

        # A RoleBinding grants permissions only inside its own namespace,
        # even when it references a ClusterRole. A ClusterRoleBinding grants
        # cluster-wide (scope_namespace = None).
        scope = None if binding.kind == "ClusterRoleBinding" else binding.namespace

        for subject in binding.subjects:
            subject = _normalise_subject(subject, binding)
            for rule in role.rules:
                cluster.permissions[subject].append(GrantedRule(scope, rule))

    return cluster


def _lookup_role(cluster: Cluster, binding: Binding):
    if binding.role_ref_kind == "ClusterRole":
        return cluster.roles.get(("ClusterRole", None, binding.role_ref_name))
    # Role: same namespace as the (RoleBinding) that references it.
    return cluster.roles.get(("Role", binding.namespace, binding.role_ref_name))


def _normalise_subject(subject: Subject, binding: Binding) -> Subject:
    """
    A ServiceAccount subject in a RoleBinding may omit its namespace, meaning
    'the binding's namespace'. Fill that in so subjects are comparable.
    """
    if subject.kind == "ServiceAccount" and not subject.namespace:
        return Subject("ServiceAccount", subject.name, binding.namespace)
    return subject


# ---- Permission query helpers (used by the rule engine) --------------------

def rule_matches(rule: PolicyRule, api_group: str, resource: str, verb: str) -> bool:
    """Does a single PolicyRule grant (api_group, resource, verb)? Handles '*'."""
    def hit(values, wanted):
        return wanted in values or "*" in values

    return (
        hit(rule.api_groups, api_group)
        and hit(rule.resources, resource)
        and hit(rule.verbs, verb)
    )


def can(
    cluster: Cluster,
    subject: Subject,
    api_group: str,
    resource: str,
    verb: str,
) -> List[GrantedRule]:
    """
    Return the GrantedRules that let `subject` do (api_group, resource, verb).
    Empty list => not permitted.
    """
    hits = []
    for granted in cluster.permissions.get(subject, []):
        if rule_matches(granted.rule, api_group, resource, verb):
            hits.append(granted)
    return hits
