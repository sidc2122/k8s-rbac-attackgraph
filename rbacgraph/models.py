"""
Data model for Kubernetes RBAC objects.

Everything downstream (rule engine, graph, ranking) works against these
classes, not against raw YAML dictionaries. Keeping the raw parsing in one
place means the rest of the code never has to care whether the data came
from a YAML file or a live cluster.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class PolicyRule:
    """One rule inside a Role or ClusterRole (a single entry under `rules:`)."""
    api_groups: tuple      # e.g. ("",) for core, ("rbac.authorization.k8s.io",)
    resources: tuple       # e.g. ("secrets",), ("pods",), ("*",)
    verbs: tuple           # e.g. ("get", "list"), ("create",), ("*",)
    resource_names: tuple = ()   # optional: restrict to named objects


@dataclass
class Role:
    """A Role (namespaced) or ClusterRole (namespace is None)."""
    name: str
    namespace: Optional[str]     # None => ClusterRole
    kind: str                    # "Role" or "ClusterRole"
    rules: List[PolicyRule] = field(default_factory=list)

    @property
    def key(self):
        return (self.kind, self.namespace, self.name)


@dataclass(frozen=True)
class Subject:
    """A thing a binding grants permissions to."""
    kind: str                    # "ServiceAccount", "User", "Group"
    name: str
    namespace: Optional[str] = None   # only ServiceAccounts have one

    def label(self) -> str:
        if self.kind == "ServiceAccount":
            return f"sa:{self.namespace}/{self.name}"
        return f"{self.kind.lower()}:{self.name}"


@dataclass
class Binding:
    """A RoleBinding (namespaced) or ClusterRoleBinding (namespace None)."""
    name: str
    namespace: Optional[str]     # None => ClusterRoleBinding
    kind: str                    # "RoleBinding" or "ClusterRoleBinding"
    role_ref_kind: str           # "Role" or "ClusterRole"
    role_ref_name: str
    subjects: List[Subject] = field(default_factory=list)


@dataclass
class Pod:
    name: str
    namespace: str
    service_account: str         # resolved; defaults to "default"


@dataclass
class GrantedRule:
    """
    A PolicyRule as it actually applies to one subject, with the namespace
    it applies in.

    scope_namespace = None  -> the grant is cluster-wide
                              (came from a ClusterRoleBinding)
    scope_namespace = "foo" -> the grant only applies in namespace foo
                              (came from a RoleBinding in namespace foo)
    """
    scope_namespace: Optional[str]
    rule: PolicyRule
