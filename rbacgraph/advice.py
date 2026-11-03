"""
Fix-advice generator.

For every dangerous step in an attack path, this produces:
  - a plain-English explanation of why the permission is risky,
  - a RECOMMENDED fix that preserves the workload's legitimate function where
    possible (scope the permission down with resourceNames / namespace limits),
  - an ALTERNATIVE fix (remove the permission) with the exact kubectl command,
    for when the permission genuinely isn't needed.

Deleting a permission outright can break the application (for example, a login
service must still read its own password Secret). Least privilege narrows access
to only what is required rather than removing required access, so scoping is the
primary recommendation and removal is the fallback.

One step per path is marked as the weakest link (the exposed entry account),
since breaking any single step breaks the whole chain.
"""

from .extractor import _lookup_role, _normalise_subject, rule_matches
from .graph import path_edges
from .models import Subject

# Each rule_id maps to:
#   why    - why the permission is dangerous
#   match  - permission signature(s) used to find the responsible binding
#   scope  - how to narrow it while keeping legitimate function (or None if the
#            permission is a control-plane power a workload should not hold, in
#            which case removal is the correct primary fix)
RULE_FIX = {
    "wildcard-admin": {
        "why": "This account holds wildcard (*) permissions, i.e. it is effectively cluster-admin.",
        "match": [("*", "*", ("*",))],
        "scope": None,
        "replace": {
            "text": "This account (often the default ServiceAccount) should not be cluster-admin. Remove the broad binding and grant only the specific permissions the workload actually needs with a minimal Role. If the workload never calls the Kubernetes API, also set automountServiceAccountToken: false so no token is mounted.",
            "example": (
                "# Replace broad admin with a minimal, purpose-built Role:\n"
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: Role\n"
                "metadata:\n"
                "  name: <app>-minimal\n"
                "  namespace: <namespace>\n"
                "rules:\n"
                "- apiGroups: [\"\"]\n"
                "  resources: [\"<only-what-the-app-needs>\"]\n"
                "  verbs: [\"get\", \"list\"]"
            ),
        },
    },
    "create-binding": {
        "why": "This account can create or modify RBAC bindings, so it can grant itself any role, including cluster-admin.",
        "match": [
            ("rbac.authorization.k8s.io", "rolebindings", ("create", "update", "patch")),
            ("rbac.authorization.k8s.io", "clusterrolebindings", ("create", "update", "patch")),
        ],
        "scope": None,
        "restrict": {
            "text": "A workload should not create RBAC bindings. Remove it from the app. If a controller genuinely manages bindings, give it a dedicated ServiceAccount, scope it to a single namespace with a RoleBinding (not cluster-wide ClusterRoleBindings), and never grant 'bind'/'escalate' so it cannot grant roles more powerful than itself.",
            "example": (
                "# If a controller must manage bindings, keep it namespaced and minimal:\n"
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: Role\n"
                "metadata:\n"
                "  name: binding-manager\n"
                "  namespace: <controller-namespace>\n"
                "rules:\n"
                "- apiGroups: [\"rbac.authorization.k8s.io\"]\n"
                "  resources: [\"rolebindings\"]      # namespaced, not clusterrolebindings\n"
                "  verbs: [\"get\", \"list\", \"create\"]  # no 'bind' or 'escalate'"
            ),
        },
    },
    "escalate-verb": {
        "why": "This account has the 'escalate' or 'bind' verb on roles, bypassing the guard against granting privileges you don't hold.",
        "match": [
            ("rbac.authorization.k8s.io", "roles", ("escalate", "bind")),
            ("rbac.authorization.k8s.io", "clusterroles", ("escalate", "bind")),
        ],
        "scope": None,
        "restrict": {
            "text": "Remove the 'escalate' and 'bind' verbs. Normal RBAC already lets an account create bindings for permissions it already holds, so these verbs are almost never legitimately needed and exist mainly to bypass the anti-escalation guard.",
            "example": (
                "# Same role with the dangerous verbs removed:\n"
                "rules:\n"
                "- apiGroups: [\"rbac.authorization.k8s.io\"]\n"
                "  resources: [\"roles\", \"rolebindings\"]\n"
                "  verbs: [\"get\", \"list\", \"create\"]   # 'escalate' and 'bind' removed"
            ),
        },
    },
    "impersonate": {
        "why": "This account can impersonate other users/groups (e.g. system:masters), gaining their privileges.",
        "match": [
            ("", "users", ("impersonate",)),
            ("", "groups", ("impersonate",)),
            ("", "serviceaccounts", ("impersonate",)),
        ],
        "scope": None,
        "restrict": {
            "text": "Remove impersonate from the workload. If a component must impersonate specific identities, restrict it to exact users/ServiceAccounts with resourceNames, and never allow impersonating groups (especially system:masters).",
            "example": (
                "rules:\n"
                "- apiGroups: [\"\"]\n"
                "  resources: [\"users\"]\n"
                "  verbs: [\"impersonate\"]\n"
                "  resourceNames: [\"<only-the-specific-user>\"]   # never groups"
            ),
        },
    },
    "csr-mint": {
        "why": "This account can create AND approve certificate signing requests, so it can mint a client certificate for any identity.",
        "match": [
            ("certificates.k8s.io", "certificatesigningrequests", ("create",)),
            ("certificates.k8s.io", "certificatesigningrequests/approval", ("update",)),
        ],
        "scope": None,
        "restrict": {
            "text": "Separate duties: no single account should both create and approve CSRs. Remove the approval permission (update on certificatesigningrequests/approval) from this account, or split creation and approval across two different accounts.",
            "example": (
                "# Keep create if needed, but drop approval from this account:\n"
                "rules:\n"
                "- apiGroups: [\"certificates.k8s.io\"]\n"
                "  resources: [\"certificatesigningrequests\"]\n"
                "  verbs: [\"create\", \"get\"]\n"
                "# delete any rule granting 'update' on certificatesigningrequests/approval"
            ),
        },
    },
    "webhook": {
        "why": "This account can modify admission webhooks, letting it read or mutate any object admitted to the cluster.",
        "match": [
            ("admissionregistration.k8s.io", "mutatingwebhookconfigurations", ("create", "update", "patch")),
            ("admissionregistration.k8s.io", "validatingwebhookconfigurations", ("create", "update", "patch")),
        ],
        "scope": None,
        "restrict": {
            "text": "Restrict modifying admission webhook configurations to cluster administrators only; remove it from workloads. If a component (e.g. cert-manager) manages its own webhook, scope it to that specific configuration with resourceNames.",
            "example": (
                "rules:\n"
                "- apiGroups: [\"admissionregistration.k8s.io\"]\n"
                "  resources: [\"validatingwebhookconfigurations\"]\n"
                "  verbs: [\"get\", \"update\"]\n"
                "  resourceNames: [\"<only-its-own-webhook-config>\"]"
            ),
        },
    },
    "token-request": {
        "why": "This account can mint tokens for other ServiceAccounts (TokenRequest API), letting it become them.",
        "match": [("", "serviceaccounts/token", ("create",))],
        "scope": {
            "text": "If the workload only needs to mint tokens for specific ServiceAccounts, limit it with resourceNames instead of allowing all.",
            "example": (
                "rules:\n"
                "- apiGroups: [\"\"]\n"
                "  resources: [\"serviceaccounts/token\"]\n"
                "  verbs: [\"create\"]\n"
                "  resourceNames: [\"<only-the-serviceaccount-it-should-mint-for>\"]"
            ),
        },
    },
    "read-secrets": {
        "why": "This account can read Secrets, which store other accounts' tokens. Reading them lets an attacker steal those tokens and impersonate more privileged accounts.",
        "match": [("", "secrets", ("get", "list", "watch"))],
        "scope": {
            "text": "Keep access to only the specific Secret this workload needs by adding resourceNames. The app can still read its own secret, but no longer other accounts' tokens. (Note: resourceNames does not restrict list/watch, so drop those verbs and use get.)",
            "example": (
                "rules:\n"
                "- apiGroups: [\"\"]\n"
                "  resources: [\"secrets\"]\n"
                "  verbs: [\"get\"]\n"
                "  resourceNames: [\"<the-secret-this-app-needs>\"]"
            ),
        },
    },
    "create-secret-token": {
        "why": "This account can create/modify Secrets, so it can forge a token secret bound to a privileged ServiceAccount.",
        "match": [("", "secrets", ("create", "update", "patch"))],
        "scope": {
            "text": "If the workload must manage its own Secrets, restrict the binding to that workload's namespace only (use a RoleBinding, not a ClusterRoleBinding), and to named Secrets where possible.",
            "example": None,
        },
    },
    "create-workload": {
        "why": "This account can create workloads (pods/deployments/jobs...). A workload can mount any ServiceAccount's token, so it can run as a more privileged account.",
        "match": [
            ("", "pods", ("create",)),
            ("apps", "deployments", ("create",)),
            ("apps", "daemonsets", ("create",)),
            ("apps", "statefulsets", ("create",)),
            ("apps", "replicasets", ("create",)),
            ("batch", "jobs", ("create",)),
            ("batch", "cronjobs", ("create",)),
        ],
        "scope": {
            "text": "RBAC alone can't restrict which ServiceAccount a created workload uses. Limit the binding to a single namespace, and use an admission policy (e.g. Kyverno or Gatekeeper) to control which ServiceAccounts pods may reference. Remove the permission if the workload doesn't need to create others.",
            "example": None,
        },
    },
    "pods-exec": {
        "why": "This account can exec/attach into running pods, inheriting those pods' ServiceAccount.",
        "match": [("", "pods/exec", ("create",)), ("", "pods/attach", ("create",))],
        "scope": {
            "text": "Limit exec to a single, low-privilege namespace by using a RoleBinding scoped to that namespace instead of a cluster-wide grant, or remove it if it's only needed for occasional debugging.",
            "example": None,
        },
    },
    "mutate-pod": {
        "why": "This account can patch pods or add ephemeral containers, gaining code execution inside existing pods.",
        "match": [
            ("", "pods", ("update", "patch")),
            ("", "pods/ephemeralcontainers", ("update", "patch")),
        ],
        "scope": {
            "text": "Restrict update/patch on pods to the workload's own namespace via a RoleBinding, and remove ephemeralcontainers access unless it's genuinely required for debugging.",
            "example": None,
        },
    },
}


def _label_to_subject(label: str) -> Subject:
    if label.startswith("sa:"):
        ns, name = label[3:].split("/", 1)
        return Subject("ServiceAccount", name, ns)
    kind, name = label.split(":", 1)
    return Subject(kind.capitalize(), name, None)


def _subject_in_binding(subj: Subject, binding) -> bool:
    for s in binding.subjects:
        s2 = _normalise_subject(s, binding)
        if (s2.kind == subj.kind and s2.name == subj.name
                and (s2.namespace or None) == (subj.namespace or None)):
            return True
    return False


def _rule_hits(rule, sigs) -> bool:
    for ag, res, verbs in sigs:
        if any(rule_matches(rule, ag, res, v) for v in verbs):
            return True
    return False


def _delete_command(binding) -> str:
    if binding.kind == "ClusterRoleBinding":
        return f"kubectl delete clusterrolebinding {binding.name}"
    return f"kubectl delete rolebinding {binding.name} -n {binding.namespace}"


def _find_culprit_bindings(cluster, actor_label, sigs):
    subj = _label_to_subject(actor_label)
    culprits = []
    for b in cluster.bindings:
        if not _subject_in_binding(subj, b):
            continue
        role = _lookup_role(cluster, b)
        if role is None:
            continue
        if any(_rule_hits(r, sigs) for r in role.rules):
            culprits.append(b)
    return culprits


def generate_fixes(cluster, graph, path) -> dict:
    steps = []
    for idx, (u, v, tech, rid) in enumerate(path_edges(graph, path)):
        meta = RULE_FIX.get(rid)
        commands = []
        if meta:
            commands = sorted({_delete_command(b)
                               for b in _find_culprit_bindings(cluster, u, meta["match"])})

        remove_block = {
            "approach": "Remove the permission",
            "text": ("If this workload does not need this access, remove the "
                     "binding that grants it:"),
            "example": None,
            "commands": commands,
        }

        if meta and meta.get("scope"):
            has_example = bool(meta["scope"].get("example"))
            scope_block = {
                "approach": "Scope it down (keeps the app working)",
                "text": meta["scope"]["text"],
                "example": meta["scope"].get("example"),
                # When scoping can be shown as a rule edit, the example is the
                # action. When it can't (e.g. workload creation), attach the
                # concrete command so the recommendation is still actionable.
                "commands": [] if has_example else commands,
            }
            steps.append({
                "index": idx, "actor": u, "technique": tech,
                "why": meta["why"] if meta else tech,
                "recommended": scope_block,
                "alternative": remove_block if has_example else None,
            })
        elif meta and meta.get("replace"):
            # Cannot be scoped (e.g. wildcard admin); provide least-
            # privilege replacement rather than a bare deletion.
            replace_block = {
                "approach": "Replace with least privilege",
                "text": meta["replace"]["text"],
                "example": meta["replace"].get("example"),
                "commands": commands,
            }
            steps.append({
                "index": idx, "actor": u, "technique": tech,
                "why": meta["why"],
                "recommended": replace_block,
                "alternative": None,
            })
        elif meta and meta.get("restrict"):
            # Control-plane power: give proper least-privilege guidance, with
            # removal as the concrete alternative.
            restrict_block = {
                "approach": "Restrict to least privilege",
                "text": meta["restrict"]["text"],
                "example": meta["restrict"].get("example"),
                "commands": [],
            }
            steps.append({
                "index": idx, "actor": u, "technique": tech,
                "why": meta["why"],
                "recommended": restrict_block,
                "alternative": remove_block,
            })
        else:
            # Control-plane power (or unknown rule): removing/restricting is the
            # correct primary fix - a workload should not hold it.
            note = ("This is a cluster-control permission a workload should not "
                    "hold. Remove it, or if a controller genuinely needs it, "
                    "move it to a dedicated, non-workload ServiceAccount.")
            remove_block["text"] = note
            steps.append({
                "index": idx, "actor": u, "technique": tech,
                "why": meta["why"] if meta else tech,
                "recommended": remove_block,
                "alternative": None,
            })

    return {"recommended": 0 if steps else None, "steps": steps}
