# Scope and limitations

A clear statement of what the tool does, what it deliberately does not do, and
the assumptions behind its results. Stating these plainly is part of the
contribution: it makes the tool's output trustworthy and defensible.

## In scope

The tool discovers, ranks and helps remediate privilege-escalation paths that
arise from Kubernetes RBAC. Specifically it:

- extracts RBAC (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings,
  ServiceAccounts, Pods) from static YAML or a live cluster;
- maps permissions to twelve documented escalation primitives;
- chains them into directed attack paths ending at cluster-admin;
- ranks paths by attacker effort versus privilege impact;
- validates whether a remediation removed a path;
- generates a plain-English fix and the exact kubectl command;
- operates purely defensively, performing no active exploitation.

## Out of scope (by design)

The tool models RBAC only. It does not analyse, and does not claim to analyse:

- network policies and network reachability;
- container escapes, host mounts, or kernel/privileged-container issues;
- cloud IAM (IRSA, workload identity) and cloud-provider permissions;
- admission control, Pod Security Standards, or image vulnerabilities;
- runtime behaviour or attacks in progress (this is static analysis).

This boundary is a deliberate design decision. The tool is
a focused RBAC attack-path analyser, not a broad posture scanner, and is meant
to complement tools such as KubeScape rather than replace them.

## Modelling assumptions (and why they are reasonable)

Every result follows from these assumptions; each is a deliberate,
defensible choice rather than an oversight.

- Secret reads are treated as token theft. From static configuration the tool
  cannot see what a Secret contains, so "can read Secrets" is modelled as "can
  obtain any ServiceAccount token in scope". This is a conservative worst-case
  that can over-report, which is the safer direction for a security tool.

- Entry points are pod-attached ServiceAccounts. The tool assumes an attacker
  first compromises a running workload and inherits its token. It does not model
  an external attacker reaching the API server directly, or theft of a human
  user's credentials.

- Effort and impact scores are coarse and heuristic (effort 1-3 per step;
  cluster-admin impact fixed at 100). They give a transparent, defensible
  ordering but are not empirically calibrated against real incident data.

- Only the built-in cluster-admin ClusterRole is modelled by name. Bindings to
  other built-in roles (admin, edit) are not expanded, so a path relying on
  those specific built-ins could be missed.

- resourceNames are not fully used when scoping some permissions. A permission
  narrowed to a single named object may still be treated broadly, which can
  over-report.

## Coverage and correctness limits

- The rule engine covers twelve documented primitives. A new or undocumented
  escalation technique will not be detected until a rule for it is added. The
  engine is designed to be extended for exactly this reason.

- On very large, densely connected clusters the tool reports the highest-risk
  shortest paths per entry point rather than exhaustively enumerating every
  route. This is a deliberate scalability choice; the total count is always
  reported so nothing is silently hidden.

- There is no public ground-truth benchmark of "correct" RBAC attack paths, so
  correctness is demonstrated against known, hand-verified test cases and a
  reproducible test suite rather than a labelled dataset.

## Threats to validity

- False positives: the conservative secret-read model may report a path that a
  narrower real-world configuration would not permit.
- False negatives: primitives not yet encoded, or escalation via mechanisms
  outside RBAC, will not appear.
- Construct validity: the effort/impact scoring encodes a reasonable but
  subjective view of attacker cost; other weightings are possible.

## Future work

- Model network policies, cloud IAM, and admission control for cross-domain
  attack paths.
- Expand built-in role coverage and make permission scoping resourceName-aware.
- Calibrate the risk scoring against real incident data.
- Build a labelled benchmark of RBAC attack paths for quantitative evaluation.
- Integrate into CI/CD to block risky RBAC changes before they are applied.

## Design rationale (common questions)

- "What are the limitations?" — see above; the honest headline is that it is
  RBAC-only, static, and uses a conservative secret model that can over-report.

- "How do you know it is correct?" — a 42-test automated suite locks in expected
  results for every sample and edge case; run `python -m unittest discover -s
  tests -v`.

- "Why show a path from an account that legitimately needs a permission?" — the
  tool follows an assume-breach model and measures blast radius. The fix is to
  scope the permission, not remove it.

- "Could it be hosted as a public web service?" — no; it runs locally so cluster
  credentials never leave the operator's machine, matching how tools like
  KubeScape are used.

- "Won't deleting the permission break the application?" — Yes, which is why
  the tool recommends scoping the permission down (e.g. limiting secret reads to
  a specific Secret with resourceNames) as the primary fix, keeping the workload
  working, and offers removal only as an alternative. For control-plane powers a
  workload should never hold (creating bindings, impersonation), removal is the
  correct primary fix.

- "Does it replace KubeScape?" — no; it is narrower and deeper. KubeScape is a
  broad posture scanner; this tool specialises in RBAC attack-path chaining,
  ranking and remediation validation, which open-source KubeScape does not do.
