# Evaluation: RBAC Attack-Path Analyser vs existing tools

_Generated 2026-08-09 23:18_

## 1. Methodology

All tools are pointed at the **same target** so any difference in output
reflects a real difference in capability, not a different input. This tool's
results below are produced automatically; KubeScape's captured results on the
same target are given in section 5, and the exact command used to obtain them
is in section 4, so the comparison is reproducible.

## 2. This tool's output (captured automatically)

Target analysed: **samples/vulnerable_rbac.yaml**

- Identities analysed: **3**
- Pods analysed: **1**
- Attack paths found: **2**

| # | Severity | Risk | Entry point | Steps to cluster-admin |
|---|---|---|---|---|
| 1 | HIGH | 33.33 | `sa:app/frontend` | 2 |
| 2 | MEDIUM | 20.0 | `sa:app/frontend` | 3 |

Highest-risk path (ranked #1): `sa:app/frontend` reaches cluster-admin in 2 step(s), risk 33.33.

Full chain of the #1 path:
- sa:app/frontend  ->  Read secrets: steal token of sa:app/binder
- sa:app/binder  ->  Can create/modify rolebindings: bind self to a privileged role

## 3. Capability comparison

| Capability | This tool | KubeScape (OSS) | Peirates | kube-hunter |
|---|---|---|---|---|
| Detects RBAC misconfigurations | ✅ Yes | ✅ Yes | ➖ Partial (exploits, not lists) | ➖ Partial |
| Chains permissions into multi-step attack paths | ✅ Yes | ➖ No (ARMO Platform / Kubehound only) | ❌ No | ❌ No |
| Attacker-centric risk ranking of whole paths (effort vs impact) | ✅ Yes | ➖ No (per-control scores only) | ❌ No | ❌ No |
| Remediation validation (confirms a fix removed a path) | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Plain-English fix command per finding | ✅ Yes | ➖ Partial (per-control guidance) | ❌ No | ❌ No |
| Works on static YAML and live cluster | ✅ Yes | ✅ Yes | ➖ Live only | ➖ Live only |
| Purely defensive (no active exploitation) | ✅ Yes | ✅ Yes | ➖ No (offensive) | ➖ Partial |


The decisive difference is in the second and third rows: existing open-source
tools report findings **individually** (a flat list of misconfigurations),
whereas this tool **chains** related permissions into complete, attacker-
traversable paths to cluster-admin and **ranks** them by attacker effort vs
impact. It then **validates** that a remediation actually removed a path -
which none of the compared tools do.

## 4. How to capture KubeScape's output on the same target

Install KubeScape and scan the same target, then save the result:

```
# install (one line)
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash

# scan the same cluster
kubescape scan --format json --output kubescape_result.json

# or scan the same YAML file
kubescape scan samples/vulnerable_rbac.yaml --format json --output kubescape_result.json
```

Note how KubeScape lists RBAC controls/findings individually with scores, but
does not present a ranked multi-step path from `frontend` to cluster-admin.

## 5. KubeScape output on the same target (captured)

KubeScape v3 was installed in WSL and run on the same `samples/vulnerable_rbac.yaml`
target. It completed 118 controls and produced a flat "security posture overview"
grouped by category. The RBAC-relevant findings it reported were:

**Access control**

| Control | Control ID | Resources |
|---|---|---|
| Access container service account | C-0053 | 3 |
| List Kubernetes secrets | C-0015 | 1 |
| Minimize access to secrets | C-0186 | 1 |

**Secrets**

| Control | Control ID | Resources |
|---|---|---|
| Automatic mapping of service account | C-0034 | 1 |

**Workload / cluster-takeover**

| Control | Control ID | Resources |
|---|---|---|
| Workload with cluster takeover roles | C-0267 | 1 |

It additionally reported unrelated posture controls outside RBAC scope
(pod security context, liveness/readiness probes, resource limits, network
policy, image signature, node-escape controls such as C-0016 allow-privilege-
escalation), which are not relevant to the RBAC attack-path comparison.

**Observations for the comparison**

- KubeScape reported the RBAC weaknesses as **separate, individually-scored
  controls**: "List Kubernetes secrets" (C-0015) and "Workload with cluster
  takeover roles" (C-0267) appear as two unrelated findings.
- **No single finding stated that `frontend` can reach cluster-admin in two
  steps.** The relationship between reading secrets and creating bindings - the
  actual attack path - is not expressed anywhere in the output.
- The findings are **not ranked as paths**: each control carries its own score,
  but there is no ordering that tells the operator which finding is the entry
  point of the most dangerous route.
- KubeScape offers **no remediation validation**: re-running it after a fix
  re-lists controls, but it never confirms that a specific attack path was
  eliminated.

By contrast, this tool reported the same underlying weaknesses as **two ranked
attack paths**, identified that `sa:app/frontend` reaches cluster-admin in two
steps at HIGH risk (33.33), gave the exact scope-down fix for the entry step,
and confirmed after the fix that both paths were eliminated (2 -> 0).

## 6. Discussion

On the vulnerable target, existing tools would flag "frontend can read secrets"
and "binder can create bindings" as **separate** findings, leaving the operator
to work out that together they form a path to full cluster takeover. This tool
surfaces that path directly, ranks it as the top risk, gives the exact fix
command, and confirms the fix eliminated it. This is the contribution set out in
the core aim of the tool: turning flat RBAC findings into prioritised, validated
attack-path intelligence.

## References (competitor capabilities)

- KubeScape scans clusters, YAML and Helm for misconfigurations against
  frameworks (NSA-CISA, MITRE ATT&CK) and reports RBAC violations with
  per-finding risk scores. kubescape.io ; slashdot.org/software/p/Kubescape/
- Multi-step attack-path analysis is provided by the commercial ARMO Platform
  and by Datadog's Kubehound - not by open-source KubeScape, which reports
  control-based findings. armosec.io/armo-vs-kubescape/ ;
  nebulablogs.com (CDK/Kubehound/Kubescape walkthrough, 2026)
- Peirates is an offensive Kubernetes exploitation toolkit (attack execution),
  not a prioritising analyser. github.com/inguardians/peirates
- kube-hunter is a vulnerability hunter (now archived by Aqua); it enumerates
  weaknesses without chaining them into ranked attack paths.
  github.com/aquasecurity/kube-hunter

