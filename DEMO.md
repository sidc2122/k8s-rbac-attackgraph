# Walkthrough

## Before you start (safety net)

Kind clusters can stop after a reboot. Run this first to be sure everything is
up, and to recover instantly if anything is off:

```
python -m rbacgraph.demo status     # check Docker + cluster + RBAC
python -m rbacgraph.demo reset       # recreate cluster if needed + reload RBAC
python -m rbacgraph.demo reset-rbac  # just reload RBAC (use after remediation deletes bindings)
```

If the dashboard dropdown is empty or a live scan errors, the message will tell
you what to do — usually "start Docker" or "run reset".


A 5-minute click-through that exercises every capability. Start
Docker Desktop first, then run the dashboard:

```
python -m rbacgraph.web
```

## Part 1 - Find and rank attack paths

1. **Upload YAML tab** → drag in `samples/vulnerable_rbac.yaml` → **Scan**.
   Shows two colour-coded paths: a HIGH 2-step path and a MEDIUM 3-step path.
   Talk track: "No single permission here is obviously wrong, but chained
   together they lead to full cluster takeover. The tool ranks them by
   Risk = Impact / Effort, so the operator knows what to fix first."

   Then expand **"How to fix this"** on a card. Talk track: "For an operator who
   isn't a Kubernetes security expert, each step comes with a plain-English
   reason and the exact kubectl command to close it. The recommended fix — the
   weakest link — is highlighted, since breaking any one step breaks the whole
   chain."

2. **Live cluster tab** → pick `kind-rbac-test` → **Scan**. Same two paths,
   now from a real running cluster (note the identity count jumps to ~65 as it
   reads the whole cluster, then filters system noise). This is discovery and ranking on live
   Kubernetes.

3. Pick `kind-clean-cluster` → **Scan** → green "no attack paths". Talk track:
   "It stays quiet when the config is sound — no false alarms."

## Part 2 - Remediation validation

4. **Remediation check tab** → pick `kind-rbac-test` → **Capture baseline**
   (shows 2 paths).

5. In a terminal, apply a partial fix:
   ```
   kubectl delete rolebinding deployer-workload-creator -n app
   ```
   Back in the dashboard → **Re-scan & compare**. Result: 1 eliminated
   (the 3-step path), 1 still present (the 2-step path). Talk track: "The tool
   proves the fix helped but didn't finish the job — the direct path remains."

6. Apply the full fix:
   ```
   kubectl delete rolebinding frontend-secret-reader -n app
   ```
   → **Re-scan & compare** → everything eliminated, "Fix fully effective".

7. Re-create the RBAC afterwards to reset for another run:
   ```
   kubectl apply -f samples/vulnerable_rbac.yaml
   ```

## Command-line equivalents (if asked)

```
python -m rbacgraph.cli analyze samples/vulnerable_rbac.yaml
python -m rbacgraph.cli analyze --live --context kind-rbac-test
python -m rbacgraph.cli validate --before samples/vulnerable_rbac.yaml \
                                 --after  samples/fix_partial_rbac.yaml
```

## Likely questions and answers

- **Why local, not a hosted website?** Security tools that read RBAC run next
  to the cluster; credentials never leave the operator's machine. Same model as
  KubeScape. Hosting it would mean collecting strangers' cluster credentials,
  which contradicts the project's own security goals.
- **Why show a path from login/frontend if it "must" read secrets?** Assume-
  breach: the tool measures blast radius if that app is ever compromised. The
  fix is to scope the permission (own secret only), not remove it.
- **Does it assume the entry point is exploitable?** No — it assumes it *might*
  be, and reports how far an attacker could get if it were.
