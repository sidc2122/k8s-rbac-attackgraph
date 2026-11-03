# make_big.py - generates a large synthetic RBAC file for stress testing
lines = []
for i in range(400):
    lines.append(f"""---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa{i}
  namespace: big
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: r{i}
  namespace: big
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb{i}
  namespace: big
subjects:
- kind: ServiceAccount
  name: sa{i}
  namespace: big
roleRef:
  kind: Role
  name: r{i}
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: p{i}
  namespace: big
spec:
  serviceAccountName: sa{i}""")

with open("samples/big_test.yaml", "w") as f:
    f.write("\n".join(lines))

print("Created samples/big_test.yaml with 400 service accounts")