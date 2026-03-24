# Lab 2: RBAC Deep Dive

**Duration:** 45 minutes

## Objectives

By the end of this lab, you will be able to:

- Create and manage Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings
- Design least-privilege RBAC policies for common use cases
- Use `kubectl auth can-i` to test and audit permissions
- Identify and fix overly permissive RBAC configurations

## Prerequisites

- Running kind cluster from Lab 1 (or create a new one)
- `kubectl` CLI configured

## Lab Environment Setup

### Step 1: Verify Cluster Access

```bash
# If you need to create a new cluster
kind create cluster --name security-lab --config labs/setup/kind-config-default.yaml

# Verify cluster access
kubectl cluster-info --context kind-security-lab
```

### Step 2: Create Lab Namespaces

```bash
# Create namespaces for our RBAC exercises
kubectl create namespace dev-team
kubectl create namespace staging
kubectl create namespace production
```

## Part 1: Understanding Roles and RoleBindings

### Step 3: Create a Namespace-Scoped Role

```bash
# Create a read-only role for the dev-team namespace
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: dev-team
  name: pod-reader
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
EOF
```

### Step 4: Create a ServiceAccount and Bind the Role

```bash
# Create a service account
kubectl create serviceaccount dev-viewer -n dev-team

# Bind the role to the service account
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: dev-team
subjects:
  - kind: ServiceAccount
    name: dev-viewer
    namespace: dev-team
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
EOF
```

### Step 5: Test the Permissions

```bash
# Test what the service account can do
kubectl auth can-i get pods --namespace dev-team --as system:serviceaccount:dev-team:dev-viewer
# Expected: yes

kubectl auth can-i create pods --namespace dev-team --as system:serviceaccount:dev-team:dev-viewer
# Expected: no

kubectl auth can-i get pods --namespace production --as system:serviceaccount:dev-team:dev-viewer
# Expected: no

kubectl auth can-i get secrets --namespace dev-team --as system:serviceaccount:dev-team:dev-viewer
# Expected: no
```

### Step 6: List All Permissions

```bash
# List all permissions for the service account
kubectl auth can-i --list --namespace dev-team --as system:serviceaccount:dev-team:dev-viewer
```

## Part 2: Designing Least-Privilege Roles

### Step 7: Create a CI/CD Deployer Role

This role allows deploying applications but not accessing secrets or modifying RBAC:

```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: staging
  name: deployer
rules:
  # Can manage deployments
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  # Can manage services
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  # Can view pods and logs (for deployment verification)
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  # Can manage configmaps (for app config)
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  # Cannot access secrets, RBAC, or namespaces
EOF

# Create the service account and binding
kubectl create serviceaccount ci-deployer -n staging

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ci-deployer-binding
  namespace: staging
subjects:
  - kind: ServiceAccount
    name: ci-deployer
    namespace: staging
roleRef:
  kind: Role
  name: deployer
  apiGroup: rbac.authorization.k8s.io
EOF
```

### Step 8: Verify the Deployer Role

```bash
# Should be allowed
kubectl auth can-i create deployments -n staging --as system:serviceaccount:staging:ci-deployer
kubectl auth can-i update services -n staging --as system:serviceaccount:staging:ci-deployer
kubectl auth can-i get configmaps -n staging --as system:serviceaccount:staging:ci-deployer

# Should be denied
kubectl auth can-i get secrets -n staging --as system:serviceaccount:staging:ci-deployer
kubectl auth can-i create roles -n staging --as system:serviceaccount:staging:ci-deployer
kubectl auth can-i delete namespaces -n staging --as system:serviceaccount:staging:ci-deployer
```

### Step 9: Create a Monitoring Agent Role

```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-agent
rules:
  # Read-only access to core resources
  - apiGroups: [""]
    resources: ["pods", "nodes", "services", "endpoints", "namespaces"]
    verbs: ["get", "list", "watch"]
  # Read metrics
  - apiGroups: ["metrics.k8s.io"]
    resources: ["pods", "nodes"]
    verbs: ["get", "list"]
  # Read events
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "list", "watch"]
  # No write access to anything
EOF

# Create service account and bind at cluster level
kubectl create serviceaccount monitoring -n kube-system

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: monitoring-agent-binding
subjects:
  - kind: ServiceAccount
    name: monitoring
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: monitoring-agent
  apiGroup: rbac.authorization.k8s.io
EOF
```

## Part 3: Identifying RBAC Anti-Patterns

### Step 10: Create Overly Permissive RBAC (Anti-Pattern)

```bash
# WARNING: This is intentionally insecure for learning purposes
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: too-permissive
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: overly-permissive-binding
subjects:
  - kind: ServiceAccount
    name: default
    namespace: dev-team
roleRef:
  kind: ClusterRole
  name: too-permissive
  apiGroup: rbac.authorization.k8s.io
EOF
```

### Step 11: Audit the Anti-Pattern

```bash
# Check what the default service account can do now
kubectl auth can-i --list --as system:serviceaccount:dev-team:default

# Can it access secrets across all namespaces?
kubectl auth can-i get secrets --all-namespaces --as system:serviceaccount:dev-team:default

# Can it modify RBAC?
kubectl auth can-i create clusterrolebindings --as system:serviceaccount:dev-team:default

# Can it delete namespaces?
kubectl auth can-i delete namespaces --as system:serviceaccount:dev-team:default
```

**Questions:**
1. What is the risk of giving wildcard permissions?
2. Why is this especially dangerous on the `default` service account?
3. What could an attacker do if they compromised a pod in `dev-team`?

### Step 12: Fix the Anti-Pattern

```bash
# Remove the overly permissive binding
kubectl delete clusterrolebinding overly-permissive-binding
kubectl delete clusterrole too-permissive

# Verify it is cleaned up
kubectl auth can-i get secrets --all-namespaces --as system:serviceaccount:dev-team:default
# Expected: no
```

## Part 4: Auditing Existing RBAC

### Step 13: Audit Cluster-Wide RBAC

```bash
# List all ClusterRoleBindings that reference cluster-admin
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.roleRef.name == "cluster-admin") |
    .metadata.name as $binding |
    (.subjects // [])[] |
    "  \(.kind): \(.name) (ns: \(.namespace // "cluster-wide"))  [\($binding)]"'
```

### Step 14: Check Default Service Account Permissions

```bash
# Check each namespace's default service account
for ns in dev-team staging production kube-system; do
  echo "=== Namespace: $ns ==="
  kubectl auth can-i --list --namespace $ns --as system:serviceaccount:$ns:default 2>/dev/null | head -20
  echo ""
done
```

### Step 15: Use kubectl auth can-i for Comprehensive Auditing

```bash
# Create a script to audit a service account
cat > /tmp/audit-rbac.sh <<'SCRIPT'
#!/bin/bash
SA=$1
NS=$2
echo "Auditing: system:serviceaccount:$NS:$SA"
echo "========================================="

resources=("pods" "deployments" "services" "secrets" "configmaps" "namespaces" "nodes" "roles" "clusterroles")
verbs=("get" "list" "create" "update" "delete")

for resource in "${resources[@]}"; do
  for verb in "${verbs[@]}"; do
    result=$(kubectl auth can-i $verb $resource -n $NS --as system:serviceaccount:$NS:$SA 2>/dev/null)
    if [ "$result" = "yes" ]; then
      echo "  ALLOWED: $verb $resource"
    fi
  done
done
SCRIPT
chmod +x /tmp/audit-rbac.sh

# Audit our service accounts
bash /tmp/audit-rbac.sh dev-viewer dev-team
echo ""
bash /tmp/audit-rbac.sh ci-deployer staging
```

## Part 5: Advanced RBAC — resourceNames

### Step 16: Restrict Access to Specific Resources

```bash
# Create a role that can only read a specific ConfigMap
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: dev-team
data:
  environment: development
  log-level: info
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: db-credentials
  namespace: dev-team
data:
  connection-string: "postgresql://localhost:5432/mydb"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: dev-team
  name: app-config-reader
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]
    verbs: ["get"]
EOF

kubectl create serviceaccount app-reader -n dev-team

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-config-reader-binding
  namespace: dev-team
subjects:
  - kind: ServiceAccount
    name: app-reader
    namespace: dev-team
roleRef:
  kind: Role
  name: app-config-reader
  apiGroup: rbac.authorization.k8s.io
EOF
```

### Step 17: Verify resourceNames Restriction

```bash
# Can read app-config
kubectl auth can-i get configmaps/app-config -n dev-team --as system:serviceaccount:dev-team:app-reader
# Expected: yes

# Cannot read db-credentials
kubectl auth can-i get configmaps/db-credentials -n dev-team --as system:serviceaccount:dev-team:app-reader
# Expected: no

# Cannot list all configmaps (resourceNames doesn't work with list)
kubectl auth can-i list configmaps -n dev-team --as system:serviceaccount:dev-team:app-reader
# Expected: no
```

## Cleanup

```bash
# Clean up lab resources
kubectl delete namespace dev-team staging production

# Delete cluster-scoped resources
kubectl delete clusterrole monitoring-agent
kubectl delete clusterrolebinding monitoring-agent-binding

# (Optional) Delete the cluster
# kind delete cluster --name security-lab
```

> **Note:** Keep the cluster running if you plan to continue with Lab 3.

## Summary

In this lab, you:
- Created namespace-scoped Roles and RoleBindings for pod viewing
- Designed least-privilege roles for CI/CD deployer and monitoring use cases
- Identified and remediated overly permissive RBAC (wildcard anti-pattern)
- Audited RBAC permissions using `kubectl auth can-i`
- Used `resourceNames` to restrict access to specific resources

Key takeaway: Always start with zero permissions and add only what is needed. Audit regularly to detect permission creep.
