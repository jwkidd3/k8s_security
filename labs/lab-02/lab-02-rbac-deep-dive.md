# Lab 2: RBAC Deep Dive

**Duration:** 40 minutes

## Objectives

- Create Roles, ClusterRoles, RoleBindings, and ServiceAccounts with least-privilege permissions
- Use `kubectl auth can-i` to test and audit permissions
- Restrict access to specific resources by name using `resourceNames`
- Audit cluster-wide RBAC bindings for overly permissive configurations
- Identify and fix overly permissive RBAC configurations

## Prerequisites

- Cloud9 environment from Lab 1 (m5.large, us-east-1)
- Tools installed from Lab 1 (`kind`, `kubectl`, `jq`)

---

### Step 1: Create Lab Namespaces

```bash
kubectl create namespace dev-team
kubectl create namespace staging
kubectl create namespace monitoring
```

### Step 2: Create a Role, ServiceAccount, and RoleBinding

Create a read-only role for pods in the `dev-team` namespace and bind it to a new ServiceAccount:

```bash
# Create the Role
kubectl apply -f labs/lab-02/pod-reader-role.yaml

# Create the ServiceAccount
kubectl create serviceaccount dev-viewer -n dev-team

# Bind the Role to the ServiceAccount
kubectl apply -f labs/lab-02/read-pods-rolebinding.yaml
```

### Step 3: Test Permissions with kubectl auth can-i

```bash
# Should be ALLOWED — get pods in dev-team
kubectl auth can-i get pods --namespace dev-team --as system:serviceaccount:dev-team:dev-viewer

# Should be DENIED — create pods in dev-team
kubectl auth can-i create pods --namespace dev-team --as system:serviceaccount:dev-team:dev-viewer

# Should be DENIED — get pods in staging (different namespace)
kubectl auth can-i get pods --namespace staging --as system:serviceaccount:dev-team:dev-viewer

# Should be DENIED — get secrets in dev-team (different resource)
kubectl auth can-i get secrets --namespace dev-team --as system:serviceaccount:dev-team:dev-viewer
```

This demonstrates that Roles are scoped to a single namespace and only grant the specific verbs and resources listed.

### Step 4: Create a CI/CD Deployer Role

Create a role in the `staging` namespace that allows deploying applications but not accessing secrets or modifying RBAC:

```bash
kubectl apply -f labs/lab-02/deployer-role.yaml

# Create the ServiceAccount and RoleBinding
kubectl create serviceaccount ci-deployer -n staging

kubectl apply -f labs/lab-02/ci-deployer-binding-rolebinding.yaml
```

### Step 5: Verify Deployer Permissions

```bash
# Should be ALLOWED
kubectl auth can-i create deployments -n staging --as system:serviceaccount:staging:ci-deployer
kubectl auth can-i update services -n staging --as system:serviceaccount:staging:ci-deployer
kubectl auth can-i get configmaps -n staging --as system:serviceaccount:staging:ci-deployer

# Should be DENIED
kubectl auth can-i get secrets -n staging --as system:serviceaccount:staging:ci-deployer
kubectl auth can-i create roles -n staging --as system:serviceaccount:staging:ci-deployer
kubectl auth can-i delete namespaces -n staging --as system:serviceaccount:staging:ci-deployer
```

The deployer can manage applications but cannot access secrets, modify RBAC, or perform destructive cluster operations.

### Step 6: Create a Monitoring Agent ClusterRole

A monitoring agent needs read-only access across the entire cluster — not just one namespace. This requires a ClusterRole and ClusterRoleBinding:

```bash
# Create the monitoring ServiceAccount
kubectl create serviceaccount monitoring-agent -n monitoring

# Create a ClusterRole with read-only access to key resources
kubectl apply -f labs/lab-02/monitoring-reader-resources.yaml

# Test — should be ALLOWED across all namespaces
kubectl auth can-i get pods --all-namespaces --as system:serviceaccount:monitoring:monitoring-agent
kubectl auth can-i list nodes --as system:serviceaccount:monitoring:monitoring-agent
kubectl auth can-i list events -n kube-system --as system:serviceaccount:monitoring:monitoring-agent

# Test — should be DENIED (read-only means no mutations)
kubectl auth can-i create pods -n default --as system:serviceaccount:monitoring:monitoring-agent
kubectl auth can-i delete nodes --as system:serviceaccount:monitoring:monitoring-agent
kubectl auth can-i get secrets --all-namespaces --as system:serviceaccount:monitoring:monitoring-agent
```

Notice the monitoring agent can read pods, nodes, services, and events across all namespaces but cannot modify anything or access secrets. This is the principle of least privilege applied to cluster-wide roles.

### Step 7: Use resourceNames to Restrict Access to a Specific ConfigMap

Sometimes you need to grant access to only a specific named resource, not all resources of that type. The `resourceNames` field enables this:

```bash
# First, create two ConfigMaps in the dev-team namespace
kubectl create configmap app-config -n dev-team --from-literal=log-level=info --from-literal=env=development
kubectl create configmap database-config -n dev-team --from-literal=host=db.internal --from-literal=port=5432

# Create a Role that only allows access to app-config, NOT database-config
kubectl apply -f labs/lab-02/app-config-reader-role.yaml

# Create a ServiceAccount and bind it
kubectl create serviceaccount config-reader -n dev-team

kubectl apply -f labs/lab-02/read-app-config-rolebinding.yaml

# Test — should be ALLOWED (specific named resource)
kubectl auth can-i get configmaps/app-config -n dev-team --as system:serviceaccount:dev-team:config-reader

# Test — should be DENIED (different named resource)
kubectl auth can-i get configmaps/database-config -n dev-team --as system:serviceaccount:dev-team:config-reader

# Test — list is allowed (needed to discover resources), but get is restricted by name
kubectl auth can-i list configmaps -n dev-team --as system:serviceaccount:dev-team:config-reader
```

The `resourceNames` field is useful for restricting access to specific secrets, ConfigMaps, or other named resources. Note that `list` cannot be restricted by `resourceNames` — it either lists all or none — but `get` is enforced per resource name.

### Step 8: Create an Anti-Pattern and Audit It

This demonstrates the danger of wildcard permissions on a default ServiceAccount:

```bash
# WARNING: This is intentionally insecure for learning purposes
kubectl apply -f labs/lab-02/too-permissive-resources.yaml

# Audit — the default SA now has full cluster access
kubectl auth can-i --list --as system:serviceaccount:dev-team:default

# Can it access secrets across all namespaces?
kubectl auth can-i get secrets --all-namespaces --as system:serviceaccount:dev-team:default

# Can it modify RBAC?
kubectl auth can-i create clusterrolebindings --as system:serviceaccount:dev-team:default

# Can it delete namespaces?
kubectl auth can-i delete namespaces --as system:serviceaccount:dev-team:default
```

Every pod in the `dev-team` namespace that uses the `default` ServiceAccount now has full cluster-admin access. If an attacker compromises any pod, they own the entire cluster.

### Step 9: Fix the Anti-Pattern

```bash
# Remove the overly permissive binding and role
kubectl delete clusterrolebinding overly-permissive-binding
kubectl delete clusterrole too-permissive

# Verify the default SA is back to minimal permissions
kubectl auth can-i get secrets --all-namespaces --as system:serviceaccount:dev-team:default
# Expected: no
```

### Step 10: Audit Cluster-Wide RBAC for cluster-admin Bindings

In production, you should regularly audit which subjects have cluster-admin access. This step uses jq to find all ClusterRoleBindings that reference the `cluster-admin` ClusterRole:

```bash
# List all ClusterRoleBindings that reference cluster-admin
echo "=== ClusterRoleBindings referencing cluster-admin ==="
kubectl get clusterrolebindings -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  {
    binding: .metadata.name,
    subjects: [.subjects[]? | "\(.kind)/\(.name)" + (if .namespace then " (ns: \(.namespace))" else "" end)]
  } |
  "\(.binding):\n  Subjects: \(.subjects | join(", "))"
'

# Count how many bindings reference cluster-admin
echo ""
echo -n "Total cluster-admin bindings: "
kubectl get clusterrolebindings -o json | jq '[.items[] | select(.roleRef.name == "cluster-admin")] | length'

# Find any ServiceAccounts (not users or groups) with cluster-admin
echo ""
echo "=== ServiceAccounts with cluster-admin access ==="
kubectl get clusterrolebindings -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  .subjects[]? |
  select(.kind == "ServiceAccount") |
  "ServiceAccount: \(.name) in namespace: \(.namespace // "N/A")"
'

# Find all ClusterRoles that use wildcard permissions
echo ""
echo "=== ClusterRoles with wildcard permissions ==="
kubectl get clusterroles -o json | jq -r '
  .items[] |
  select(.rules[]? | (.apiGroups[]? == "*") or (.resources[]? == "*") or (.verbs[]? == "*")) |
  .metadata.name
'
```

This kind of RBAC auditing should be part of your regular security review process. Any unexpected ServiceAccount with cluster-admin access is a potential privilege escalation path.

### Step 11: Cleanup

```bash
# Clean up lab resources
kubectl delete namespace dev-team staging monitoring

# Clean up cluster-scoped resources
kubectl delete clusterrole monitoring-reader --ignore-not-found
kubectl delete clusterrolebinding monitoring-reader-binding --ignore-not-found

# (Optional) Delete the cluster — keep it if continuing to Lab 3
# kind delete cluster --name security-lab
```

## Summary

- Roles and RoleBindings grant namespace-scoped permissions; ClusterRoles and ClusterRoleBindings grant cluster-wide permissions. Always start with zero permissions and add only what is needed.
- `kubectl auth can-i` is the primary tool for testing and auditing RBAC permissions interactively.
- The `resourceNames` field restricts access to specific named resources, enabling fine-grained access control beyond resource types.
- Wildcard permissions (`*`) on default ServiceAccounts are a critical anti-pattern that gives every pod full cluster access.
- Regular RBAC auditing with jq queries against ClusterRoleBindings helps detect privilege escalation risks before attackers do.
