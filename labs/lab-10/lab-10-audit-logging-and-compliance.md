# Lab 10: Audit Logging & Compliance

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Configure Kubernetes API server audit logging
- Generate and analyze audit log events with jq
- Write targeted jq queries for security-relevant events (exec, RBAC, failures)
- Run CIS Benchmark scans with kube-bench
- Use Polaris for automated compliance scanning

## Prerequisites

- Cloud9 environment from Lab 1 (m5.large, us-east-1)
- Tools installed from Lab 1 (`kind`, `kubectl`, `jq`)

---

### Step 1: Create a Cluster with Audit Logging

```bash
# Create cluster with audit logging enabled
cd labs/setup
kind create cluster --name audit-lab --config kind-config-audit.yaml
cd ../..

# Verify the cluster
kubectl cluster-info --context kind-audit-lab
kubectl get nodes

# Confirm audit logging is active
docker exec audit-lab-control-plane ls -la /var/log/kubernetes/audit/
docker exec audit-lab-control-plane tail -3 /var/log/kubernetes/audit/audit.log | jq .
```

### Step 2: Review the Audit Policy

```bash
# View the audit policy that controls what gets logged
docker exec audit-lab-control-plane cat /etc/kubernetes/audit/audit-policy.yaml
```

The audit policy defines rules that determine which API requests are logged and at what detail level. Key levels are:
- **None** — do not log
- **Metadata** — log who did what, but not the request/response body
- **Request** — log metadata plus the request body
- **RequestResponse** — log everything (use sparingly)

Examine the policy and answer:
1. Which resources are logged at RequestResponse level?
2. Which resources are explicitly excluded from logging?
3. What is the default catch-all level?

```bash
# Count the number of rules in the policy
docker exec audit-lab-control-plane cat /etc/kubernetes/audit/audit-policy.yaml | grep -c "level:"

# Look at what the API server flags are set to for audit
docker exec audit-lab-control-plane ps aux | grep audit
```

### Step 3: Generate Audit Events

```bash
# Create a namespace for testing
kubectl create namespace audit-test

# Create and read a secret
kubectl create secret generic sensitive-data -n audit-test \
  --from-literal=password=MySecret123 \
  --from-literal=api-key=sk-1234567890

kubectl get secret sensitive-data -n audit-test -o yaml > /dev/null

# Create RBAC resources
kubectl apply -f labs/lab-10/audit-test-role-resources.yaml

# Deploy a pod and exec into it
kubectl run test-pod --image=busybox:1.36 -n audit-test -- sleep 3600
kubectl wait --for=condition=Ready pod/test-pod -n audit-test --timeout=60s
kubectl exec -n audit-test test-pod -- whoami

# Run a few more exec commands to generate more events
kubectl exec -n audit-test test-pod -- cat /etc/hostname
kubectl exec -n audit-test test-pod -- ls /tmp

# Generate some failed requests (these should show as forbidden)
kubectl auth can-i delete nodes --as system:serviceaccount:audit-test:default
kubectl get secrets -n kube-system --as system:serviceaccount:audit-test:default 2>/dev/null || true

# Delete the pod to generate a delete event
kubectl delete pod test-pod -n audit-test
```

### Step 4: Analyze Audit Logs with jq — Secret and RBAC Events

```bash
# Show secret access events
echo "=== Secret Access Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.resource == "secrets" and .objectRef.namespace == "audit-test") |
    "  \(.requestReceivedTimestamp // "") | \(.verb) | \(.user.username) | \(.objectRef.name // "") | status: \(.responseStatus.code // "")"'

# Show RBAC change events
echo ""
echo "=== RBAC Change Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.apiGroup == "rbac.authorization.k8s.io" and .objectRef.namespace == "audit-test") |
    "  \(.requestReceivedTimestamp // "") | \(.verb) | \(.objectRef.resource)/\(.objectRef.name // "") | \(.user.username)"'

# Show pod exec and delete events
echo ""
echo "=== Pod Exec and Delete Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select((.objectRef.subresource == "exec" or (.objectRef.resource == "pods" and .verb == "delete")) and .objectRef.namespace == "audit-test") |
    "  \(.requestReceivedTimestamp // "") | \(.verb) | \(.objectRef.name // "") | \(.user.username)"'
```

### Step 5: Advanced Audit Log Queries

```bash
# Find ALL kubectl exec events across the entire cluster
echo "=== All Exec Events (Cluster-Wide) ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.subresource == "exec") |
    "  \(.requestReceivedTimestamp // "") | ns:\(.objectRef.namespace // "N/A") | pod:\(.objectRef.name // "") | user:\(.user.username)"'

# Find failed/forbidden requests (HTTP 403)
echo ""
echo "=== Failed/Forbidden Requests ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.responseStatus.code == 403) |
    "  \(.requestReceivedTimestamp // "") | \(.verb) \(.objectRef.resource // "")/\(.objectRef.name // "") | user:\(.user.username) | reason:\(.responseStatus.reason // "")"' | tail -20

# Find all RBAC-related changes (roles, bindings, clusterroles)
echo ""
echo "=== All RBAC Modifications ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.apiGroup == "rbac.authorization.k8s.io" and (.verb == "create" or .verb == "update" or .verb == "delete" or .verb == "patch")) |
    "  \(.requestReceivedTimestamp // "") | \(.verb) | \(.objectRef.resource)/\(.objectRef.name // "") | ns:\(.objectRef.namespace // "cluster") | user:\(.user.username)"'

# Count events by verb for the audit-test namespace
echo ""
echo "=== Event Counts by Verb (audit-test) ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.namespace == "audit-test") | .verb' | sort | uniq -c | sort -rn

# Show the most active users in the audit log
echo ""
echo "=== Top 10 Active Users ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r '.user.username' | sort | uniq -c | sort -rn | head -10
```

### Step 6: Run kube-bench as a Kubernetes Job

kube-bench checks your cluster against the CIS Kubernetes Benchmark. We run it as a Job on the control plane node:

```bash
kubectl apply -f labs/lab-10/kube-bench-job.yaml
```

### Step 7: Review kube-bench Results

```bash
# Wait for the job to complete
kubectl wait --for=condition=complete job/kube-bench --timeout=120s

# View the full results
kubectl logs job/kube-bench

# Get a summary — count PASS, FAIL, WARN results
echo "--- Result Counts ---"
echo -n "PASS: "; kubectl logs job/kube-bench | grep -c "\[PASS\]"
echo -n "FAIL: "; kubectl logs job/kube-bench | grep -c "\[FAIL\]"
echo -n "WARN: "; kubectl logs job/kube-bench | grep -c "\[WARN\]"

# Look at failed checks specifically
echo ""
echo "--- Failed Checks ---"
kubectl logs job/kube-bench | grep -A 3 "\[FAIL\]"
```

Review the results and note:
1. Which CIS benchmark checks are failing?
2. Do any failures relate to the audit logging configuration we set up?
3. What remediations does kube-bench suggest for the top failures?

### Step 8: Install and Run Polaris

```bash
# Install the Polaris CLI
POLARIS_VERSION=9.0.1
curl -LO "https://github.com/FairwindsOps/polaris/releases/download/${POLARIS_VERSION}/polaris_linux_amd64.tar.gz"
tar -xzf polaris_linux_amd64.tar.gz
sudo mv polaris /usr/local/bin/
rm polaris_linux_amd64.tar.gz

# Run a cluster-wide compliance audit
polaris audit --format=pretty --kubeconfig ~/.kube/config 2>/dev/null | head -80
```

### Step 9: Deploy a Test Workload and Re-Scan

```bash
# Deploy an insecure workload alongside a hardened one
kubectl apply -f labs/lab-10/insecure-deploy-resources.yaml

kubectl wait --for=condition=Available deployment/insecure-deploy -n audit-test --timeout=60s

# Re-run Polaris audit scoped to the test namespace — compare the two deployments
polaris audit --namespace audit-test --format=pretty --kubeconfig ~/.kube/config 2>/dev/null
```

Notice how `insecure-deploy` fails many checks (no resource limits, no security context, uses `latest` tag) while `secure-deploy` passes most checks.

### Step 10: Correlate Polaris Findings with Audit Events

```bash
# The deployments we just created generated audit events — let's see them
echo "=== Deployment Creation Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.resource == "deployments" and .objectRef.namespace == "audit-test" and .verb == "create") |
    "  \(.requestReceivedTimestamp // "") | \(.verb) \(.objectRef.name // "") | user:\(.user.username)"'

# Show a timeline of ALL events in audit-test namespace, sorted by timestamp
echo ""
echo "=== Full Event Timeline (audit-test namespace) ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.namespace == "audit-test") |
    "  \(.requestReceivedTimestamp // "") | \(.verb) \(.objectRef.resource // "")/\(.objectRef.name // "") | \(.user.username)"' | sort | tail -30

# Count events by resource type
echo ""
echo "=== Events by Resource Type ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.namespace == "audit-test") | .objectRef.resource // "unknown"' | sort | uniq -c | sort -rn
```

This demonstrates how audit logging and compliance scanning work together: Polaris tells you *what* is misconfigured, and audit logs tell you *who* deployed it and *when*.

### Step 11: Cleanup

```bash
# Delete the kube-bench job
kubectl delete job kube-bench

# Delete the namespace
kubectl delete namespace audit-test

# (Optional) Delete the cluster
kind delete cluster --name audit-lab
```

## Summary

- Audit logging records API activity and is essential for forensic investigation
- Use jq to query audit logs for secret access, RBAC changes, exec events, and failed requests
- kube-bench runs CIS Kubernetes Benchmark checks and reveals control plane and node configuration gaps
- Polaris scans workloads against security best practices and highlights misconfigurations
- Hardened workloads (non-root, read-only filesystem, resource limits) pass compliance checks that default deployments fail
