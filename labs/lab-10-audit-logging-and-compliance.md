# Lab 10: Audit Logging & Compliance

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Configure and customize Kubernetes API server audit logging policies
- Generate, collect, and analyze audit log events
- Run CIS Kubernetes Benchmark scans with kube-bench
- Use Polaris for automated compliance checking

## Prerequisites

- Cloud9 environment with Docker
- `kubectl` and `kind` installed

## Lab Environment Setup

### Step 1: Create a Cluster with Audit Logging

```bash
# Create cluster with audit logging enabled
kind create cluster --name audit-lab --config labs/setup/kind-config-audit.yaml

# Verify the cluster
kubectl cluster-info --context kind-audit-lab
kubectl get nodes
```

### Step 2: Verify Audit Logging Is Active

```bash
# Check the API server has audit flags
docker exec audit-lab-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep audit

# Check audit log file exists
docker exec audit-lab-control-plane ls -la /var/log/kubernetes/audit/

# View recent audit events
docker exec audit-lab-control-plane tail -3 /var/log/kubernetes/audit/audit.log | python3 -m json.tool
```

## Part 1: Audit Policy Configuration

### Step 3: Review the Current Audit Policy

```bash
docker exec audit-lab-control-plane cat /etc/kubernetes/audit/audit-policy.yaml
```

### Step 4: Understand Audit Levels

```bash
cat <<'EXPLANATION'
Kubernetes Audit Levels:

  None             - Do not log this event
  Metadata         - Log request metadata (user, timestamp, resource, verb)
                     but not request or response body
  Request          - Log metadata + request body (but not response body)
  RequestResponse  - Log metadata + request body + response body

Best Practices:
  - Use None for health checks and system noise
  - Use Metadata for most resources (good signal-to-noise)
  - Use Request for sensitive resources (secrets, RBAC)
  - Use RequestResponse only when you need the full trail
  - Be careful with RequestResponse on high-volume resources (can fill disk)
EXPLANATION
```

### Step 5: Create an Enhanced Audit Policy

```bash
cat > /tmp/enhanced-audit-policy.yaml <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Skip health checks and API discovery
  - level: None
    nonResourceURLs:
      - /healthz*
      - /readyz*
      - /livez*
      - /openapi*

  # Skip system controller noise
  - level: None
    users:
      - system:kube-proxy
      - system:kube-controller-manager
      - system:kube-scheduler
      - system:serviceaccount:kube-system:*
    verbs: ["get", "list", "watch"]

  # Log all secret operations at Request level (captures who accessed what)
  - level: Request
    resources:
      - group: ""
        resources: ["secrets"]
    omitStages:
      - RequestReceived

  # Log exec/attach/port-forward at RequestResponse level
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # Log all RBAC changes at RequestResponse level
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

  # Log service account token creation
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["serviceaccounts/token"]

  # Log namespace changes
  - level: Metadata
    resources:
      - group: ""
        resources: ["namespaces"]
    verbs: ["create", "delete", "update", "patch"]

  # Log all other changes at Metadata level
  - level: Metadata
    verbs: ["create", "update", "patch", "delete"]
    omitStages:
      - RequestReceived

  # Log reads at None (reduce noise)
  - level: None
    verbs: ["get", "list", "watch"]
EOF

echo "Enhanced audit policy created"
```

### Step 6: Apply the Enhanced Audit Policy

```bash
# Copy into the control plane container
docker cp /tmp/enhanced-audit-policy.yaml audit-lab-control-plane:/etc/kubernetes/audit/audit-policy.yaml

# Restart the API server to pick up the new policy
docker exec audit-lab-control-plane sh -c 'kill $(pgrep kube-apiserver)' 2>/dev/null || true

echo "Waiting for API server to restart..."
sleep 20
kubectl get nodes --timeout=60s
```

## Part 2: Generating and Analyzing Audit Events

### Step 7: Generate Security-Relevant Events

```bash
# Create a namespace
kubectl create namespace audit-test

# Create and access a secret
kubectl create secret generic sensitive-data -n audit-test \
  --from-literal=password=MySecret123 \
  --from-literal=api-key=sk-1234567890

kubectl get secret sensitive-data -n audit-test -o yaml > /dev/null

# Create RBAC resources
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: audit-test-role
  namespace: audit-test
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: audit-test-binding
  namespace: audit-test
subjects:
  - kind: ServiceAccount
    name: default
    namespace: audit-test
roleRef:
  kind: Role
  name: audit-test-role
  apiGroup: rbac.authorization.k8s.io
EOF

# Deploy a pod and exec into it
kubectl run test-pod --image=busybox:1.36 -n audit-test -- sleep 3600
kubectl wait --for=condition=Ready pod/test-pod -n audit-test --timeout=60s
kubectl exec -n audit-test test-pod -- whoami
```

### Step 8: Analyze Secret Access Events

```bash
echo "=== Secret Access Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        ref = e.get('objectRef', {})
        if ref.get('resource') == 'secrets':
            print(f\"  {e['verb']:8s} | {e['user']['username']:30s} | {ref.get('namespace','')}/{ref.get('name','')} | {e.get('responseStatus',{}).get('code','')}\")
    except: pass
"
```

### Step 9: Analyze RBAC Change Events

```bash
echo "=== RBAC Change Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        ref = e.get('objectRef', {})
        if ref.get('apiGroup') == 'rbac.authorization.k8s.io':
            print(f\"  {e['verb']:8s} | {ref.get('resource'):20s} | {ref.get('name',''):25s} | {e['user']['username']}\")
    except: pass
"
```

### Step 10: Analyze Pod Exec Events

```bash
echo "=== Pod Exec Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        ref = e.get('objectRef', {})
        if ref.get('subresource') in ('exec', 'attach'):
            print(f\"  {e['verb']:8s} | {e['user']['username']:30s} | {ref.get('namespace','')}/{ref.get('name','')} | {e.get('requestURI','')}\")
    except: pass
"
```

### Step 11: Build a Suspicious Activity Query

```bash
echo "=== Suspicious Activity Detection ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  python3 -c "
import json, sys
from collections import defaultdict

suspicious = []
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        ref = e.get('objectRef', {})
        user = e['user']['username']
        verb = e['verb']

        # Flag: secret access by non-system users
        if ref.get('resource') == 'secrets' and not user.startswith('system:'):
            suspicious.append(f'SECRET ACCESS: {user} {verb} {ref.get(\"namespace\",\"\")}/{ref.get(\"name\",\"\")}')

        # Flag: RBAC modifications
        if ref.get('apiGroup') == 'rbac.authorization.k8s.io' and verb in ('create','update','patch','delete'):
            suspicious.append(f'RBAC CHANGE: {user} {verb} {ref.get(\"resource\",\"\")} {ref.get(\"name\",\"\")}')

        # Flag: pod exec
        if ref.get('subresource') == 'exec':
            suspicious.append(f'POD EXEC: {user} into {ref.get(\"namespace\",\"\")}/{ref.get(\"name\",\"\")}')

    except: pass

for item in suspicious:
    print(f'  [!] {item}')
print(f'\n  Total suspicious events: {len(suspicious)}')
"
```

## Part 3: CIS Benchmark Scanning with kube-bench

### Step 12: Run kube-bench

```bash
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench
spec:
  template:
    metadata:
      labels:
        app: kube-bench
    spec:
      hostPID: true
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
      containers:
        - name: kube-bench
          image: aquasec/kube-bench:v0.7.1
          command: ["kube-bench", "run", "--targets", "master,node,policies", "--json"]
          volumeMounts:
            - name: var-lib-kubelet
              mountPath: /var/lib/kubelet
              readOnly: true
            - name: etc-kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
      restartPolicy: Never
      volumes:
        - name: var-lib-kubelet
          hostPath:
            path: /var/lib/kubelet
        - name: etc-kubernetes
          hostPath:
            path: /etc/kubernetes
  backoffLimit: 0
EOF

kubectl wait --for=condition=complete job/kube-bench --timeout=120s
```

### Step 13: Analyze CIS Benchmark Results

```bash
# Get summary
echo "=== CIS Benchmark Summary ==="
kubectl logs job/kube-bench | python3 -c "
import json, sys
data = json.load(sys.stdin)
total_pass = total_fail = total_warn = total_info = 0
for control in data.get('Controls', []):
    desc = control.get('text', 'Unknown')
    p = f = w = i = 0
    for group in control.get('tests', []):
        for result in group.get('results', []):
            status = result.get('status', '')
            if status == 'PASS': p += 1
            elif status == 'FAIL': f += 1
            elif status == 'WARN': w += 1
            elif status == 'INFO': i += 1
    total_pass += p; total_fail += f; total_warn += w; total_info += i
    print(f'  {desc}: PASS={p} FAIL={f} WARN={w} INFO={i}')
print(f'\n  TOTAL: PASS={total_pass} FAIL={total_fail} WARN={total_warn} INFO={total_info}')
"

# Show failed checks
echo ""
echo "=== Failed Checks ==="
kubectl logs job/kube-bench | python3 -c "
import json, sys
data = json.load(sys.stdin)
for control in data.get('Controls', []):
    for group in control.get('tests', []):
        for result in group.get('results', []):
            if result.get('status') == 'FAIL':
                print(f\"  [{result['test_number']}] {result['test_desc']}\")
                if result.get('remediation'):
                    print(f\"    Remediation: {result['remediation'][:120]}...\")
                print()
" | head -60
```

## Part 4: Polaris Compliance Checking

### Step 14: Install Polaris

```bash
# Install Polaris via Helm
helm repo add fairwinds-stable https://charts.fairwinds.com/stable
helm repo update

helm install polaris fairwinds-stable/polaris \
  -n polaris --create-namespace \
  --set dashboard.service.type=NodePort

# Wait for Polaris
kubectl wait --for=condition=Ready pods --all -n polaris --timeout=120s
```

### Step 15: Run Polaris Audit

```bash
# Install the Polaris CLI for command-line auditing
curl -LO https://github.com/FairwindsOps/polaris/releases/download/9.0.1/polaris_linux_amd64.tar.gz
tar -xzf polaris_linux_amd64.tar.gz
sudo mv polaris /usr/local/bin/
rm polaris_linux_amd64.tar.gz

# Run an audit
polaris audit --format=pretty --kubeconfig ~/.kube/config 2>/dev/null | head -80
```

### Step 16: Deploy Test Workloads and Re-Audit

```bash
# Deploy a poorly configured workload
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-deploy
  namespace: audit-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: insecure
  template:
    metadata:
      labels:
        app: insecure
    spec:
      containers:
        - name: app
          image: nginx:latest
          ports:
            - containerPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-deploy
  namespace: audit-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure
  template:
    metadata:
      labels:
        app: secure
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: nginx:1.25-alpine
          ports:
            - containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            limits:
              cpu: 200m
              memory: 128Mi
            requests:
              cpu: 100m
              memory: 64Mi
          livenessProbe:
            httpGet:
              path: /
              port: 8080
            initialDelaySeconds: 10
          readinessProbe:
            httpGet:
              path: /
              port: 8080
            initialDelaySeconds: 5
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /var/cache/nginx
      volumes:
        - name: tmp
          emptyDir: {}
        - name: cache
          emptyDir: {}
EOF

# Re-run audit on the specific namespace
polaris audit --namespace audit-test --format=pretty --kubeconfig ~/.kube/config 2>/dev/null
```

## Part 5: Compliance Report

### Step 17: Generate Compliance Summary

```bash
echo "============================================"
echo "  Kubernetes Compliance Report"
echo "============================================"
echo ""
echo "Cluster: kind-audit-lab"
echo "Date: $(date)"
echo ""
echo "--- Audit Logging ---"
echo "  Status: Enabled"
docker exec audit-lab-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -c "audit" | xargs -I{} echo "  Audit flags configured: {}"
echo ""
echo "--- CIS Benchmark ---"
kubectl logs job/kube-bench 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    p = f = w = 0
    for c in data.get('Controls', []):
        for g in c.get('tests', []):
            for r in g.get('results', []):
                s = r.get('status', '')
                if s == 'PASS': p += 1
                elif s == 'FAIL': f += 1
                elif s == 'WARN': w += 1
    print(f'  Pass: {p}  Fail: {f}  Warn: {w}')
    score = (p / (p + f + w) * 100) if (p + f + w) > 0 else 0
    print(f'  Score: {score:.1f}%')
except: print('  Unable to parse results')
"
```

## Cleanup

```bash
kubectl delete namespace audit-test
kubectl delete job kube-bench

# Uninstall Polaris
helm uninstall polaris -n polaris
kubectl delete namespace polaris

# (Optional) Delete the cluster
kind delete cluster --name audit-lab
```

## Summary

In this lab, you:
- Configured and customized API server audit policies with appropriate levels
- Generated and analyzed audit log events for secrets, RBAC changes, and pod exec
- Built suspicious activity detection queries against audit logs
- Ran CIS Kubernetes Benchmark scans and analyzed results
- Used Polaris for workload compliance checking

Key takeaway: Audit logging provides the forensic trail needed for compliance and incident investigation. Combine it with automated benchmark scanning for continuous compliance assurance.
