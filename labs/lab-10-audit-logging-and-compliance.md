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

### Step 2: Install jq for JSON Parsing

```bash
# Install jq for JSON parsing
sudo yum install -y jq 2>/dev/null || sudo apt-get install -y jq 2>/dev/null
```

### Step 3: Verify Audit Logging Is Active

```bash
# Check the API server has audit flags
docker exec audit-lab-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep audit

# Check audit log file exists
docker exec audit-lab-control-plane ls -la /var/log/kubernetes/audit/

# View recent audit events (formatted)
docker exec audit-lab-control-plane tail -3 /var/log/kubernetes/audit/audit.log | jq .
```

## Part 1: Audit Policy Configuration

### Step 4: Review the Current Audit Policy

```bash
docker exec audit-lab-control-plane cat /etc/kubernetes/audit/audit-policy.yaml
```

### Step 5: Understand Audit Levels

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

### Step 6: Create an Enhanced Audit Policy

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

### Step 7: Apply the Enhanced Audit Policy

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

### Step 8: Generate Security-Relevant Events

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

### Step 9: Analyze Secret Access Events

```bash
echo "=== Secret Access Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.resource == "secrets") |
    "  \(.verb | . + " " * (8 - length)) | \(.user.username | . + " " * ([30 - length, 0] | max)) | \(.objectRef.namespace // "")/\(.objectRef.name // "") | \(.responseStatus.code // "")"'
```

### Step 10: Analyze RBAC Change Events

```bash
echo "=== RBAC Change Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.apiGroup == "rbac.authorization.k8s.io") |
    "  \(.verb | . + " " * (8 - length)) | \(.objectRef.resource | . + " " * ([20 - length, 0] | max)) | \(.objectRef.name // "" | . + " " * ([25 - length, 0] | max)) | \(.user.username)"'
```

### Step 11: Analyze Pod Exec Events

```bash
echo "=== Pod Exec Events ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.subresource == "exec" or .objectRef.subresource == "attach") |
    "  \(.verb | . + " " * (8 - length)) | \(.user.username | . + " " * ([30 - length, 0] | max)) | \(.objectRef.namespace // "")/\(.objectRef.name // "") | \(.requestURI // "")"'
```

### Step 12: Build a Suspicious Activity Query

```bash
echo "=== Suspicious Activity Detection ==="
docker exec audit-lab-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r '
    # Flag: secret access by non-system users
    (if .objectRef.resource == "secrets" and (.user.username | startswith("system:") | not)
     then "  [!] SECRET ACCESS: \(.user.username) \(.verb) \(.objectRef.namespace // "")/\(.objectRef.name // "")"
     else empty end),
    # Flag: RBAC modifications
    (if .objectRef.apiGroup == "rbac.authorization.k8s.io" and (.verb == "create" or .verb == "update" or .verb == "patch" or .verb == "delete")
     then "  [!] RBAC CHANGE: \(.user.username) \(.verb) \(.objectRef.resource // "") \(.objectRef.name // "")"
     else empty end),
    # Flag: pod exec
    (if .objectRef.subresource == "exec"
     then "  [!] POD EXEC: \(.user.username) into \(.objectRef.namespace // "")/\(.objectRef.name // "")"
     else empty end)
  ' | tee /tmp/suspicious_events.txt

echo ""
echo "  Total suspicious events: $(wc -l < /tmp/suspicious_events.txt | tr -d ' ')"
```

## Part 3: CIS Benchmark Scanning with kube-bench

### Step 13: Run kube-bench

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

### Step 14: Analyze CIS Benchmark Results

```bash
# Get summary
echo "=== CIS Benchmark Summary ==="
kubectl logs job/kube-bench | jq -r '
  .Controls[] |
  .text as $desc |
  [.tests[].results[] | .status] |
  {desc: $desc,
   PASS: (map(select(. == "PASS")) | length),
   FAIL: (map(select(. == "FAIL")) | length),
   WARN: (map(select(. == "WARN")) | length),
   INFO: (map(select(. == "INFO")) | length)} |
  "  \($desc): PASS=\(.PASS) FAIL=\(.FAIL) WARN=\(.WARN) INFO=\(.INFO)"
'
kubectl logs job/kube-bench | jq -r '
  [.Controls[].tests[].results[] | .status] |
  {PASS: (map(select(. == "PASS")) | length),
   FAIL: (map(select(. == "FAIL")) | length),
   WARN: (map(select(. == "WARN")) | length),
   INFO: (map(select(. == "INFO")) | length)} |
  "\n  TOTAL: PASS=\(.PASS) FAIL=\(.FAIL) WARN=\(.WARN) INFO=\(.INFO)"
'

# Show failed checks
echo ""
echo "=== Failed Checks ==="
kubectl logs job/kube-bench | jq -r '
  [.Controls[].tests[].results[] | select(.status == "FAIL")] |
  .[] |
  "  [\(.test_number)] \(.test_desc)\n    Remediation: \(.remediation // "" | .[0:120])...\n"
' | head -60
```

## Part 4: Polaris Compliance Checking

### Step 15: Install Polaris

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

### Step 16: Run Polaris Audit

```bash
# Install the Polaris CLI for command-line auditing
curl -LO https://github.com/FairwindsOps/polaris/releases/download/9.0.1/polaris_linux_amd64.tar.gz
tar -xzf polaris_linux_amd64.tar.gz
sudo mv polaris /usr/local/bin/
rm polaris_linux_amd64.tar.gz

# Run an audit
polaris audit --format=pretty --kubeconfig ~/.kube/config 2>/dev/null | head -80
```

### Step 17: Deploy Test Workloads and Re-Audit

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

### Step 18: Generate Compliance Summary

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
kubectl logs job/kube-bench 2>/dev/null | jq -r '
  [.Controls[].tests[].results[] | .status] |
  {p: (map(select(. == "PASS")) | length),
   f: (map(select(. == "FAIL")) | length),
   w: (map(select(. == "WARN")) | length)} |
  "  Pass: \(.p)  Fail: \(.f)  Warn: \(.w)\n  Score: \(if (.p + .f + .w) > 0 then ((.p * 1000 / (.p + .f + .w) | round) / 10) else 0 end)%"
' 2>/dev/null || echo "  Unable to parse results"
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
