# Lab 1: Auditing Cluster Security

**Duration:** 45 minutes

## Objectives

By the end of this lab, you will be able to:

- Set up a kind cluster for security testing
- Run CIS Kubernetes Benchmark scans with kube-bench
- Scan container images for vulnerabilities with Trivy
- Identify and prioritize security findings
- Understand the baseline security posture of a default cluster

## Prerequisites

- Cloud9 environment with Docker installed
- `kubectl` CLI installed
- `kind` CLI installed

## Lab Environment Setup

### Step 1: Install Required Tools

```bash
# Install kind (if not already installed)
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Install kubectl (if not already installed)
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/kubectl

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin

# Install kube-bench
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.7.1/kube-bench_0.7.1_linux_amd64.tar.gz | tar xz
sudo mv kube-bench /usr/local/bin/
```

### Step 2: Create a kind Cluster

```bash
# Create the cluster using our default config
kind create cluster --name security-lab --config labs/setup/kind-config-default.yaml

# Verify the cluster is running
kubectl cluster-info --context kind-security-lab
kubectl get nodes
```

Expected output:
```
NAME                          STATUS   ROLES           AGE   VERSION
security-lab-control-plane    Ready    control-plane   60s   v1.28.x
security-lab-worker           Ready    <none>          30s   v1.28.x
security-lab-worker2          Ready    <none>          30s   v1.28.x
```

## Part 1: CIS Benchmark Scanning with kube-bench

### Step 3: Run kube-bench Inside the Cluster

kube-bench checks your cluster against the CIS Kubernetes Benchmark. In kind, we run it as a Job:

```bash
# Run kube-bench as a Kubernetes Job
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
          command: ["kube-bench", "run", "--targets", "master,node,policies"]
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
```

### Step 4: Review kube-bench Results

```bash
# Wait for the job to complete
kubectl wait --for=condition=complete job/kube-bench --timeout=120s

# View the results
kubectl logs job/kube-bench
```

### Step 5: Analyze the Findings

Look for these key sections in the output:

```bash
# Get a summary of results
kubectl logs job/kube-bench | grep -E "^\[|^== Summary"

# Count PASS, FAIL, WARN results
kubectl logs job/kube-bench | grep -c "\[PASS\]"
kubectl logs job/kube-bench | grep -c "\[FAIL\]"
kubectl logs job/kube-bench | grep -c "\[WARN\]"
```

**Questions to answer:**
1. How many checks passed, failed, and generated warnings?
2. Which control plane checks failed? Are any critical?
3. What is the most common category of failures?

### Step 6: Examine Specific Failures

```bash
# Look at failed checks in detail
kubectl logs job/kube-bench | grep -A 3 "\[FAIL\]"
```

Pick two FAIL results and note:
- The CIS benchmark ID (e.g., 1.2.3)
- What the check verifies
- The suggested remediation

## Part 2: Image Vulnerability Scanning with Trivy

### Step 7: Scan Common Kubernetes Images

```bash
# Scan the nginx image (commonly used)
trivy image --severity HIGH,CRITICAL nginx:latest

# Scan the default pause image used by Kubernetes
trivy image --severity HIGH,CRITICAL registry.k8s.io/pause:3.9

# Scan a known-vulnerable image
trivy image --severity HIGH,CRITICAL nginx:1.16
```

### Step 8: Compare Image Security

```bash
# Scan a minimal/distroless image
trivy image --severity HIGH,CRITICAL gcr.io/distroless/static-debian12:latest

# Scan an Alpine-based image
trivy image --severity HIGH,CRITICAL nginx:alpine
```

**Questions to answer:**
1. How do vulnerability counts compare between `nginx:latest` and `nginx:alpine`?
2. How many vulnerabilities does the distroless image have?
3. What is the most common type of vulnerability found?

### Step 9: Scan Images Running in Your Cluster

```bash
# List all images running in the cluster
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u

# Scan each unique image
for img in $(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u); do
  echo "=== Scanning: $img ==="
  trivy image --severity HIGH,CRITICAL --quiet "$img"
  echo ""
done
```

### Step 10: Generate a Vulnerability Report

```bash
# Generate a JSON report for further analysis
trivy image --severity HIGH,CRITICAL --format json --output trivy-report.json nginx:latest

# View summary
cat trivy-report.json | python3 -m json.tool | head -50
```

## Part 3: Deploying and Auditing a Sample Workload

### Step 11: Deploy an Intentionally Insecure Application

```bash
# Deploy an insecure workload
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: insecure-app
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: insecure-app
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
      containers:
        - name: web
          image: nginx:latest
          ports:
            - containerPort: 80
          securityContext:
            privileged: true
            runAsRoot: true
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: insecure-app
automountServiceAccountToken: true
EOF
```

### Step 12: Identify Security Issues

Use what you learned to audit this deployment:

```bash
# Check pod security context
kubectl get pods -n insecure-app -o jsonpath='{range .items[*]}{.metadata.name}: privileged={.spec.containers[0].securityContext.privileged}{"\n"}{end}'

# Check if pods run as root
kubectl exec -n insecure-app deploy/web-app -- id

# Check service account token mounting
kubectl exec -n insecure-app deploy/web-app -- ls /var/run/secrets/kubernetes.io/serviceaccount/

# Check for network policies
kubectl get networkpolicies -n insecure-app
```

**Document the security issues found:**
1. Is the container running as privileged?
2. What user is the container running as?
3. Is the service account token mounted?
4. Are there any network policies?

## Part 4: Creating a Security Audit Report

### Step 13: Compile Your Findings

Create a summary of all security findings across the three areas:

| Category | Tool | Finding | Severity | Remediation |
|----------|------|---------|----------|-------------|
| Cluster Config | kube-bench | (your finding) | (FAIL/WARN) | (remediation) |
| Image Vuln | Trivy | (your finding) | (HIGH/CRITICAL) | (update image) |
| Workload | kubectl | (your finding) | (severity) | (fix config) |

### Step 14: Prioritize Remediation

Order your findings by:
1. **Critical** — immediate action required (privileged containers, critical CVEs)
2. **High** — address within sprint (high CVEs, CIS FAIL results)
3. **Medium** — plan for near-term (CIS WARN results, medium CVEs)

## Cleanup

```bash
# Delete the insecure app
kubectl delete namespace insecure-app

# Delete the kube-bench job
kubectl delete job kube-bench

# (Optional) Delete the cluster
# kind delete cluster --name security-lab
```

> **Note:** Keep the cluster running if you plan to continue with Lab 2.

## Summary

In this lab, you:
- Created a kind cluster for security testing
- Ran CIS Benchmark scans with kube-bench and analyzed the results
- Scanned container images with Trivy to identify vulnerabilities
- Audited a running workload for security misconfigurations
- Created a prioritized security audit report

These tools and techniques form the foundation of Kubernetes security auditing that you will build upon throughout the course.
