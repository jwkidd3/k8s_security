# Lab 1: Auditing Cluster Security

**Duration:** 30 minutes

## Objectives

- Set up a kind cluster for security testing
- Run CIS Kubernetes Benchmark scans with kube-bench
- Scan container images for vulnerabilities with Trivy
- Compare vulnerability surfaces across different base images
- Generate and analyze JSON vulnerability reports
- Identify security misconfigurations in a running workload

## Prerequisites

- AWS account with access to create Cloud9 environments

---

### Step 0: Create Your Cloud9 Environment

1. Open the [AWS Cloud9 Console](https://us-east-1.console.aws.amazon.com/cloud9/) in **us-east-1**
2. Click **Create environment**
3. Configure:
   - **Name:** `kubernetes-security-<your-username>` (e.g., `kubernetes-security-jsmith`)
   - **Environment type:** New EC2 instance
   - **Instance type:** `m5.large`
   - **Platform:** Amazon Linux 2023
   - **Connection:** SSH
   - Leave all other settings as defaults
4. Click **Create**
5. Wait for the environment to be ready, then click **Open** to launch the IDE

### Step 1: Clone the Course Repository

```bash
git clone https://github.com/jwkidd3/kubernetes_security.git
cd kubernetes_security
```

### Step 2: Install Required Tools

```bash
# Install kind
KIND_VERSION=v0.25.0
curl -Lo ./kind https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
kind version

# Install kubectl
KUBECTL_VERSION=$(curl -L -s https://dl.k8s.io/release/stable.txt)
curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/kubectl
kubectl version --client

# Install Trivy
TRIVY_VERSION=0.69.3
curl -LO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
tar xzf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz trivy
sudo mv trivy /usr/local/bin/
rm -f trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz
trivy version

# Install jq
sudo yum install -y jq 2>/dev/null || sudo apt-get install -y jq 2>/dev/null
```

### Step 3: Create a kind Cluster

```bash
# Create the cluster
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

### Step 4: Run kube-bench as a Kubernetes Job

kube-bench checks your cluster against the CIS Kubernetes Benchmark. In kind, we run it as a Job:

```bash
kubectl apply -f labs/lab-01/kube-bench-job.yaml
```

### Step 5: Review kube-bench Results

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

# Look at failed checks with details
kubectl logs job/kube-bench | grep -A 3 "\[FAIL\]"
```

Pick two FAIL results and note the CIS benchmark ID (e.g., 1.2.3), what the check verifies, and the suggested remediation.

### Step 6: Scan Images with Trivy

```bash
# Scan nginx:latest — a full Debian-based image
trivy image --severity HIGH,CRITICAL nginx:latest

# Scan nginx:alpine — a minimal Alpine-based image
trivy image --severity HIGH,CRITICAL nginx:alpine
```

Compare the results. The Alpine-based image will have significantly fewer vulnerabilities because it has a smaller OS footprint. This demonstrates why minimal base images are a security best practice.

### Step 7: Scan a Distroless Image and Compare

Distroless images contain only your application and its runtime dependencies — no shell, no package manager, no OS utilities. This dramatically reduces the attack surface:

```bash
# Scan the distroless static image
trivy image --severity HIGH,CRITICAL gcr.io/distroless/static-debian12:latest

# Compare side-by-side: count total vulnerabilities for each image
echo "=== Vulnerability Comparison ==="
echo -n "nginx:latest       — HIGH+CRITICAL: "
trivy image --severity HIGH,CRITICAL --quiet nginx:latest 2>/dev/null | grep "Total:" | tail -1
echo -n "nginx:alpine       — HIGH+CRITICAL: "
trivy image --severity HIGH,CRITICAL --quiet nginx:alpine 2>/dev/null | grep "Total:" | tail -1
echo -n "distroless/static  — HIGH+CRITICAL: "
trivy image --severity HIGH,CRITICAL --quiet gcr.io/distroless/static-debian12:latest 2>/dev/null | grep "Total:" | tail -1
```

The distroless image should have zero or near-zero vulnerabilities. This image also lacks a shell, which means even if an attacker gains code execution, they cannot easily interact with the container.

### Step 8: Scan All Images Running in the Cluster

In a production environment, you need to audit every image running across all namespaces. This loop discovers and scans them all:

```bash
# Get a list of unique images running in the cluster
echo "=== Images running in the cluster ==="
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u

# Scan each image for HIGH and CRITICAL vulnerabilities
echo ""
echo "=== Scanning all cluster images ==="
for IMAGE in $(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u); do
  echo ""
  echo "--- Scanning: ${IMAGE} ---"
  trivy image --severity HIGH,CRITICAL --no-progress "${IMAGE}" 2>/dev/null | tail -5
done
```

This technique is essential for continuous security monitoring. In production, you would automate this as a scheduled job or integrate it into your CI/CD pipeline.

### Step 9: Generate a JSON Vulnerability Report

Trivy can output structured JSON for programmatic analysis. This is how security teams build dashboards and automated alerting:

```bash
# Generate a JSON report for nginx:latest
trivy image --format json --output /tmp/trivy-nginx-report.json nginx:latest

# Examine the report structure
echo "=== Report Structure ==="
jq 'keys' /tmp/trivy-nginx-report.json

# Count vulnerabilities by severity
echo ""
echo "=== Vulnerability Counts by Severity ==="
jq '[.Results[].Vulnerabilities[]? | .Severity] | group_by(.) | map({severity: .[0], count: length}) | sort_by(.count) | reverse' /tmp/trivy-nginx-report.json

# List all CRITICAL vulnerabilities with CVE ID, package, and installed version
echo ""
echo "=== CRITICAL Vulnerabilities ==="
jq -r '.Results[].Vulnerabilities[]? | select(.Severity == "CRITICAL") | "\(.VulnerabilityID)  \(.PkgName):\(.InstalledVersion)  \(.Title // "No title")"' /tmp/trivy-nginx-report.json

# Find which packages have the most vulnerabilities
echo ""
echo "=== Most Vulnerable Packages (top 10) ==="
jq '[.Results[].Vulnerabilities[]? | .PkgName] | group_by(.) | map({package: .[0], count: length}) | sort_by(.count) | reverse | .[0:10]' /tmp/trivy-nginx-report.json

# Check if any vulnerabilities have known fixes available
echo ""
echo "=== Fixable CRITICAL Vulnerabilities ==="
jq -r '.Results[].Vulnerabilities[]? | select(.Severity == "CRITICAL" and .FixedVersion != null and .FixedVersion != "") | "\(.VulnerabilityID)  \(.PkgName)  Fixed in: \(.FixedVersion)"' /tmp/trivy-nginx-report.json
```

### Step 10: Deploy an Insecure Workload and Identify Issues

```bash
# Deploy an intentionally insecure workload
kubectl apply -f labs/lab-01/insecure-app.yaml

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app=web-app -n insecure-app --timeout=60s

# Check pod security context — is it privileged?
kubectl get pods -n insecure-app -o jsonpath='{range .items[*]}{.metadata.name}: privileged={.spec.containers[0].securityContext.privileged}{"\n"}{end}'

# Check if pods run as root
kubectl exec -n insecure-app deploy/web-app -- id

# Check service account token mounting
kubectl exec -n insecure-app deploy/web-app -- ls /var/run/secrets/kubernetes.io/serviceaccount/

# Check for network policies
kubectl get networkpolicies -n insecure-app
```

You should find four issues: the container runs as privileged, it runs as root (uid=0), the service account token is auto-mounted, and there are no network policies restricting traffic.

### Step 11: Scan the Running Workload Image

Now connect the Trivy scanning to the deployed workload by scanning the exact image the insecure pods are using:

```bash
# Get the image used by the insecure deployment
WORKLOAD_IMAGE=$(kubectl get deployment web-app -n insecure-app -o jsonpath='{.spec.template.spec.containers[0].image}')
echo "Workload image: ${WORKLOAD_IMAGE}"

# Scan it
trivy image --severity HIGH,CRITICAL "${WORKLOAD_IMAGE}"
```

This combines configuration auditing (Steps 10-11) with image scanning — a complete security picture of a running workload.

### Step 12: Cleanup

```bash
# Delete the insecure app
kubectl delete namespace insecure-app

# Delete the kube-bench job
kubectl delete job kube-bench

# Remove the report file
rm -f /tmp/trivy-nginx-report.json

# (Optional) Delete the cluster — keep it if continuing to Lab 2
# kind delete cluster --name security-lab
```

## Summary

- **kube-bench** audits your cluster against CIS Benchmarks and reveals configuration gaps in the control plane and nodes.
- **Trivy** scans container images for known CVEs — Alpine-based and distroless images have far fewer vulnerabilities than full OS images.
- Scanning all images running in a cluster provides a complete vulnerability inventory and should be automated in production.
- JSON output from Trivy enables programmatic analysis with jq for building dashboards, alerts, and compliance reports.
- Running workloads should never use privileged containers, run as root, or auto-mount service account tokens without need.
