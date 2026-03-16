# Lab 9: Runtime Security with Falco

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Install Falco with the eBPF driver on a kind cluster
- Deploy Falcosidekick for alert routing
- Trigger and detect security events in real time
- Write custom Falco rules for specific threat scenarios

## Prerequisites

- Running kind cluster (or create a new one with default config)
- `kubectl` and `helm` CLI configured

## Lab Environment Setup

### Step 1: Create Lab Cluster

```bash
# Create cluster if needed
kind create cluster --name security-lab --config labs/setup/kind-config-default.yaml

# Create lab namespace
kubectl create namespace falco-lab
```

### Step 2: Install Falco with eBPF Driver

In kind clusters, the eBPF driver is more reliable than the kernel module:

```bash
# Add Falco Helm repo
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco with eBPF driver
helm install falco falcosecurity/falco \
  -n falco --create-namespace \
  --set driver.kind=ebpf \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set falcosidekick.webui.service.type=NodePort \
  --set falcosidekick.webui.service.nodePort=30080 \
  --set resources.requests.cpu=100m \
  --set resources.requests.memory=256Mi

# Wait for Falco pods
echo "Waiting for Falco pods..."
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/name=falco -n falco --timeout=180s

echo "Falco installed and running"
kubectl get pods -n falco
```

### Step 3: Verify Falco Is Working

```bash
# Check Falco logs
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=20

# You should see: "Falco initialized with configuration..."
```

## Part 1: Detecting Security Events

### Step 4: Deploy a Test Workload

```bash
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: falco-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-app
  template:
    metadata:
      labels:
        app: vulnerable-app
    spec:
      containers:
        - name: app
          image: ubuntu:22.04
          command: ["sleep", "infinity"]
EOF

kubectl wait --for=condition=Ready pods -l app=vulnerable-app -n falco-lab --timeout=60s
```

### Step 5: Trigger — Shell in Container

```bash
# This should trigger Falco's "Terminal shell in container" rule
VULN_POD=$(kubectl get pod -n falco-lab -l app=vulnerable-app -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n falco-lab $VULN_POD -- bash -c "echo 'shell access detected'"

# Check Falco logs for the alert
sleep 3
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=10 | grep -i "terminal\|shell"
```

### Step 6: Trigger — Reading Sensitive Files

```bash
# Read /etc/shadow (sensitive file read)
kubectl exec -n falco-lab $VULN_POD -- cat /etc/shadow

# Read /etc/passwd
kubectl exec -n falco-lab $VULN_POD -- cat /etc/passwd

# Check Falco logs
sleep 3
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=20 | grep -i "sensitive\|shadow"
```

### Step 7: Trigger — Package Management

```bash
# Install packages (suspicious activity in a running container)
kubectl exec -n falco-lab $VULN_POD -- bash -c "apt-get update && apt-get install -y curl" 2>/dev/null

# Check Falco logs
sleep 3
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=20 | grep -i "package\|dpkg\|apt"
```

### Step 8: Trigger — Writing to /etc

```bash
# Modify files in /etc (filesystem modification)
kubectl exec -n falco-lab $VULN_POD -- bash -c "echo 'malicious' >> /etc/hosts"

# Check Falco logs
sleep 3
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=20 | grep -i "etc\|write"
```

### Step 9: Trigger — Network Activity

```bash
# If curl was installed, make an outbound connection
kubectl exec -n falco-lab $VULN_POD -- bash -c "curl -s http://google.com > /dev/null 2>&1" || true

# Check Falco logs for network-related alerts
sleep 3
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=20 | grep -i "network\|connect\|outbound"
```

## Part 2: Understanding Falco Rules

### Step 10: View Default Rules

```bash
# List the Falco rules files
kubectl exec -n falco $(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}') -- ls /etc/falco/

# View a few key rules
kubectl exec -n falco $(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}') -- cat /etc/falco/falco_rules.yaml | head -100
```

### Step 11: Understand Rule Anatomy

```bash
cat <<'EXPLANATION'
A Falco rule has these components:

- rule: Terminal shell in container
  desc: Detect a shell being spawned inside a container
  condition: >
    spawned_process and
    container and
    shell_procs and
    proc.tty != 0
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name
    shell=%proc.name parent=%proc.pname
    cmdline=%proc.cmdline)
  priority: NOTICE
  tags: [container, shell, mitre_execution]

Components:
  - condition: Sysdig filter expression that triggers the rule
  - output: What to log when the rule fires
  - priority: DEBUG, INFORMATIONAL, NOTICE, WARNING, ERROR, CRITICAL, ALERT, EMERGENCY
  - tags: For categorization and filtering
EXPLANATION
```

## Part 3: Custom Falco Rules

### Step 12: Create Custom Rules

```bash
# Create a ConfigMap with custom rules
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-custom-rules
  namespace: falco
data:
  custom-rules.yaml: |
    # Custom rule: Detect crypto mining indicators
    - rule: Detect Crypto Mining Process
      desc: Detect processes commonly associated with crypto mining
      condition: >
        spawned_process and
        container and
        (proc.name in (xmrig, minerd, minergate, cpuminer) or
         proc.cmdline contains "stratum+tcp" or
         proc.cmdline contains "cryptonight")
      output: >
        Crypto mining process detected
        (user=%user.name container=%container.name
        process=%proc.name cmdline=%proc.cmdline
        image=%container.image.repository)
      priority: CRITICAL
      tags: [container, crypto, mitre_execution]

    # Custom rule: Detect kubectl exec
    - rule: Kubectl Exec Into Pod
      desc: Detect kubectl exec commands
      condition: >
        spawned_process and
        container and
        proc.pname = "runc:[2:INIT]" and
        proc.tty != 0
      output: >
        Interactive exec detected in container
        (user=%user.name container=%container.name
        command=%proc.cmdline image=%container.image.repository
        namespace=%k8s.ns.name pod=%k8s.pod.name)
      priority: WARNING
      tags: [container, kubectl, mitre_execution]

    # Custom rule: Detect sensitive mount
    - rule: Sensitive Mount Detected
      desc: Detect when container has sensitive host paths mounted
      condition: >
        container and evt.type = open and
        (fd.name startswith /host/etc or
         fd.name startswith /host/var/run/docker.sock or
         fd.name startswith /host/root)
      output: >
        Sensitive host path accessed in container
        (user=%user.name container=%container.name
        file=%fd.name image=%container.image.repository)
      priority: ERROR
      tags: [container, filesystem, mitre_persistence]
EOF
```

### Step 13: Apply Custom Rules

```bash
# Extract custom rules into a Helm values file
cat > /tmp/falco-custom-values.yaml <<'EOF'
customRules:
  custom-rules.yaml: |
EOF
kubectl get configmap falco-custom-rules -n falco -o jsonpath='{.data.custom-rules\.yaml}' | sed 's/^/    /' >> /tmp/falco-custom-values.yaml

# Upgrade Falco with custom rules
helm upgrade falco falcosecurity/falco \
  -n falco \
  --set driver.kind=ebpf \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --reuse-values \
  -f /tmp/falco-custom-values.yaml

# Wait for Falco to restart
sleep 15
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/name=falco -n falco --timeout=120s

echo "Custom rules applied"
```

### Step 14: Test Custom Rules

```bash
# Trigger the kubectl exec rule
kubectl exec -n falco-lab $VULN_POD -- whoami

# Check for custom rule alerts
sleep 5
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=20 | grep -i "exec\|interactive"
```

## Part 4: Falcosidekick — Alert Routing

### Step 15: Check Falcosidekick Status

```bash
# View Falcosidekick logs
kubectl logs -l app.kubernetes.io/name=falcosidekick -n falco --tail=20

# Check available output channels
kubectl get pods -n falco -l app.kubernetes.io/name=falcosidekick-ui
```

### Step 16: Access the Falcosidekick UI

```bash
# Port-forward to access the UI
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802:2802 &
PF_PID=$!

echo "Falcosidekick UI available at http://localhost:2802"
echo "Default credentials: admin / admin"
echo ""
echo "Generate some events, then check the UI for alerts"

# Generate some test events
kubectl exec -n falco-lab $VULN_POD -- bash -c "cat /etc/shadow"
kubectl exec -n falco-lab $VULN_POD -- bash -c "ls /root"
sleep 5

echo ""
echo "Check the UI for new alerts"

# Clean up port-forward
kill $PF_PID 2>/dev/null
```

## Part 5: Analyzing Falco Output

### Step 17: Export and Analyze Events

```bash
# Get all Falco alerts from the last few minutes
kubectl logs -l app.kubernetes.io/name=falco -n falco --since=10m | grep -E "^{" | head -20

# Count alerts by priority
echo "=== Alert Summary ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --since=10m | \
  grep -oP '"priority":"[^"]*"' | sort | uniq -c | sort -rn

# Count alerts by rule
echo ""
echo "=== Alerts by Rule ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --since=10m | \
  grep -oP '"rule":"[^"]*"' | sort | uniq -c | sort -rn
```

### Step 18: Create an Alert Summary Report

```bash
echo "============================================"
echo "  Falco Runtime Security Report"
echo "============================================"
echo ""
echo "Cluster: kind-security-lab"
echo "Namespace monitored: falco-lab"
echo "Report time: $(date)"
echo ""
echo "Events Detected:"
echo "  1. Terminal shell spawned in container"
echo "  2. Sensitive file read (/etc/shadow)"
echo "  3. Package management in running container"
echo "  4. Filesystem modification (/etc/hosts)"
echo "  5. Outbound network connection"
echo ""
echo "Recommended Actions:"
echo "  - Investigate shell access to production containers"
echo "  - Block package managers in production images"
echo "  - Use read-only root filesystem"
echo "  - Implement network policies to restrict egress"
echo "  - Enable immutable containers"
```

## Cleanup

```bash
# Delete test workloads
kubectl delete namespace falco-lab

# Uninstall Falco
helm uninstall falco -n falco
kubectl delete namespace falco

# (Optional) Delete the cluster
# kind delete cluster --name security-lab
```

## Summary

In this lab, you:
- Installed Falco with the eBPF driver on a kind cluster
- Triggered and detected multiple security events (shell access, sensitive file reads, package installs, filesystem modifications)
- Wrote custom Falco rules for crypto mining detection and sensitive mount access
- Used Falcosidekick for alert routing and visualization
- Analyzed Falco output and created a security report

Key takeaway: Runtime security detects threats that admission controls and static analysis miss — active exploitation, lateral movement, and unauthorized activity inside running containers.
