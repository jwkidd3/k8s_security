# Lab 9: Runtime Security with Falco

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Install Falco with the eBPF driver on a kind cluster
- Trigger and detect a variety of security events in real time
- Write custom Falco rules for crypto mining, kubectl exec, and sensitive mount detection
- Access the Falcosidekick UI for event visualization
- Export and analyze Falco alert data by priority and rule

## Prerequisites

- Cloud9 environment from Lab 1 (m5.large, us-east-1)
- Tools installed from Lab 1 (`kind`, `kubectl`)
- `helm` CLI installed (from Lab 6, or run: see install commands in Lab 6 Step 6)

---

### Step 1: Install Falco with eBPF Driver via Helm

```bash
# Create lab namespace
kubectl create namespace falco-lab

# Add Falco Helm repo
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco with eBPF driver and Falcosidekick (with UI)
helm install falco falcosecurity/falco \
  -n falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set resources.requests.cpu=100m \
  --set resources.requests.memory=256Mi

# Wait for Falco pods
echo "Waiting for Falco pods..."
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/name=falco -n falco --timeout=180s

echo "Falco installed and running"
kubectl get pods -n falco
```

### Step 2: Deploy Test Workload

```bash
kubectl apply -f labs/lab-09/test-app-pod.yaml

kubectl wait --for=condition=Ready pod/test-app -n falco-lab --timeout=60s
echo "Test pod is running"
```

### Step 3: Trigger Security Events — Shell Access and Sensitive Files

```bash
# Get the pod name
POD_NAME=test-app

# Trigger 1: Shell in container
kubectl exec -n falco-lab $POD_NAME -- bash -c "echo 'shell access detected'"

# Trigger 2: Read sensitive file
kubectl exec -n falco-lab $POD_NAME -- cat /etc/shadow

# Trigger 3: Install a package (suspicious in a running container)
kubectl exec -n falco-lab $POD_NAME -- bash -c "apt-get update && apt-get install -y curl" 2>/dev/null

echo "Security events triggered. Waiting for Falco to process..."
sleep 5
```

### Step 4: Trigger Additional Security Events — File Writes and Network Connections

```bash
POD_NAME=test-app

# Trigger 4: Write to /etc directory (tampering with system configuration)
kubectl exec -n falco-lab $POD_NAME -- bash -c "echo '# malicious entry' >> /etc/hosts"
echo "Trigger: wrote to /etc/hosts"

# Trigger 5: Write to a new file in /etc
kubectl exec -n falco-lab $POD_NAME -- bash -c "echo 'backdoor' > /etc/cron.d/backdoor"
echo "Trigger: created file in /etc/cron.d"

# Trigger 6: Outbound network connection (potential data exfiltration)
kubectl exec -n falco-lab $POD_NAME -- bash -c "curl -s -o /dev/null --connect-timeout 3 http://example.com || true"
echo "Trigger: outbound network connection attempted"

# Trigger 7: Read sensitive Kubernetes service account token
kubectl exec -n falco-lab $POD_NAME -- bash -c "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo 'No token mounted'"
echo "Trigger: attempted to read service account token"

echo ""
echo "Additional security events triggered. Waiting for Falco to process..."
sleep 5
```

### Step 5: Check Falco Logs for Alerts

```bash
# Check for shell-related alerts
echo "=== Shell Alerts ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=100 | grep -i "terminal\|shell" | tail -5

# Check for sensitive file alerts
echo ""
echo "=== Sensitive File Alerts ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=100 | grep -i "sensitive\|shadow" | tail -5

# Check for package management alerts
echo ""
echo "=== Package Management Alerts ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=100 | grep -i "package\|dpkg\|apt" | tail -5

# Check for file write alerts
echo ""
echo "=== File Write Alerts ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=100 | grep -i "etc\|write\|modify" | tail -5

# Check for network alerts
echo ""
echo "=== Network Alerts ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --tail=100 | grep -i "network\|connect\|outbound" | tail -5
```

### Step 6: Write and Apply Custom Rules

```bash
# Create Helm values file with three custom rules
cat > /tmp/falco-custom-values.yaml <<'EOF'
customRules:
  custom-rules.yaml: |
    - rule: Detect Crypto Mining Process
      desc: Detect processes commonly associated with crypto mining
      condition: >
        spawned_process and container and
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

    - rule: Detect kubectl exec into Container
      desc: Detect when kubectl exec is used to run a command in a container
      condition: >
        spawned_process and container and
        proc.pname = runc:[2:INIT] and
        not proc.name in (sh, bash, ls)
      output: >
        kubectl exec detected in container
        (user=%user.name container=%container.name
        process=%proc.name parent=%proc.pname
        cmdline=%proc.cmdline namespace=%k8s.ns.name
        pod=%k8s.pod.name)
      priority: WARNING
      tags: [container, exec, mitre_execution]

    - rule: Detect Sensitive Mount in Container
      desc: Detect containers that mount sensitive host paths
      condition: >
        container and container.image.repository != "" and
        (fd.name startswith /proc or
         fd.name startswith /sys or
         fd.name startswith /var/run/docker.sock)
      output: >
        Sensitive path accessed in container
        (user=%user.name container=%container.name
        file=%fd.name image=%container.image.repository
        namespace=%k8s.ns.name pod=%k8s.pod.name)
      priority: WARNING
      tags: [container, filesystem, mitre_privilege_escalation]
EOF

# Upgrade Falco with the custom rules
helm upgrade falco falcosecurity/falco \
  -n falco \
  --set driver.kind=modern_ebpf \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --reuse-values \
  -f /tmp/falco-custom-values.yaml

# Wait for Falco to restart with new rules
sleep 15
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/name=falco -n falco --timeout=120s

echo "Custom rules applied: crypto mining, kubectl exec, and sensitive mount detection"
```

### Step 7: Test Custom Rules

```bash
POD_NAME=test-app

# Trigger the kubectl exec rule by running commands in the container
kubectl exec -n falco-lab $POD_NAME -- whoami
kubectl exec -n falco-lab $POD_NAME -- id

# Trigger the sensitive mount rule by accessing /proc
kubectl exec -n falco-lab $POD_NAME -- bash -c "ls /proc/1/status 2>/dev/null || true"

# Wait for Falco to process
sleep 5

# Check for new alerts from custom rules
echo "=== Recent Alerts (last 2 minutes) ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --since=2m | tail -20
```

### Step 8: Access Falcosidekick UI

```bash
# Port-forward to the Falcosidekick UI
echo "Starting port-forward to Falcosidekick UI..."
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802:2802 &
PF_PID=$!

sleep 3

# Verify the UI is accessible
echo "Falcosidekick UI is available at http://localhost:2802"
echo "In a Cloud9 environment, use Preview > Preview Running Application"
echo ""

# Show what the UI provides
echo "The Falcosidekick UI provides:"
echo "  - Real-time event stream from Falco"
echo "  - Event filtering by priority, rule, and source"
echo "  - Event count dashboard"
echo ""

# Check the Falcosidekick health endpoint
curl -s http://localhost:2802/api/v1/healthz 2>/dev/null && echo " - UI health check passed" || echo " - UI not yet available (may take a moment)"

# Kill the port-forward
kill $PF_PID 2>/dev/null
wait $PF_PID 2>/dev/null
echo ""
echo "Port-forward stopped. In production, Falcosidekick forwards events to Slack, PagerDuty, or a SIEM."
```

### Step 9: Export and Analyze Events

```bash
# Export recent Falco events to a file for analysis
kubectl logs -l app.kubernetes.io/name=falco -n falco --since=15m > /tmp/falco-events.log

# Count total alerts
TOTAL=$(grep -c "Warning\|Error\|Critical\|Notice\|Informational" /tmp/falco-events.log 2>/dev/null || echo "0")
echo "=== Total Alerts: ${TOTAL} ==="

# Count alerts by priority
echo ""
echo "=== Alerts by Priority ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --since=15m | \
  grep -oP '"priority":"[^"]*"' | sort | uniq -c | sort -rn

# Count alerts by rule name
echo ""
echo "=== Alerts by Rule ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --since=15m | \
  grep -oP '"rule":"[^"]*"' | sort | uniq -c | sort -rn

# Show the most recent 5 unique alert types
echo ""
echo "=== Most Recent Unique Alert Types ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco --since=15m | \
  grep -oP '"rule":"[^"]*"' | sort -u | tail -10

echo ""
echo "In production, these events feed into a SIEM for correlation with other security data"
```

### Step 10: View Falco Configuration and Rule Statistics

```bash
# Show the loaded rules count
echo "=== Falco Rule Sources ==="
kubectl logs -l app.kubernetes.io/name=falco -n falco | grep -i "rules\|loaded" | head -10

# List all pods being monitored
echo ""
echo "=== Monitored Pods ==="
kubectl get pods --all-namespaces -o wide | grep -v kube-system

# Show Falco DaemonSet details
echo ""
echo "=== Falco DaemonSet ==="
kubectl get daemonset -n falco
echo ""
echo "Falco runs as a DaemonSet so every node in the cluster is monitored"
```

### Step 11: Cleanup

```bash
# Delete test workloads
kubectl delete namespace falco-lab

# Uninstall Falco
helm uninstall falco -n falco
kubectl delete namespace falco

# Remove temp files
rm -f /tmp/falco-custom-values.yaml
rm -f /tmp/falco-events.log
```

## Summary

- Falco with the eBPF driver detects runtime threats like shell access, sensitive file reads, file tampering, and outbound network connections
- Custom rules extend detection to specific threats such as crypto mining processes, kubectl exec usage, and sensitive mount access
- Falcosidekick UI provides a real-time dashboard, and in production forwards events to alerting systems like Slack, PagerDuty, or a SIEM
- Exporting and analyzing events by priority and rule name helps security teams prioritize response efforts
- Runtime security catches active exploitation that static analysis and admission controls cannot detect
