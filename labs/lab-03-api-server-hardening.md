# Lab 3: API Server Hardening

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Configure kubelet security settings in a kind cluster
- Enable and configure API server audit logging
- Set up encryption at rest for Kubernetes Secrets
- Test and verify API server authorization modes

## Prerequisites

- Cloud9 environment with Docker
- `kubectl` and `kind` installed
- Familiarity with kubeadm configuration

## Lab Environment Setup

### Step 1: Create a Cluster with Audit Logging

For this lab, we use a specialized kind configuration with audit logging enabled:

```bash
# First, ensure the audit policy file is in place
cat labs/setup/audit-policy.yaml

# Create the kind cluster with audit logging
kind create cluster --name api-hardening --config labs/setup/kind-config-audit.yaml

# Verify the cluster
kubectl cluster-info --context kind-api-hardening
kubectl get nodes
```

## Part 1: Exploring API Server Configuration

### Step 2: Examine the API Server Manifest

```bash
# The API server runs as a static pod — view its manifest
docker exec api-hardening-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml
```

### Step 3: Identify Current Security Settings

```bash
# Extract the command-line arguments
docker exec api-hardening-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -E "^\s+--"

# Key flags to look for:
# --authorization-mode
# --enable-admission-plugins
# --anonymous-auth
# --audit-policy-file
# --audit-log-path
# --encryption-provider-config
```

**Questions:**
1. What authorization modes are enabled?
2. Which admission plugins are active?
3. Is anonymous authentication enabled?

## Part 2: Kubelet Security

### Step 4: Check Current Kubelet Configuration

```bash
# Check kubelet config on the control plane node
docker exec api-hardening-control-plane cat /var/lib/kubelet/config.yaml
```

### Step 5: Verify Kubelet Authentication Settings

```bash
# Check if anonymous authentication is disabled
docker exec api-hardening-control-plane cat /var/lib/kubelet/config.yaml | grep -A 5 "authentication"

# Check authorization mode
docker exec api-hardening-control-plane cat /var/lib/kubelet/config.yaml | grep -A 3 "authorization"
```

### Step 6: Test Kubelet API Access

```bash
# Get the control plane node's IP
CONTROL_PLANE_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' api-hardening-control-plane)

# Try to access the kubelet API (should require authentication)
docker exec api-hardening-control-plane curl -sk https://localhost:10250/pods/ 2>&1 | head -5

# Check the read-only port (should be disabled)
docker exec api-hardening-control-plane curl -s http://localhost:10255/pods/ 2>&1 | head -5
```

### Step 7: Configure Kubelet Security Settings

```bash
# Create a hardened kubelet configuration patch
cat > /tmp/kubelet-config-patch.yaml <<EOF
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
    cacheTTL: 2m0s
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
readOnlyPort: 0
protectKernelDefaults: false
eventRecordQPS: 5
EOF

echo "Kubelet hardening configuration created."
echo "Key settings:"
echo "  - Anonymous auth: disabled"
echo "  - Webhook authentication: enabled"
echo "  - Webhook authorization: enabled"
echo "  - Read-only port: disabled (0)"
```

## Part 3: Audit Logging

### Step 8: Verify Audit Logging Is Active

```bash
# Check if audit logs are being written
docker exec api-hardening-control-plane ls -la /var/log/kubernetes/audit/

# View recent audit log entries
docker exec api-hardening-control-plane tail -5 /var/log/kubernetes/audit/audit.log 2>/dev/null | python3 -m json.tool
```

### Step 9: Generate Audit Events

```bash
# Create some resources to generate audit events
kubectl create namespace audit-test
kubectl create secret generic test-secret -n audit-test --from-literal=password=supersecret
kubectl get secrets -n audit-test
kubectl delete secret test-secret -n audit-test
```

### Step 10: Analyze Audit Logs

```bash
# Find audit events for secret operations
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  python3 -c "
import json, sys
for line in sys.stdin:
    try:
        event = json.loads(line.strip())
        resource = event.get('objectRef', {}).get('resource', '')
        if resource == 'secrets':
            print(f\"Verb: {event['verb']:10s} | User: {event['user']['username']:30s} | Resource: {event['objectRef'].get('name', 'N/A')}\")
    except:
        pass
"
```

### Step 11: Understand Audit Policy Levels

```bash
# View the current audit policy
docker exec api-hardening-control-plane cat /etc/kubernetes/audit/audit-policy.yaml

# Create a more detailed audit policy for testing
cat > /tmp/enhanced-audit-policy.yaml <<EOF
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Don't log read-only health checks
  - level: None
    nonResourceURLs:
      - /healthz*
      - /readyz*
      - /livez*

  # Log all secret operations at RequestResponse level
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]

  # Log RBAC changes at RequestResponse level
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

  # Log pod exec at RequestResponse level
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach"]

  # Log namespace operations
  - level: Metadata
    resources:
      - group: ""
        resources: ["namespaces"]

  # Default: log at Metadata level
  - level: Metadata
    omitStages:
      - RequestReceived
EOF

echo "Enhanced audit policy created at /tmp/enhanced-audit-policy.yaml"
echo "This policy provides detailed logging for:"
echo "  - Secret access (full request/response)"
echo "  - RBAC changes (full request/response)"
echo "  - Pod exec/attach (full request/response)"
echo "  - Namespace operations (metadata only)"
```

### Step 12: Query Audit Logs with jq-style Analysis

```bash
# Count events by verb
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  python3 -c "
import json, sys
from collections import Counter
verbs = Counter()
for line in sys.stdin:
    try:
        event = json.loads(line.strip())
        verbs[event['verb']] += 1
    except:
        pass
for verb, count in verbs.most_common():
    print(f'  {verb}: {count}')
"

# Find all unique users in audit log
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  python3 -c "
import json, sys
users = set()
for line in sys.stdin:
    try:
        event = json.loads(line.strip())
        users.add(event['user']['username'])
    except:
        pass
for user in sorted(users):
    print(f'  {user}')
"
```

## Part 4: Encryption at Rest

### Step 13: Check Current Encryption Status

```bash
# Read a secret and check how it's stored in etcd
kubectl create secret generic encryption-test -n audit-test --from-literal=api-key=my-super-secret-key

# Access etcd directly to see how the secret is stored
docker exec api-hardening-control-plane sh -c \
  'ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/audit-test/encryption-test' | hexdump -C | head -20
```

Notice: The secret value is stored in plain text (base64-decoded) in etcd.

### Step 14: Create an Encryption Configuration

```bash
# Generate an encryption key
ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)

# Create the encryption configuration
cat > /tmp/encryption-config.yaml <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: ${ENCRYPTION_KEY}
      - identity: {}
EOF

echo "Encryption configuration created."
echo "Provider: aescbc (AES-CBC with PKCS#7 padding)"
echo "Key name: key1"
```

### Step 15: Apply Encryption at Rest

```bash
# Copy the encryption config into the control plane container
docker cp /tmp/encryption-config.yaml api-hardening-control-plane:/etc/kubernetes/encryption-config.yaml

# Add the encryption provider config flag to the API server
# In kind, we modify the static pod manifest
docker exec api-hardening-control-plane sh -c '
  # Backup the original manifest
  cp /etc/kubernetes/manifests/kube-apiserver.yaml /etc/kubernetes/kube-apiserver.yaml.backup

  # Check if the flag already exists
  if ! grep -q "encryption-provider-config" /etc/kubernetes/manifests/kube-apiserver.yaml; then
    # Add the flag and volume mount using sed
    sed -i "/--etcd-servers/a\\    - --encryption-provider-config=/etc/kubernetes/encryption-config.yaml" /etc/kubernetes/manifests/kube-apiserver.yaml

    # Add volume mount
    sed -i "/volumeMounts:/a\\    - mountPath: /etc/kubernetes/encryption-config.yaml\\n      name: encryption-config\\n      readOnly: true" /etc/kubernetes/manifests/kube-apiserver.yaml

    # Add volume
    sed -i "/volumes:/a\\  - hostPath:\\n      path: /etc/kubernetes/encryption-config.yaml\\n      type: File\\n    name: encryption-config" /etc/kubernetes/manifests/kube-apiserver.yaml
  fi
'

echo "Waiting for API server to restart..."
sleep 30

# Wait for the API server to come back
kubectl wait --for=condition=Ready node/api-hardening-control-plane --timeout=120s 2>/dev/null || true
kubectl get nodes
```

### Step 16: Verify Encryption at Rest

```bash
# Create a new secret (this will be encrypted)
kubectl create secret generic encrypted-secret -n audit-test --from-literal=password=this-should-be-encrypted

# Check etcd — the new secret should be encrypted
docker exec api-hardening-control-plane sh -c \
  'ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/audit-test/encrypted-secret' | hexdump -C | head -20

# The output should show "k8s:enc:aescbc:v1:key1:" prefix instead of plain text

# Verify we can still read the secret through the API
kubectl get secret encrypted-secret -n audit-test -o jsonpath='{.data.password}' | base64 -d
echo ""
```

### Step 17: Encrypt Existing Secrets

```bash
# Re-encrypt all existing secrets
kubectl get secrets --all-namespaces -o json | kubectl replace -f -

echo "All existing secrets have been re-encrypted with the new encryption key."
```

## Part 5: Testing Authorization Modes

### Step 18: Understand Authorization Mode Ordering

```bash
# Check current authorization modes
docker exec api-hardening-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep authorization-mode

# Typical order: Node,RBAC
# Node: authorizes kubelet API requests
# RBAC: authorizes all other requests based on roles/bindings
```

### Step 19: Test Node Authorization

```bash
# Node authorization allows kubelets to:
# - Read services, endpoints, nodes, pods
# - Write node status, pod status
# - Create events

# Check what the kubelet's node identity can do
kubectl auth can-i get pods --as system:node:api-hardening-control-plane
kubectl auth can-i create pods --as system:node:api-hardening-control-plane
kubectl auth can-i get secrets --as system:node:api-hardening-control-plane
```

## Cleanup

```bash
# Delete lab resources
kubectl delete namespace audit-test

# (Optional) Delete the cluster
kind delete cluster --name api-hardening
```

## Summary

In this lab, you:
- Explored API server configuration and security flags
- Verified and hardened kubelet security settings
- Configured and analyzed API server audit logging
- Set up encryption at rest for Kubernetes Secrets
- Tested and understood API server authorization modes

Key takeaway: The API server is the central control point for Kubernetes security. Proper configuration of authentication, authorization, audit logging, and encryption at rest are foundational security controls.
