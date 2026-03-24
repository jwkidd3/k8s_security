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

### Step 1: Create a Cluster with Audit Logging and Encryption at Rest

For this lab, we use a specialized kind configuration with audit logging **and** encryption at rest pre-configured. First, we generate an encryption key and prepare the config file, then create the cluster.

```bash
# Generate a 32-byte encryption key
ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)

# Write the encryption config (used by the kind extraMounts)
cat > labs/setup/encryption-config.yaml <<EOF
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

echo "Encryption key generated and config written to labs/setup/encryption-config.yaml"

# Review the kind config — note the audit AND encryption settings
cat labs/setup/kind-config-api-hardening.yaml

# Create the kind cluster with audit logging and encryption at rest
kind create cluster --name api-hardening --config labs/setup/kind-config-api-hardening.yaml

# Verify the cluster
kubectl cluster-info --context kind-api-hardening
kubectl get nodes

# Install jq for JSON parsing
sudo yum install -y jq 2>/dev/null || sudo apt-get install -y jq 2>/dev/null
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
docker exec api-hardening-control-plane tail -5 /var/log/kubernetes/audit/audit.log 2>/dev/null | jq .
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
  jq -r 'select(.objectRef.resource == "secrets") |
    "Verb: \(.verb | . + " " * (10 - length)) | User: \(.user.username | . + " " * (30 - length)) | Resource: \(.objectRef.name // "N/A")"'
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

### Step 12: Query Audit Logs with jq

```bash
# Count events by verb
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r '.verb' | sort | uniq -c | sort -rn | awk '{printf "  %s: %s\n", $2, $1}'

# Find all unique users in audit log
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r '.user.username' | sort -u | awk '{printf "  %s\n", $0}'
```

## Part 4: Encryption at Rest

### Step 13: Inspect How Secrets Are Stored in etcd

```bash
# Create a secret and inspect its raw storage in etcd
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

Because encryption at rest was configured at cluster creation, the output should already show encrypted data (look for the `k8s:enc:aescbc:v1:key1:` prefix). Without encryption, the secret value would be visible in plain text.

### Step 14: Review the Pre-Configured Encryption Setup

Because we generated the encryption key and created the config **before** the cluster was created, the kind config mounted the file and passed the `--encryption-provider-config` flag to the API server at boot. No manual manifest patching is needed.

```bash
# Review the encryption config that was mounted into the control plane
docker exec api-hardening-control-plane cat /etc/kubernetes/encryption-config.yaml

# Key things to note:
# - Provider: aescbc (AES-CBC with PKCS#7 padding)
# - Key name: key1
# - Fallback: identity (allows reading unencrypted data written before encryption was enabled)
```

### Step 15: Verify Encryption at Rest Is Active

```bash
# Confirm the API server was started with the encryption-provider-config flag
docker exec api-hardening-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep encryption-provider-config

# Confirm the encryption config volume is mounted
docker exec api-hardening-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -A 2 "encryption-config"

# Verify the API server pod is running and healthy
kubectl get pods -n kube-system -l component=kube-apiserver
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
