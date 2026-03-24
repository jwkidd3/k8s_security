# Lab 3: API Server Hardening

**Duration:** 40 minutes

## Objectives

- Examine API server security configuration and flags
- Understand audit policy levels and how they control logging granularity
- Verify audit logging and analyze audit events with advanced jq queries
- Confirm encryption at rest for Kubernetes Secrets and re-encrypt existing secrets
- Test kubelet API access and verify authentication is required
- Test API server authorization modes

## Prerequisites

- Cloud9 environment from Lab 1 (m5.large, us-east-1)
- Tools installed from Lab 1 (`kind`, `kubectl`, `jq`)

---

### Step 1: Create a Cluster with Audit Logging and Encryption

This lab uses a specialized kind configuration with audit logging and encryption at rest pre-configured. First generate an encryption key, then create the cluster:

```bash
cd kubernetes_security

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

echo "Encryption config written to labs/setup/encryption-config.yaml"

# Review the kind config — note the audit AND encryption settings
cat labs/setup/kind-config-api-hardening.yaml

# Create the cluster
kind create cluster --name api-hardening --config labs/setup/kind-config-api-hardening.yaml

# Verify the cluster
kubectl cluster-info --context kind-api-hardening
kubectl get nodes
```

### Step 2: Examine API Server Security Configuration

```bash
# View the API server static pod manifest
docker exec api-hardening-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml

# Extract command-line arguments — look for security-relevant flags
docker exec api-hardening-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -E "^\s+--"
```

Key flags to identify:
- `--authorization-mode` (should be Node,RBAC)
- `--enable-admission-plugins`
- `--anonymous-auth`
- `--audit-policy-file` and `--audit-log-path`
- `--encryption-provider-config`

### Step 3: Examine the Audit Policy File

The audit policy controls what events are logged and at what level of detail. Understanding the four audit levels is critical for tuning logging:

```bash
# View the audit policy
docker exec api-hardening-control-plane cat /etc/kubernetes/audit/audit-policy.yaml

# Examine the structure
echo ""
echo "=== Audit Levels Explained ==="
echo "None            - Do not log this event"
echo "Metadata        - Log request metadata (user, timestamp, resource, verb) but not request/response body"
echo "Request         - Log metadata + request body, but not response body"
echo "RequestResponse - Log metadata + request body + response body (most verbose)"
```

Review the policy and identify:
1. Which resources are logged at the `RequestResponse` level? (Typically secrets, configmaps, and RBAC resources)
2. Which resources are set to `Metadata` only? (Often read-heavy resources like pods and events)
3. Are there any resources set to `None`? (Often health check endpoints to reduce noise)

```bash
# Parse the audit policy to see which rules are defined
docker exec api-hardening-control-plane cat /etc/kubernetes/audit/audit-policy.yaml | grep -E "level:|resources:|verbs:|namespaces:" | head -30
```

### Step 4: Verify Audit Logging Is Active

```bash
# Check if audit logs exist
docker exec api-hardening-control-plane ls -la /var/log/kubernetes/audit/

# View recent audit log entries
docker exec api-hardening-control-plane tail -5 /var/log/kubernetes/audit/audit.log 2>/dev/null | jq .

# Check the size of the audit log
docker exec api-hardening-control-plane du -sh /var/log/kubernetes/audit/audit.log
```

### Step 5: Generate and Analyze Audit Events

```bash
# Create resources to generate audit events
kubectl create namespace audit-test
kubectl create secret generic test-secret -n audit-test --from-literal=password=supersecret
kubectl get secrets -n audit-test
kubectl delete secret test-secret -n audit-test

# Find audit events for secret operations
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.objectRef.resource == "secrets") |
    "Verb: \(.verb)  User: \(.user.username)  Resource: \(.objectRef.name // "N/A")"'
```

You should see create, get, list, and delete events for secrets, showing who performed each action.

### Step 6: Advanced Audit Log Analysis with jq

Security teams need to query audit logs for specific patterns during incident investigation. Practice these common queries:

```bash
# Find all failed (403 Forbidden) requests — potential unauthorized access attempts
echo "=== Failed Authorization Attempts (403) ==="
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.responseStatus.code == 403) |
    "User: \(.user.username)  Verb: \(.verb)  Resource: \(.objectRef.resource // "N/A")  Reason: \(.responseStatus.reason // "Forbidden")"' | head -20

# Generate some failed requests to see them in the log
kubectl auth can-i get secrets -n kube-system --as system:anonymous 2>/dev/null
kubectl get secrets -n kube-system --as system:anonymous 2>/dev/null

# Re-query for 403 events
echo ""
echo "=== Recent 403 Events (after test) ==="
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(.responseStatus.code == 403) |
    "\(.stageTimestamp // .requestReceivedTimestamp)  User: \(.user.username)  Verb: \(.verb)  Resource: \(.objectRef.resource // "unknown")"' | tail -10

# Find RBAC-related changes (role, rolebinding, clusterrole, clusterrolebinding modifications)
echo ""
echo "=== RBAC Changes ==="
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r 'select(
    (.objectRef.resource == "roles" or
     .objectRef.resource == "rolebindings" or
     .objectRef.resource == "clusterroles" or
     .objectRef.resource == "clusterrolebindings") and
    (.verb == "create" or .verb == "update" or .verb == "patch" or .verb == "delete")
  ) |
    "\(.stageTimestamp // .requestReceivedTimestamp)  \(.verb) \(.objectRef.resource)/\(.objectRef.name // "N/A")  by \(.user.username)"' | tail -10

# Find all unique users who have accessed the API server
echo ""
echo "=== Unique API Server Users ==="
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r '.user.username' | sort -u

# Summarize operations by verb
echo ""
echo "=== Operations by Verb ==="
docker exec api-hardening-control-plane cat /var/log/kubernetes/audit/audit.log | \
  jq -r '.verb' | sort | uniq -c | sort -rn | head -10
```

These queries are the foundation of Kubernetes security monitoring. In production, you would stream audit logs to a SIEM (Splunk, Elasticsearch) for real-time alerting.

### Step 7: Verify Encryption at Rest

```bash
# Create a secret
kubectl create secret generic encryption-test -n audit-test --from-literal=api-key=my-super-secret-key

# Access etcd directly to see how the secret is stored
docker exec api-hardening-control-plane sh -c \
  'ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/audit-test/encryption-test' | hexdump -C | head -20

# Look for the "k8s:enc:aescbc:v1:key1:" prefix — this confirms the data is encrypted
# Without encryption, the secret value would be visible as plain text

# Verify we can still read the secret through the API (it gets decrypted transparently)
kubectl get secret encryption-test -n audit-test -o jsonpath='{.data.api-key}' | base64 -d
echo ""
```

### Step 8: Re-Encrypt Existing Secrets

When you first enable encryption at rest, only newly created secrets are encrypted. Any secrets that existed before the encryption configuration was applied remain stored in plaintext in etcd. You must re-encrypt them:

```bash
# First, create a secret BEFORE encryption is fully applied to simulate a pre-existing secret
# (In our lab, encryption was enabled at cluster creation, so we simulate the process)

# List all secrets across the cluster
echo "=== All Secrets in the Cluster ==="
kubectl get secrets --all-namespaces --no-headers | head -20

# Re-encrypt all secrets in every namespace
# This reads each secret through the API (decrypting it) and writes it back (re-encrypting with current key)
echo ""
echo "=== Re-encrypting all secrets ==="
kubectl get secrets --all-namespaces -o json | \
  jq -r '.items[] | "\(.metadata.namespace) \(.metadata.name)"' | \
  while read NAMESPACE NAME; do
    kubectl get secret "${NAME}" -n "${NAMESPACE}" -o json | \
      kubectl replace -f - 2>/dev/null && \
      echo "Re-encrypted: ${NAMESPACE}/${NAME}" || \
      echo "Skipped (immutable): ${NAMESPACE}/${NAME}"
  done

# Verify the encryption-test secret is still encrypted in etcd after re-encryption
echo ""
echo "=== Verifying encryption after re-encrypt ==="
docker exec api-hardening-control-plane sh -c \
  'ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/audit-test/encryption-test' | hexdump -C | head -5

# Confirm the encrypted prefix is present
docker exec api-hardening-control-plane sh -c \
  'ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/audit-test/encryption-test' | grep -c "k8s:enc:aescbc" && \
  echo "Encryption confirmed: aescbc prefix found" || \
  echo "WARNING: Encryption prefix not found"
```

In production, after enabling encryption at rest or rotating encryption keys, you must always re-encrypt all existing secrets to ensure none remain stored in plaintext.

### Step 9: Verify Kubelet Security Settings

```bash
# Check kubelet configuration on the control plane node
docker exec api-hardening-control-plane cat /var/lib/kubelet/config.yaml | grep -A 5 "authentication"

# Check authorization mode
docker exec api-hardening-control-plane cat /var/lib/kubelet/config.yaml | grep -A 3 "authorization"
```

Key settings to verify:
- Anonymous authentication should be **disabled**
- Webhook authentication should be **enabled**
- Authorization mode should be **Webhook** (not AlwaysAllow)
- Read-only port should be **0** (disabled)

### Step 10: Test Kubelet API Access

The kubelet exposes an API on port 10250. Verify that authentication is required and anonymous access is blocked:

```bash
# Get the IP address of the control plane node
NODE_IP=$(docker inspect api-hardening-control-plane --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "Control plane node IP: ${NODE_IP}"

# Attempt to access the kubelet API without credentials (should fail with 401 Unauthorized)
echo ""
echo "=== Testing unauthenticated kubelet access ==="
docker exec api-hardening-control-plane curl -sk https://localhost:10250/pods 2>&1 | head -5

# Check if the read-only port (10255) is disabled
echo ""
echo "=== Testing read-only port (should be disabled) ==="
docker exec api-hardening-control-plane curl -s http://localhost:10255/pods 2>&1 | head -5

# Verify the kubelet's read-only port setting
echo ""
echo "=== Read-only port configuration ==="
docker exec api-hardening-control-plane cat /var/lib/kubelet/config.yaml | grep "readOnlyPort"
```

If the kubelet is properly secured:
- HTTPS port 10250 returns `401 Unauthorized` without valid credentials
- HTTP read-only port 10255 is disabled (connection refused)
- This prevents unauthenticated access to pod listings, container logs, and exec capabilities

### Step 11: Test Authorization Modes

```bash
# Check which authorization modes are configured
docker exec api-hardening-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep authorization-mode

# Node authorization — allows kubelets specific access
kubectl auth can-i get pods --as system:node:api-hardening-control-plane
kubectl auth can-i create pods --as system:node:api-hardening-control-plane
kubectl auth can-i get secrets --as system:node:api-hardening-control-plane

# RBAC authorization — test an unauthenticated request
kubectl auth can-i get pods --as system:anonymous
kubectl auth can-i get nodes --as system:anonymous

# Verify that Node and RBAC work together
echo ""
echo "=== Authorization Mode Summary ==="
echo "Node authorizer: grants kubelets read access to pods scheduled on their node"
echo "RBAC authorizer: handles all other authorization based on roles and bindings"
echo "Request flow: Node -> RBAC -> Deny (if no authorizer approves)"
```

The Node authorizer grants kubelets read access to pods and limited access to other resources. RBAC handles all other authorization decisions. Requests are evaluated by each authorizer in order — if none approves, the request is denied.

### Step 12: Cleanup

```bash
# Delete lab resources
kubectl delete namespace audit-test

# (Optional) Delete the cluster
kind delete cluster --name api-hardening
```

## Summary

- The API server manifest reveals all security-relevant flags including authorization modes, admission plugins, audit logging, and encryption configuration.
- Audit policies control logging granularity with four levels (None, Metadata, Request, RequestResponse) — tune them to balance security visibility with log volume.
- Audit log analysis with jq enables detection of failed authentication attempts, unauthorized access, and RBAC changes during incident investigation.
- Encryption at rest ensures secrets stored in etcd are encrypted; after enabling encryption or rotating keys, you must re-encrypt all existing secrets.
- Kubelet API security requires disabling anonymous authentication, enabling webhook authorization, and closing the read-only port to prevent unauthenticated access.
