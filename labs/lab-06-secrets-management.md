# Lab 6: Secrets Management

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Configure encryption at rest for Kubernetes Secrets
- Compare volume mounts vs environment variable approaches for secret consumption
- Install and use Bitnami Sealed Secrets for GitOps-friendly secret management
- Implement RBAC controls to restrict secret access

## Prerequisites

- Running kind cluster (or create a new one with default config)
- `kubectl` CLI configured
- `helm` CLI installed (for Sealed Secrets)

## Lab Environment Setup

### Step 1: Create Lab Cluster and Namespace

```bash
# Create cluster if needed
kind create cluster --name security-lab --config labs/setup/kind-config-default.yaml

# Create lab namespace
kubectl create namespace secrets-lab

# Install Helm if not already installed
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

## Part 1: Kubernetes Secrets Fundamentals

### Step 2: Create Secrets and Understand Base64

```bash
# Create a secret using kubectl
kubectl create secret generic db-credentials \
  -n secrets-lab \
  --from-literal=username=admin \
  --from-literal=password='S3cur3P@ssw0rd!'

# View the secret — values are base64-encoded, NOT encrypted
kubectl get secret db-credentials -n secrets-lab -o yaml

# Decode the values — this is trivial
kubectl get secret db-credentials -n secrets-lab -o jsonpath='{.data.username}' | base64 -d
echo ""
kubectl get secret db-credentials -n secrets-lab -o jsonpath='{.data.password}' | base64 -d
echo ""
```

**Key lesson:** Base64 encoding is NOT encryption. Anyone with access to read secrets can decode them.

### Step 3: Examine How Secrets Are Stored in etcd

```bash
# Read the secret directly from etcd
docker exec security-lab-control-plane sh -c \
  'ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/secrets-lab/db-credentials' | hexdump -C | head -30

# You can see the secret values in plain text in etcd
```

## Part 2: Volume Mounts vs Environment Variables

### Step 4: Mount Secrets as Volumes

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: secret-volume-pod
  namespace: secrets-lab
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
      volumeMounts:
        - name: db-creds
          mountPath: /etc/secrets
          readOnly: true
  volumes:
    - name: db-creds
      secret:
        secretName: db-credentials
        defaultMode: 0400
EOF

kubectl wait --for=condition=Ready pod/secret-volume-pod -n secrets-lab --timeout=60s

# Read the mounted secrets
kubectl exec -n secrets-lab secret-volume-pod -- ls -la /etc/secrets/
kubectl exec -n secrets-lab secret-volume-pod -- cat /etc/secrets/username
echo ""
kubectl exec -n secrets-lab secret-volume-pod -- cat /etc/secrets/password
echo ""

# Secrets mounted as volumes are stored in tmpfs (memory, not disk)
kubectl exec -n secrets-lab secret-volume-pod -- df -T /etc/secrets
```

### Step 5: Mount Secrets as Environment Variables

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: secret-env-pod
  namespace: secrets-lab
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
      env:
        - name: DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: username
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
EOF

kubectl wait --for=condition=Ready pod/secret-env-pod -n secrets-lab --timeout=60s

# Read the environment variables
kubectl exec -n secrets-lab secret-env-pod -- env | grep DB_

# Risk: env vars appear in process listing and can leak to child processes
kubectl exec -n secrets-lab secret-env-pod -- cat /proc/1/environ | tr '\0' '\n' | grep DB_
```

### Step 6: Compare the Two Approaches

```bash
echo "=== Volume Mount Advantages ==="
echo "  - Stored in tmpfs (memory)"
echo "  - Can be updated without pod restart (eventual consistency)"
echo "  - File permissions can be set (0400)"
echo "  - Less likely to leak in logs/crash dumps"
echo ""
echo "=== Environment Variable Risks ==="
echo "  - Visible in /proc/<pid>/environ"
echo "  - Inherited by child processes"
echo "  - Often logged by application frameworks"
echo "  - Cannot be updated without pod restart"
echo "  - May appear in docker inspect output"
```

## Part 3: Encryption at Rest

### Step 7: Configure Encryption at Rest

```bash
# Generate encryption key
ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)

# Create encryption configuration
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

# Copy into control plane and configure API server
docker cp /tmp/encryption-config.yaml security-lab-control-plane:/etc/kubernetes/encryption-config.yaml

# Patch the API server manifest
docker exec security-lab-control-plane sh -c '
  if ! grep -q "encryption-provider-config" /etc/kubernetes/manifests/kube-apiserver.yaml; then
    sed -i "/--etcd-servers/a\\    - --encryption-provider-config=/etc/kubernetes/encryption-config.yaml" /etc/kubernetes/manifests/kube-apiserver.yaml
    sed -i "/volumeMounts:/a\\    - mountPath: /etc/kubernetes/encryption-config.yaml\\n      name: encryption-config\\n      readOnly: true" /etc/kubernetes/manifests/kube-apiserver.yaml
    sed -i "/volumes:/a\\  - hostPath:\\n      path: /etc/kubernetes/encryption-config.yaml\\n      type: File\\n    name: encryption-config" /etc/kubernetes/manifests/kube-apiserver.yaml
  fi
'

echo "Waiting for API server to restart..."
sleep 30
kubectl get nodes --timeout=120s
```

### Step 8: Verify Encryption Works

```bash
# Create a new secret
kubectl create secret generic encrypted-test -n secrets-lab --from-literal=key=encrypted-value

# Check etcd — should see encrypted data
docker exec security-lab-control-plane sh -c \
  'ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/secrets-lab/encrypted-test' | hexdump -C | head -10

# Should see "k8s:enc:aescbc:v1:key1:" prefix

# Verify the secret is still readable via API
kubectl get secret encrypted-test -n secrets-lab -o jsonpath='{.data.key}' | base64 -d
echo ""
```

## Part 4: Sealed Secrets for GitOps

### Step 9: Install Sealed Secrets Controller

```bash
# Install Sealed Secrets via Helm
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm repo update

helm install sealed-secrets sealed-secrets/sealed-secrets \
  -n kube-system \
  --set resources.requests.cpu=50m \
  --set resources.requests.memory=64Mi

# Wait for the controller to be ready
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/name=sealed-secrets -n kube-system --timeout=120s

# Install kubeseal CLI
KUBESEAL_VERSION=0.24.5
curl -OL "https://github.com/bitnami-labs/sealed-secrets/releases/download/v${KUBESEAL_VERSION}/kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz"
tar -xzf kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz
sudo mv kubeseal /usr/local/bin/
rm kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz
```

### Step 10: Create a Sealed Secret

```bash
# Create a regular secret manifest (do NOT apply this)
cat > /tmp/my-secret.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-credentials
  namespace: secrets-lab
type: Opaque
stringData:
  api-key: "my-super-secret-api-key-12345"
  api-secret: "another-secret-value-67890"
EOF

# Seal it using kubeseal
kubeseal --format yaml < /tmp/my-secret.yaml > /tmp/sealed-secret.yaml

# View the sealed secret — this is safe to commit to git
cat /tmp/sealed-secret.yaml

# Apply the sealed secret
kubectl apply -f /tmp/sealed-secret.yaml

# The controller will decrypt it into a regular secret
sleep 5
kubectl get secret api-credentials -n secrets-lab
kubectl get secret api-credentials -n secrets-lab -o jsonpath='{.data.api-key}' | base64 -d
echo ""

# Clean up the plain-text file
rm /tmp/my-secret.yaml
```

### Step 11: Understand the Sealed Secret Flow

```bash
echo "Sealed Secrets GitOps Flow:"
echo "1. Developer creates a Secret YAML locally"
echo "2. kubeseal encrypts it with the cluster's public key"
echo "3. The SealedSecret YAML is committed to git (safe!)"
echo "4. GitOps tool (Flux/ArgoCD) applies the SealedSecret"
echo "5. Controller decrypts it into a regular Secret"
echo ""
echo "Key point: Only the cluster's private key can decrypt."
echo "The SealedSecret is safe to store in version control."

# Verify: modifying a sealed secret breaks it
cat /tmp/sealed-secret.yaml | sed 's/encryptedData:/encryptedData:\n  tampered: dGFtcGVyZWQ=/' > /tmp/tampered-sealed-secret.yaml
# The controller will reject tampered values
```

## Part 5: RBAC for Secrets

### Step 12: Create Restrictive RBAC for Secrets

```bash
# Create a service account that can only read specific secrets
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: secrets-lab
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: secrets-lab
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["db-credentials"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-secret-reader
  namespace: secrets-lab
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: secrets-lab
roleRef:
  kind: Role
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
EOF
```

### Step 13: Test Secret RBAC

```bash
# Can read the allowed secret
kubectl auth can-i get secrets/db-credentials -n secrets-lab --as system:serviceaccount:secrets-lab:app-sa
# Expected: yes

# Cannot read other secrets
kubectl auth can-i get secrets/api-credentials -n secrets-lab --as system:serviceaccount:secrets-lab:app-sa
# Expected: no

# Cannot list all secrets
kubectl auth can-i list secrets -n secrets-lab --as system:serviceaccount:secrets-lab:app-sa
# Expected: no

# Cannot create or delete secrets
kubectl auth can-i create secrets -n secrets-lab --as system:serviceaccount:secrets-lab:app-sa
# Expected: no
```

### Step 14: Disable Auto-Mounted Service Account Tokens

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-token-pod
  namespace: secrets-lab
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: false
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
EOF

kubectl wait --for=condition=Ready pod/no-token-pod -n secrets-lab --timeout=60s

# Verify no token is mounted
kubectl exec -n secrets-lab no-token-pod -- ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1
# Expected: No such file or directory
```

## Cleanup

```bash
kubectl delete namespace secrets-lab
rm -f /tmp/sealed-secret.yaml /tmp/tampered-sealed-secret.yaml /tmp/encryption-config.yaml

# (Optional) Delete the cluster
# kind delete cluster --name security-lab
```

## Summary

In this lab, you:
- Demonstrated that base64-encoded secrets are not encrypted
- Compared volume mounts (preferred) vs environment variables (risky) for secrets
- Configured encryption at rest using EncryptionConfiguration
- Installed Sealed Secrets and created GitOps-safe encrypted secrets
- Implemented RBAC controls restricting secret access to specific resources

Key takeaway: Secrets require multiple layers of protection — encryption at rest, RBAC restrictions, secure consumption patterns, and GitOps-safe workflows.
