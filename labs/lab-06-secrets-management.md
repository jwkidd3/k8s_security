# Lab 6: Secrets Management

**Duration:** 40 minutes

## Objectives

By the end of this lab, you will be able to:

- Configure and verify encryption at rest for Kubernetes Secrets
- Compare volume mounts vs environment variables for secret consumption
- Create RBAC policies to restrict secret access by resource name
- Disable automatic service account token mounting
- Install and use Bitnami Sealed Secrets for GitOps-friendly secret management

## Prerequisites

- Cloud9 environment from Lab 1 (m5.large, us-east-1)
- Tools installed from Lab 1 (`kind`, `kubectl`)

---

### Step 1: Prepare Encryption Config and Create Cluster

```bash
# Generate a 32-byte encryption key
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

# Copy into the setup directory so kind can mount it
cp /tmp/encryption-config.yaml labs/setup/encryption-config-generated.yaml

# Create the cluster with encryption at rest pre-configured
cd labs/setup
kind create cluster --name security-lab --config kind-config-encryption.yaml
cd ../..

# Create lab namespace
kubectl create namespace secrets-lab
```

### Step 2: Create a Secret and Demonstrate Base64 Is Not Encryption

```bash
# Create a secret
kubectl create secret generic db-credentials \
  -n secrets-lab \
  --from-literal=username=admin \
  --from-literal=password='S3cur3P@ssw0rd!'

# View the secret — values are base64-encoded, NOT encrypted
kubectl get secret db-credentials -n secrets-lab -o jsonpath='{.data}' | jq .

# Decode the values — this is trivial for anyone with read access
kubectl get secret db-credentials -n secrets-lab -o jsonpath='{.data.username}' | base64 -d
echo ""
kubectl get secret db-credentials -n secrets-lab -o jsonpath='{.data.password}' | base64 -d
echo ""
```

**Key lesson:** Base64 encoding is NOT encryption. Anyone with access to read secrets can decode them instantly.

### Step 3: Verify Encryption at Rest

Check that secrets are actually encrypted when stored in etcd:

```bash
# Read the secret directly from etcd
docker exec security-lab-control-plane sh -c \
  'ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/secrets-lab/db-credentials' | hexdump -C | head -20

# Look for the "k8s:enc:aescbc" prefix in the output —
# this confirms the secret is encrypted at rest, not stored as plain text
```

### Step 4: Mount Secret as Volume

Volume mounts are the preferred way to consume secrets:

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
kubectl exec -n secrets-lab secret-volume-pod -- cat /etc/secrets/username
echo ""
kubectl exec -n secrets-lab secret-volume-pod -- cat /etc/secrets/password
echo ""

# Verify file permissions (0400 = owner read-only)
kubectl exec -n secrets-lab secret-volume-pod -- ls -la /etc/secrets/

# Secrets mounted as volumes are stored in tmpfs (memory, not disk)
kubectl exec -n secrets-lab secret-volume-pod -- df -T /etc/secrets
```

### Step 5: Mount Secret as Env Var and Show the Risks

Environment variables are convenient but have security downsides:

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

# Risk: env vars are visible in /proc — any process in the container can read them
kubectl exec -n secrets-lab secret-env-pod -- cat /proc/1/environ | tr '\0' '\n' | grep DB_
```

### Step 6: Create RBAC to Restrict Secret Access

Limit who can read which secrets using Role and RoleBinding with `resourceNames`:

```bash
# Create a ServiceAccount that represents a restricted application
kubectl create serviceaccount app-reader -n secrets-lab

# Create a second secret that the restricted account should NOT be able to read
kubectl create secret generic admin-credentials \
  -n secrets-lab \
  --from-literal=admin-token='super-admin-token-DO-NOT-SHARE'

# Create a Role that can ONLY get the db-credentials secret (not admin-credentials)
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: read-db-credentials-only
  namespace: secrets-lab
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["db-credentials"]
    verbs: ["get"]
EOF

# Bind the role to the service account
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-reader-db-creds
  namespace: secrets-lab
subjects:
  - kind: ServiceAccount
    name: app-reader
    namespace: secrets-lab
roleRef:
  kind: Role
  name: read-db-credentials-only
  apiGroup: rbac.authorization.k8s.io
EOF

echo "RBAC Role and RoleBinding created."

# Inspect the role to confirm it limits access by resourceNames
kubectl describe role read-db-credentials-only -n secrets-lab
```

### Step 7: Test the RBAC Restrictions with kubectl auth can-i

Verify that the restricted service account can only access the intended secret:

```bash
# Test: can app-reader get the db-credentials secret? (should be YES)
kubectl auth can-i get secrets/db-credentials \
  -n secrets-lab \
  --as=system:serviceaccount:secrets-lab:app-reader
# Expected: yes

# Test: can app-reader get the admin-credentials secret? (should be NO)
kubectl auth can-i get secrets/admin-credentials \
  -n secrets-lab \
  --as=system:serviceaccount:secrets-lab:app-reader
# Expected: no

# Test: can app-reader list all secrets? (should be NO)
kubectl auth can-i list secrets \
  -n secrets-lab \
  --as=system:serviceaccount:secrets-lab:app-reader
# Expected: no

# Test: can app-reader delete secrets? (should be NO)
kubectl auth can-i delete secrets/db-credentials \
  -n secrets-lab \
  --as=system:serviceaccount:secrets-lab:app-reader
# Expected: no

# Confirm by actually trying to get each secret as the service account
kubectl get secret db-credentials -n secrets-lab \
  --as=system:serviceaccount:secrets-lab:app-reader -o jsonpath='{.data.username}' | base64 -d
echo ""
echo "app-reader CAN read db-credentials"

kubectl get secret admin-credentials -n secrets-lab \
  --as=system:serviceaccount:secrets-lab:app-reader 2>&1
echo "app-reader CANNOT read admin-credentials (expected Forbidden)"
```

### Step 8: Disable Auto-Mounted Service Account Tokens

By default, Kubernetes mounts a service account token into every pod. This token can be exploited if the pod is compromised. Disable it when not needed:

```bash
# First, see the default behavior — a token is auto-mounted
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: default-sa-pod
  namespace: secrets-lab
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
EOF

kubectl wait --for=condition=Ready pod/default-sa-pod -n secrets-lab --timeout=60s

# The service account token is mounted automatically
kubectl exec -n secrets-lab default-sa-pod -- ls -la /var/run/secrets/kubernetes.io/serviceaccount/
kubectl exec -n secrets-lab default-sa-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
echo ""
echo "^ This token grants API access — a compromised pod could use it"

# Now deploy a pod with automountServiceAccountToken disabled
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-sa-token-pod
  namespace: secrets-lab
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
EOF

kubectl wait --for=condition=Ready pod/no-sa-token-pod -n secrets-lab --timeout=60s

# Verify no token is mounted
kubectl exec -n secrets-lab no-sa-token-pod -- ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1
# Expected: No such file or directory

# You can also disable it at the ServiceAccount level
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: no-token-sa
  namespace: secrets-lab
automountServiceAccountToken: false
EOF

echo "ServiceAccount 'no-token-sa' created with automountServiceAccountToken: false"
kubectl get serviceaccount no-token-sa -n secrets-lab -o json | jq '{name: .metadata.name, automountServiceAccountToken: .automountServiceAccountToken}'
```

### Step 9: Install and Use Sealed Secrets

Install the Sealed Secrets controller and kubeseal CLI, then create a sealed secret:

```bash
# Install Helm if not already installed
if ! command -v helm &>/dev/null; then
  HELM_VERSION=v3.14.2
  curl -LO "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz"
  tar xzf "helm-${HELM_VERSION}-linux-amd64.tar.gz" linux-amd64/helm
  sudo mv linux-amd64/helm /usr/local/bin/helm
  rm -rf linux-amd64 "helm-${HELM_VERSION}-linux-amd64.tar.gz"
fi

# Install Sealed Secrets controller via Helm
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
tar -xzf "kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz"
sudo mv kubeseal /usr/local/bin/
rm "kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz"

# Create a regular secret manifest (do NOT apply this directly)
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

# Seal it using kubeseal — the output is safe to commit to git
kubeseal --format yaml < /tmp/my-secret.yaml > /tmp/sealed-secret.yaml

# View the sealed secret
cat /tmp/sealed-secret.yaml

# Apply the sealed secret to the cluster
kubectl apply -f /tmp/sealed-secret.yaml

# Clean up the plain-text file immediately
rm /tmp/my-secret.yaml
```

### Step 10: Verify Sealed Secret Was Decrypted

The Sealed Secrets controller decrypts SealedSecrets into regular Secrets:

```bash
# Wait for the controller to process the SealedSecret
sleep 5

# Verify the regular secret was created
kubectl get secret api-credentials -n secrets-lab

# Read the decrypted values
kubectl get secret api-credentials -n secrets-lab -o jsonpath='{.data.api-key}' | base64 -d
echo ""
kubectl get secret api-credentials -n secrets-lab -o jsonpath='{.data.api-secret}' | base64 -d
echo ""
```

### Step 11: Cleanup

```bash
kubectl delete namespace secrets-lab
rm -f /tmp/sealed-secret.yaml /tmp/encryption-config.yaml
rm -f labs/setup/encryption-config-generated.yaml

# (Optional) Delete the cluster
# kind delete cluster --name security-lab
```

## Summary

- Base64 encoding is not encryption; encryption at rest (aescbc) protects secrets stored in etcd
- Volume mounts are preferred over environment variables because they use tmpfs and support file permissions
- RBAC with resourceNames restricts which secrets a service account can access, enforcing least-privilege
- Disabling automountServiceAccountToken prevents compromised pods from accessing the Kubernetes API
- Sealed Secrets enable GitOps workflows by encrypting secrets with a cluster-specific key
