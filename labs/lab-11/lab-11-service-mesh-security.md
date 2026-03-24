# Lab 11: Service Mesh Security

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Install Linkerd and verify automatic mTLS between services
- Deploy and mesh a multi-service application
- Inspect mesh identity certificates
- Monitor service traffic with Linkerd observability tools
- Access the Linkerd dashboard for visual traffic inspection
- Configure authorization policies for fine-grained access control

## Prerequisites

- Cloud9 environment from Lab 1 (m5.large, us-east-1)
- Tools installed from Lab 1 (`kind`, `kubectl`, `jq`)

---

### Step 1: Create Cluster and Install Linkerd CLI

```bash
# Create cluster
kind create cluster --name mesh-lab --config labs/setup/kind-config-mesh.yaml

# Verify the cluster
kubectl cluster-info --context kind-mesh-lab
kubectl get nodes

# Install Linkerd CLI via direct binary download
LINKERD_VERSION=stable-2.14.10
curl -LO "https://github.com/linkerd/linkerd2/releases/download/${LINKERD_VERSION}/linkerd2-cli-${LINKERD_VERSION}-linux-amd64"
chmod +x "linkerd2-cli-${LINKERD_VERSION}-linux-amd64"
sudo mv "linkerd2-cli-${LINKERD_VERSION}-linux-amd64" /usr/local/bin/linkerd

# Verify
linkerd version --client

# Pre-flight checks
linkerd check --pre
```

### Step 2: Install Linkerd Control Plane and Viz

```bash
# Install CRDs
linkerd install --crds | kubectl apply -f -

# Install the control plane
linkerd install | kubectl apply -f -

# Wait for control plane
linkerd check

# Install the viz extension (provides stat, edges, tap, top, dashboard)
linkerd viz install | kubectl apply -f -
linkerd viz check

echo ""
echo "Linkerd control plane and viz extension installed"
kubectl get pods -n linkerd
kubectl get pods -n linkerd-viz
```

### Step 3: Deploy Demo Application

```bash
kubectl create namespace mesh-demo

# Deploy frontend, backend, and database services
kubectl apply -f labs/lab-11/frontend-resources.yaml

kubectl wait --for=condition=Ready pods --all -n mesh-demo --timeout=120s
echo "Application deployed"
kubectl get pods -n mesh-demo
```

### Step 4: Inject Linkerd Proxies and Verify mTLS

```bash
# Annotate namespace for automatic proxy injection
kubectl annotate namespace mesh-demo linkerd.io/inject=enabled

# Restart deployments to trigger injection
kubectl rollout restart deployment -n mesh-demo
kubectl wait --for=condition=Ready pods --all -n mesh-demo --timeout=120s

# Verify proxies are injected (each pod should have 2 containers)
kubectl get pods -n mesh-demo -o jsonpath='{range .items[*]}{.metadata.name}: {range .spec.containers[*]}{.name} {end}{"\n"}{end}'

# Generate some traffic so we can verify mTLS
for i in $(seq 1 5); do
  kubectl exec -n mesh-demo deploy/frontend -c frontend -- wget -qO- http://backend:8080 2>/dev/null
  sleep 1
done

# Check mTLS status — the SECURED column shows encrypted connections
echo ""
echo "=== mTLS Status ==="
linkerd viz edges -n mesh-demo
```

### Step 5: Check Linkerd Identity Certificates

```bash
# Inspect the trust anchor (root CA) certificate
echo "=== Trust Anchor Certificate ==="
kubectl get cm linkerd-identity-trust-roots -n linkerd -o jsonpath='{.data.ca-bundle\.crt}' | openssl x509 -noout -text | head -20

# Verify meshed pods have proxy identities
echo ""
echo "=== Meshed Pod Count ==="
linkerd viz stat -n mesh-demo deploy

# View the identity of the linkerd control plane
echo ""
echo "=== Linkerd Control Plane Identity ==="
kubectl get secrets -n linkerd -o name

# Check the issuer certificate details
echo ""
echo "=== Identity Issuer ==="
kubectl get secret linkerd-identity-issuer -n linkerd -o jsonpath='{.data.crt\.pem}' | base64 -d | openssl x509 -noout -text 2>/dev/null | head -20

# Verify that each proxy has a valid identity
echo ""
echo "=== Proxy Identities in mesh-demo ==="
for deploy in frontend backend database; do
  POD=$(kubectl get pod -n mesh-demo -l app=$deploy -o jsonpath='{.items[0].metadata.name}')
  echo "Pod: $POD"
  kubectl exec -n mesh-demo $POD -c linkerd-proxy -- /bin/sh -c 'echo $LINKERD2_PROXY_IDENTITY_LOCAL_NAME' 2>/dev/null || echo "  (identity via annotation)"
  echo ""
done

# Show how Linkerd uses identities to enforce mTLS
echo "=== Service Account Identities ==="
kubectl get serviceaccounts -n mesh-demo -o jsonpath='{range .items[*]}SA: {.metadata.name}{"\n"}{end}'
echo ""
echo "Linkerd assigns each service account a unique cryptographic identity"
echo "in the format: <sa-name>.<namespace>.serviceaccount.identity.linkerd.cluster.local"
```

### Step 6: Monitor Traffic with linkerd stat

```bash
# Start a traffic generator
kubectl run traffic-gen --image=busybox:1.36 -n mesh-demo -- sh -c \
  'while true; do wget -qO- http://frontend/api 2>/dev/null; sleep 2; done'

sleep 15

# View traffic stats — shows success rate, RPS, and latency per deployment
linkerd viz stat -n mesh-demo deploy

# View per-route stats for frontend
echo ""
linkerd viz routes -n mesh-demo deploy/frontend
```

### Step 7: Use linkerd viz top for Live Traffic

```bash
# View live request streams — top shows real-time requests flowing through the mesh
# Run for 15 seconds to capture traffic patterns
echo "=== Live Traffic (15 seconds) ==="
timeout 15 linkerd viz top -n mesh-demo deploy/frontend 2>/dev/null || true

echo ""
echo "=== Live Traffic to Backend ==="
timeout 15 linkerd viz top -n mesh-demo deploy/backend 2>/dev/null || true

# Also check edges to see the full service graph with mTLS status
echo ""
echo "=== Service Graph (Edges) ==="
linkerd viz edges -n mesh-demo deploy
```

`linkerd viz top` shows per-request data flowing through the mesh in real time, including source, destination, method, path, latency, and HTTP status code.

### Step 8: Access the Linkerd Dashboard

```bash
# Port-forward the Linkerd dashboard to view the web UI
# This runs in the background for 60 seconds so you can explore
echo "Starting Linkerd dashboard port-forward on port 50750..."
kubectl port-forward -n linkerd-viz svc/web 50750:8084 &
DASHBOARD_PID=$!

sleep 3
echo ""
echo "Dashboard is available at: http://localhost:50750"
echo "In Cloud9, use 'Preview > Preview Running Application' to access it."
echo ""

# While the dashboard is running, let's check what it exposes
echo "=== Dashboard API: Stat Query ==="
curl -s http://localhost:50750/api/stat?resource_type=deployment\&namespace=mesh-demo 2>/dev/null | jq . 2>/dev/null || echo "Dashboard API requires browser authentication"

# Let the dashboard run for a bit, then clean up
sleep 30
kill $DASHBOARD_PID 2>/dev/null
echo ""
echo "Dashboard port-forward stopped."
echo ""
echo "The dashboard provides visual views of:"
echo "  - Service topology and dependencies"
echo "  - Success rates, RPS, and latency per service"
echo "  - mTLS status for all connections"
echo "  - Live tap and top data"
```

### Step 9: Create Authorization Policy

```bash
# Define Server resources for backend and database
kubectl apply -f labs/lab-11/backend-http-resources.yaml

# Create authorization policies — only allow meshed identities
kubectl apply -f labs/lab-11/backend-allow-frontend-resources.yaml

echo ""
echo "=== Testing Authorized Paths ==="

# Frontend -> Backend (should work)
kubectl exec -n mesh-demo deploy/frontend -c frontend -- wget -qO- --timeout=3 http://backend:8080 2>&1
echo "Frontend -> Backend: OK"

# Backend -> Database (should work)
kubectl exec -n mesh-demo deploy/backend -c backend -- wget -qO- --timeout=3 http://database:5432 2>&1
echo "Backend -> Database: OK"

echo ""
echo "=== Verify Authorization Policy Resources ==="
kubectl get server,authorizationpolicy,meshtlsauthentication -n mesh-demo

echo ""
echo "Authorization policies enforce that only authenticated mesh identities can reach backend and database services."
```

### Step 10: Cleanup

```bash
# Clean up traffic generator
kubectl delete pod traffic-gen -n mesh-demo --ignore-not-found

# Delete the demo namespace
kubectl delete namespace mesh-demo

# Uninstall Linkerd viz and control plane
linkerd viz uninstall | kubectl delete -f -
linkerd uninstall | kubectl delete -f -

# (Optional) Delete the cluster
kind delete cluster --name mesh-lab
```

## Summary

- Linkerd provides automatic mTLS between all meshed services with zero application changes
- Proxy injection adds a sidecar that handles encryption, identity, and observability
- Each service account receives a unique cryptographic identity used for mutual authentication
- `linkerd viz stat`, `linkerd viz top`, and the web dashboard give real-time visibility into service traffic, latency, and mTLS status
- Server and AuthorizationPolicy resources enforce identity-based access control at the mesh layer
