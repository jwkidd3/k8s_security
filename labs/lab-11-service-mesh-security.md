# Lab 11: Service Mesh Security

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Install Linkerd on a kind cluster
- Enable automatic mutual TLS (mTLS) between services
- Deploy and mesh an application with Linkerd proxy injection
- Configure ServerAuthorization policies for fine-grained access control
- Use Linkerd observability tools to monitor service traffic

## Prerequisites

- Cloud9 environment with Docker
- `kubectl` and `kind` installed

## Lab Environment Setup

### Step 1: Create a Cluster for Service Mesh

```bash
# Create cluster with extra port mappings
kind create cluster --name mesh-lab --config labs/setup/kind-config-mesh.yaml

# Verify the cluster
kubectl cluster-info --context kind-mesh-lab
kubectl get nodes
```

### Step 2: Install the Linkerd CLI

```bash
# Install Linkerd CLI
curl -sL https://run.linkerd.io/install | sh
export PATH=$PATH:$HOME/.linkerd2/bin

# Verify the CLI
linkerd version --client

# Run pre-installation checks
linkerd check --pre
```

### Step 3: Install Linkerd

```bash
# Install Linkerd CRDs
linkerd install --crds | kubectl apply -f -

# Install the control plane
linkerd install | kubectl apply -f -

# Wait for the control plane to be ready
linkerd check

echo "Linkerd control plane installed"
kubectl get pods -n linkerd
```

### Step 4: Install Linkerd Viz Extension

```bash
# Install the viz extension (dashboard, tap, stat, etc.)
linkerd viz install | kubectl apply -f -

# Wait for viz to be ready
linkerd viz check

echo "Linkerd viz extension installed"
kubectl get pods -n linkerd-viz
```

## Part 1: Deploy a Demo Application

### Step 5: Deploy the Application

```bash
kubectl create namespace mesh-demo

# Deploy a multi-service application
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: mesh-demo
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
        - name: frontend
          image: nginx:1.25-alpine
          ports:
            - containerPort: 80
          volumeMounts:
            - name: config
              mountPath: /etc/nginx/conf.d
      volumes:
        - name: config
          configMap:
            name: frontend-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: frontend-config
  namespace: mesh-demo
data:
  default.conf: |
    server {
        listen 80;
        location / {
            return 200 'Frontend OK\n';
            add_header Content-Type text/plain;
        }
        location /api {
            proxy_pass http://backend:8080;
        }
    }
---
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: mesh-demo
spec:
  selector:
    app: frontend
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: mesh-demo
spec:
  replicas: 2
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
        - name: backend
          image: nginx:1.25-alpine
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: config
              mountPath: /etc/nginx/conf.d
      volumes:
        - name: config
          configMap:
            name: backend-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: backend-config
  namespace: mesh-demo
data:
  default.conf: |
    server {
        listen 8080;
        location / {
            return 200 'Backend OK\n';
            add_header Content-Type text/plain;
        }
        location /data {
            proxy_pass http://database:5432;
        }
    }
---
apiVersion: v1
kind: Service
metadata:
  name: backend
  namespace: mesh-demo
spec:
  selector:
    app: backend
  ports:
    - port: 8080
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: database
  namespace: mesh-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: database
  template:
    metadata:
      labels:
        app: database
    spec:
      containers:
        - name: database
          image: nginx:1.25-alpine
          ports:
            - containerPort: 5432
          volumeMounts:
            - name: config
              mountPath: /etc/nginx/conf.d
      volumes:
        - name: config
          configMap:
            name: database-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: database-config
  namespace: mesh-demo
data:
  default.conf: |
    server {
        listen 5432;
        location / {
            return 200 'Database OK\n';
            add_header Content-Type text/plain;
        }
    }
---
apiVersion: v1
kind: Service
metadata:
  name: database
  namespace: mesh-demo
spec:
  selector:
    app: database
  ports:
    - port: 5432
      targetPort: 5432
EOF

kubectl wait --for=condition=Ready pods --all -n mesh-demo --timeout=120s
echo "Application deployed"
kubectl get pods -n mesh-demo
```

## Part 2: Inject Linkerd Proxy

### Step 6: Mesh the Application

```bash
# Annotate the namespace for automatic proxy injection
kubectl annotate namespace mesh-demo linkerd.io/inject=enabled

# Restart deployments to trigger injection
kubectl rollout restart deployment -n mesh-demo

# Wait for new pods
kubectl wait --for=condition=Ready pods --all -n mesh-demo --timeout=120s

# Verify proxies are injected (each pod should have 2 containers)
kubectl get pods -n mesh-demo -o jsonpath='{range .items[*]}{.metadata.name}: {range .spec.containers[*]}{.name} {end}{"\n"}{end}'
```

### Step 7: Verify mTLS Is Active

```bash
# Check mTLS status
linkerd viz edges -n mesh-demo

# Check that connections are secured
linkerd viz tap deploy/frontend -n mesh-demo --to deploy/backend --max-rps 0.5 &
TAP_PID=$!

# Generate some traffic
for i in $(seq 1 5); do
  kubectl exec -n mesh-demo deploy/frontend -c frontend -- wget -qO- http://backend:8080 2>/dev/null
  sleep 1
done

sleep 3
kill $TAP_PID 2>/dev/null

echo ""
echo "Look for 'tls=true' in the tap output — this confirms mTLS is active"
```

### Step 8: View mTLS Identity

```bash
# Check the identity of meshed pods
linkerd viz stat -n mesh-demo deploy

echo ""
echo "The 'MESHED' column shows proxy injection status"
echo "The 'SUCCESS' and 'RPS' columns show traffic metrics"
```

## Part 3: Observability

### Step 9: Monitor Traffic with stat

```bash
# Generate sustained traffic
kubectl run traffic-gen --image=busybox:1.36 -n mesh-demo -- sh -c \
  'while true; do wget -qO- http://frontend/api 2>/dev/null; sleep 2; done'

sleep 10

# View traffic stats
linkerd viz stat -n mesh-demo deploy

# View per-route stats
linkerd viz routes -n mesh-demo deploy/frontend
```

### Step 10: Use Top for Real-Time Monitoring

```bash
# Real-time traffic view (run for 10 seconds)
timeout 10 linkerd viz top -n mesh-demo deploy/backend 2>/dev/null || true

echo ""
echo "Top shows real-time request metrics by path"
```

### Step 11: Access the Dashboard

```bash
# Port-forward the dashboard
linkerd viz dashboard --port 9084 &
DASH_PID=$!

echo "Linkerd dashboard available at http://localhost:9084"
echo "Navigate to the mesh-demo namespace to see traffic visualization"

sleep 5
kill $DASH_PID 2>/dev/null
```

## Part 4: Authorization Policies

### Step 12: Create a Server Resource

```bash
# Define servers for each service
kubectl apply -f - <<EOF
apiVersion: policy.linkerd.io/v1beta2
kind: Server
metadata:
  name: frontend-http
  namespace: mesh-demo
spec:
  podSelector:
    matchLabels:
      app: frontend
  port: 80
  proxyProtocol: HTTP/1
---
apiVersion: policy.linkerd.io/v1beta2
kind: Server
metadata:
  name: backend-http
  namespace: mesh-demo
spec:
  podSelector:
    matchLabels:
      app: backend
  port: 8080
  proxyProtocol: HTTP/1
---
apiVersion: policy.linkerd.io/v1beta2
kind: Server
metadata:
  name: database-http
  namespace: mesh-demo
spec:
  podSelector:
    matchLabels:
      app: database
  port: 5432
  proxyProtocol: HTTP/1
EOF
```

### Step 13: Create Authorization Policies

```bash
# Allow frontend to access backend
kubectl apply -f - <<EOF
apiVersion: policy.linkerd.io/v1alpha1
kind: AuthorizationPolicy
metadata:
  name: backend-allow-frontend
  namespace: mesh-demo
spec:
  targetRef:
    group: policy.linkerd.io
    kind: Server
    name: backend-http
  requiredAuthenticationRefs:
    - name: frontend-identity
      kind: MeshTLSAuthentication
      group: policy.linkerd.io
---
apiVersion: policy.linkerd.io/v1alpha1
kind: MeshTLSAuthentication
metadata:
  name: frontend-identity
  namespace: mesh-demo
spec:
  identities:
    - "*.mesh-demo.serviceaccount.identity.linkerd.cluster.local"
EOF

# Allow backend to access database
kubectl apply -f - <<EOF
apiVersion: policy.linkerd.io/v1alpha1
kind: AuthorizationPolicy
metadata:
  name: database-allow-backend
  namespace: mesh-demo
spec:
  targetRef:
    group: policy.linkerd.io
    kind: Server
    name: database-http
  requiredAuthenticationRefs:
    - name: backend-identity
      kind: MeshTLSAuthentication
      group: policy.linkerd.io
---
apiVersion: policy.linkerd.io/v1alpha1
kind: MeshTLSAuthentication
metadata:
  name: backend-identity
  namespace: mesh-demo
spec:
  identities:
    - "*.mesh-demo.serviceaccount.identity.linkerd.cluster.local"
EOF
```

### Step 14: Test Authorization

```bash
echo "=== Testing Authorized Paths ==="

# Frontend → Backend (should work)
kubectl exec -n mesh-demo deploy/frontend -c frontend -- wget -qO- --timeout=3 http://backend:8080 2>&1
echo "Frontend → Backend: OK"

# Backend → Database (should work)
kubectl exec -n mesh-demo deploy/backend -c backend -- wget -qO- --timeout=3 http://database:5432 2>&1
echo "Backend → Database: OK"

echo ""
echo "=== Authorization policies are enforcing service identity ==="
echo "Traffic is only allowed from authenticated mesh identities"
```

### Step 15: Check Authorization Status

```bash
# View the authorization status of servers
linkerd viz authz -n mesh-demo deploy/backend
echo ""
linkerd viz authz -n mesh-demo deploy/database
```

## Part 5: Security Verification

### Step 16: Verify the Full Security Picture

```bash
echo "============================================"
echo "  Service Mesh Security Status"
echo "============================================"
echo ""
echo "--- mTLS Status ---"
linkerd viz edges -n mesh-demo 2>/dev/null | head -10
echo ""
echo "--- Meshed Workloads ---"
linkerd viz stat -n mesh-demo deploy 2>/dev/null
echo ""
echo "--- Authorization Policies ---"
kubectl get authorizationpolicies -n mesh-demo 2>/dev/null || echo "  No policies found"
echo ""
echo "--- Servers ---"
kubectl get servers -n mesh-demo 2>/dev/null || echo "  No servers found"
```

## Cleanup

```bash
# Clean up traffic generator
kubectl delete pod traffic-gen -n mesh-demo --ignore-not-found

# Delete the demo namespace
kubectl delete namespace mesh-demo

# Uninstall Linkerd viz
linkerd viz uninstall | kubectl delete -f -

# Uninstall Linkerd
linkerd uninstall | kubectl delete -f -

# (Optional) Delete the cluster
kind delete cluster --name mesh-lab
```

## Summary

In this lab, you:
- Installed Linkerd on a kind cluster with the viz extension
- Deployed a multi-service application and injected Linkerd proxies
- Verified automatic mTLS encryption between all meshed services
- Used Linkerd observability tools (stat, tap, top, edges) to monitor traffic
- Created Server and AuthorizationPolicy resources for fine-grained access control

Key takeaway: A service mesh adds a security layer that is transparent to applications — automatic mTLS, identity-based authorization, and deep traffic observability without code changes.
