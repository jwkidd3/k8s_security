# Lab 5: Network Policies

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Deploy a kind cluster with Calico CNI for NetworkPolicy support
- Implement default-deny ingress and egress policies
- Create targeted allow policies for a multi-tier application
- Test and validate network connectivity between pods

## Prerequisites

- Cloud9 environment with Docker
- `kubectl` and `kind` installed

## Lab Environment Setup

### Step 1: Create a Cluster with Calico CNI

The default kind CNI (kindnet) does not support NetworkPolicies. We need Calico:

```bash
# Create cluster with CNI disabled
kind create cluster --name netpol-lab --config labs/setup/kind-config-calico.yaml

# Install Calico
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml

# Wait for Calico pods to be ready
echo "Waiting for Calico to initialize..."
kubectl wait --for=condition=Ready pods -l k8s-app=calico-node -n kube-system --timeout=180s
kubectl wait --for=condition=Ready pods -l k8s-app=calico-kube-controllers -n kube-system --timeout=180s

# Verify all nodes are Ready
kubectl get nodes
```

### Step 2: Deploy a Three-Tier Application

We use ConfigMaps to provide custom nginx configurations that listen on the correct ports for each tier. This avoids fragile `sed` commands and is a more Kubernetes-native approach.

```bash
# Create namespace
kubectl create namespace three-tier

# Create ConfigMap for the database tier (listens on port 5432)
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: database-nginx-config
  namespace: three-tier
data:
  default.conf: |
    server {
        listen 5432;
        location / {
            return 200 'Database OK\n';
            add_header Content-Type text/plain;
        }
    }
EOF

# Create ConfigMap for the backend tier (listens on port 8080)
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: backend-nginx-config
  namespace: three-tier
data:
  default.conf: |
    server {
        listen 8080;
        location / {
            return 200 'Backend OK\n';
            add_header Content-Type text/plain;
        }
    }
EOF

# Deploy the database tier
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: database
  namespace: three-tier
  labels:
    app: database
    tier: database
spec:
  replicas: 1
  selector:
    matchLabels:
      app: database
      tier: database
  template:
    metadata:
      labels:
        app: database
        tier: database
    spec:
      containers:
        - name: db
          image: nginx:alpine
          ports:
            - containerPort: 5432
              name: postgres
          volumeMounts:
            - name: nginx-config
              mountPath: /etc/nginx/conf.d
      volumes:
        - name: nginx-config
          configMap:
            name: database-nginx-config
---
apiVersion: v1
kind: Service
metadata:
  name: database
  namespace: three-tier
spec:
  selector:
    app: database
    tier: database
  ports:
    - port: 5432
      targetPort: 5432
EOF

# Deploy the backend tier
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: three-tier
  labels:
    app: backend
    tier: backend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: backend
      tier: backend
  template:
    metadata:
      labels:
        app: backend
        tier: backend
    spec:
      containers:
        - name: api
          image: nginx:alpine
          ports:
            - containerPort: 8080
              name: http
          volumeMounts:
            - name: nginx-config
              mountPath: /etc/nginx/conf.d
      volumes:
        - name: nginx-config
          configMap:
            name: backend-nginx-config
---
apiVersion: v1
kind: Service
metadata:
  name: backend
  namespace: three-tier
spec:
  selector:
    app: backend
    tier: backend
  ports:
    - port: 8080
      targetPort: 8080
EOF

# Deploy the frontend tier (uses default nginx port 80, no ConfigMap needed)
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: three-tier
  labels:
    app: frontend
    tier: frontend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
      tier: frontend
  template:
    metadata:
      labels:
        app: frontend
        tier: frontend
    spec:
      containers:
        - name: web
          image: nginx:alpine
          ports:
            - containerPort: 80
              name: http
---
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: three-tier
spec:
  selector:
    app: frontend
    tier: frontend
  ports:
    - port: 80
      targetPort: 80
EOF

# Wait for all pods to be ready
kubectl wait --for=condition=Ready pods --all -n three-tier --timeout=120s
kubectl get pods -n three-tier -o wide
```

## Part 1: Verify Default Connectivity

### Step 3: Test Connectivity Without Policies

```bash
# Get pod names
FRONTEND_POD=$(kubectl get pod -n three-tier -l tier=frontend -o jsonpath='{.items[0].metadata.name}')
BACKEND_POD=$(kubectl get pod -n three-tier -l tier=backend -o jsonpath='{.items[0].metadata.name}')
DATABASE_POD=$(kubectl get pod -n three-tier -l tier=database -o jsonpath='{.items[0].metadata.name}')

echo "Frontend: $FRONTEND_POD"
echo "Backend:  $BACKEND_POD"
echo "Database: $DATABASE_POD"

# Test: frontend → backend (should work)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://backend:8080 2>&1 | head -5
echo "Frontend → Backend: OK"

# Test: frontend → database (should work — no policies yet)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://database:5432 2>&1 | head -5
echo "Frontend → Database: OK (this should NOT be allowed)"

# Test: backend → database (should work)
kubectl exec -n three-tier $BACKEND_POD -- wget -qO- --timeout=3 http://database:5432 2>&1 | head -5
echo "Backend → Database: OK"

# Test: external access (should work — no egress policies)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://google.com 2>&1 | head -3
echo "Frontend → Internet: OK"
```

**Problem:** Without NetworkPolicies, all pods can talk to all other pods and the internet. The frontend can directly access the database, bypassing the backend.

## Part 2: Default Deny Policies

### Step 4: Apply Default Deny Ingress

```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: three-tier
spec:
  podSelector: {}    # Selects all pods in the namespace
  policyTypes:
    - Ingress
EOF

echo "Default deny ingress applied."
```

### Step 5: Test — All Ingress Should Be Blocked

```bash
# These should all fail now
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://backend:8080 2>&1
echo "Frontend → Backend: Expected timeout (blocked)"

kubectl exec -n three-tier $BACKEND_POD -- wget -qO- --timeout=3 http://database:5432 2>&1
echo "Backend → Database: Expected timeout (blocked)"
```

### Step 6: Apply Default Deny Egress

```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: three-tier
spec:
  podSelector: {}
  policyTypes:
    - Egress
EOF

echo "Default deny egress applied."
```

## Part 3: Allow Policies for Three-Tier Architecture

### Step 7: Allow DNS Resolution (Required for Service Names)

```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: three-tier
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
EOF
```

### Step 8: Allow Frontend → Backend

```bash
# Allow frontend egress to backend
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-to-backend
  namespace: three-tier
spec:
  podSelector:
    matchLabels:
      tier: frontend
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              tier: backend
      ports:
        - port: 8080
          protocol: TCP
EOF

# Allow backend ingress from frontend
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-from-frontend
  namespace: three-tier
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              tier: frontend
      ports:
        - port: 8080
          protocol: TCP
EOF
```

### Step 9: Allow Backend → Database

```bash
# Allow backend egress to database
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-to-database
  namespace: three-tier
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              tier: database
      ports:
        - port: 5432
          protocol: TCP
EOF

# Allow database ingress from backend
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-from-backend
  namespace: three-tier
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              tier: backend
      ports:
        - port: 5432
          protocol: TCP
EOF
```

### Step 10: Validate the Network Policies

```bash
echo "=== Testing allowed paths ==="

# Frontend → Backend (should work)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://backend:8080 2>&1 | head -3
echo "Frontend → Backend: OK ✓"

# Backend → Database (should work)
kubectl exec -n three-tier $BACKEND_POD -- wget -qO- --timeout=3 http://database:5432 2>&1 | head -3
echo "Backend → Database: OK ✓"

echo ""
echo "=== Testing blocked paths ==="

# Frontend → Database (should be blocked)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://database:5432 2>&1
echo "Frontend → Database: BLOCKED ✓"

# Database → Backend (should be blocked)
kubectl exec -n three-tier $DATABASE_POD -- wget -qO- --timeout=3 http://backend:8080 2>&1
echo "Database → Backend: BLOCKED ✓"

# Frontend → Internet (should be blocked)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://google.com 2>&1
echo "Frontend → Internet: BLOCKED ✓"
```

## Part 4: Cross-Namespace Policies

### Step 11: Create a Monitoring Namespace

```bash
kubectl create namespace monitoring
kubectl label namespace monitoring purpose=monitoring

# Deploy a monitoring pod
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: monitor
  namespace: monitoring
  labels:
    app: monitor
spec:
  containers:
    - name: monitor
      image: nginx:alpine
      command: ["sleep", "3600"]
EOF

kubectl wait --for=condition=Ready pod/monitor -n monitoring --timeout=60s
```

### Step 12: Allow Monitoring Access

```bash
# Allow monitoring namespace to access all tiers (ingress)
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring
  namespace: three-tier
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              purpose: monitoring
      ports:
        - port: 80
          protocol: TCP
        - port: 8080
          protocol: TCP
        - port: 5432
          protocol: TCP
EOF

# Allow monitoring pods egress to three-tier namespace
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-three-tier
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: monitor
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: three-tier
      ports:
        - port: 80
          protocol: TCP
        - port: 8080
          protocol: TCP
        - port: 5432
          protocol: TCP
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
EOF
```

### Step 13: Test Cross-Namespace Access

```bash
# Monitoring → frontend (should work)
kubectl exec -n monitoring monitor -- wget -qO- --timeout=3 http://frontend.three-tier.svc.cluster.local:80 2>&1 | head -3
echo "Monitoring → Frontend: OK"

# Monitoring → backend (should work)
kubectl exec -n monitoring monitor -- wget -qO- --timeout=3 http://backend.three-tier.svc.cluster.local:8080 2>&1 | head -3
echo "Monitoring → Backend: OK"
```

## Part 5: Review All Policies

### Step 14: List and Inspect Policies

```bash
# List all network policies
kubectl get networkpolicies -n three-tier

# Describe each policy
kubectl describe networkpolicies -n three-tier
```

### Step 15: Visualize the Network Policy Architecture

Create a summary of the allowed traffic flows:

```
┌─────────────────────────────────────────────────┐
│                three-tier namespace              │
│                                                  │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐ │
│  │ Frontend │────>│ Backend  │────>│ Database │ │
│  │ :80      │     │ :8080    │     │ :5432    │ │
│  └──────────┘     └──────────┘     └──────────┘ │
│       ▲                ▲                ▲        │
│       │                │                │        │
└───────┼────────────────┼────────────────┼────────┘
        │                │                │
   ┌────┴────────────────┴────────────────┴────┐
   │           monitoring namespace             │
   │   ┌──────────┐                             │
   │   │ Monitor  │ (can reach all tiers)       │
   │   └──────────┘                             │
   └────────────────────────────────────────────┘
```

## Cleanup

```bash
kubectl delete namespace three-tier monitoring

# (Optional) Delete the cluster
kind delete cluster --name netpol-lab
```

## Summary

In this lab, you:
- Deployed a kind cluster with Calico CNI for NetworkPolicy support
- Deployed a three-tier application (frontend → backend → database)
- Implemented default-deny ingress and egress policies
- Created targeted allow policies following the principle of least privilege
- Configured cross-namespace access for monitoring
- Validated that unauthorized traffic flows are blocked

Key takeaway: Start with default-deny, then add specific allow rules. Always allow DNS egress, and remember that NetworkPolicies are namespace-scoped and additive.
