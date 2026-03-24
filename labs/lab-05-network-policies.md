# Lab 5: Network Policies

**Duration:** 40 minutes

## Objectives

By the end of this lab, you will be able to:

- Deploy a kind cluster with Calico CNI for NetworkPolicy support
- Implement default-deny ingress and egress policies
- Create targeted allow policies for a multi-tier application
- Configure cross-namespace network access for monitoring
- Inspect and audit all NetworkPolicies in a namespace

## Prerequisites

- Cloud9 environment (Amazon Linux) with Docker
- `kubectl` and `kind` installed

---

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

Deploy frontend, backend, and database tiers using ConfigMaps for custom nginx port configurations:

```bash
# Create namespace
kubectl create namespace three-tier

# Create ConfigMaps for custom nginx ports
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
---
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

# Deploy database tier
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

# Deploy backend tier
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
  replicas: 1
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

# Deploy frontend tier (uses default nginx port 80)
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
  replicas: 1
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

### Step 3: Test Connectivity Before Policies

Without NetworkPolicies, every pod can reach every other pod:

```bash
# Get pod names
FRONTEND_POD=$(kubectl get pod -n three-tier -l tier=frontend -o jsonpath='{.items[0].metadata.name}')
BACKEND_POD=$(kubectl get pod -n three-tier -l tier=backend -o jsonpath='{.items[0].metadata.name}')
DATABASE_POD=$(kubectl get pod -n three-tier -l tier=database -o jsonpath='{.items[0].metadata.name}')

# Frontend -> Backend (expected: OK)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://backend:8080
echo "Frontend -> Backend: OK"

# Frontend -> Database (expected: OK — but this SHOULD be blocked)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://database:5432
echo "Frontend -> Database: OK (should NOT be allowed)"

# Backend -> Database (expected: OK)
kubectl exec -n three-tier $BACKEND_POD -- wget -qO- --timeout=3 http://database:5432
echo "Backend -> Database: OK"

# Database -> Backend (expected: OK — but this SHOULD be blocked)
kubectl exec -n three-tier $DATABASE_POD -- wget -qO- --timeout=3 http://backend:8080
echo "Database -> Backend: OK (should NOT be allowed)"
```

### Step 4: Apply Default Deny Ingress Policy

Lock down all ingress traffic in the namespace:

```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: three-tier
spec:
  podSelector: {}
  policyTypes:
    - Ingress
EOF

echo "Default deny ingress applied."
```

### Step 5: Apply Default Deny Egress and Allow DNS Resolution

A complete zero-trust posture also denies all egress traffic. However, pods still need DNS to resolve service names, so we explicitly allow egress to the kube-dns service:

```bash
# Default deny all egress
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

# Allow DNS resolution for all pods
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

echo "DNS egress allowed."

# Verify DNS still works but other traffic is blocked
kubectl exec -n three-tier $FRONTEND_POD -- nslookup backend.three-tier.svc.cluster.local 2>&1
echo "DNS resolution: OK"

# Verify that actual traffic is blocked (both ingress and egress deny in effect)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://backend:8080 2>&1
echo "Frontend -> Backend: Expected timeout (blocked by deny-all)"
```

### Step 6: Test That Traffic Is Now Blocked

Confirm that both ingress and egress deny policies are working:

```bash
# Frontend -> Backend (should FAIL — ingress and egress denied)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://backend:8080 2>&1
echo "Frontend -> Backend: Expected timeout (blocked)"

# Backend -> Database (should FAIL — ingress and egress denied)
kubectl exec -n three-tier $BACKEND_POD -- wget -qO- --timeout=3 http://database:5432 2>&1
echo "Backend -> Database: Expected timeout (blocked)"

# Database -> Backend (should FAIL)
kubectl exec -n three-tier $DATABASE_POD -- wget -qO- --timeout=3 http://backend:8080 2>&1
echo "Database -> Backend: Expected timeout (blocked)"
```

### Step 7: Create Allow Policies for Intended Traffic Flows

Allow only the intended paths: frontend to backend, and backend to database. Each policy must allow both egress from the source and ingress at the destination:

```bash
# Allow frontend -> backend (egress from frontend, ingress to backend)
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-egress-to-backend
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
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-allow-from-frontend
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

# Allow backend -> database (egress from backend, ingress to database)
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-egress-to-database
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
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-allow-from-backend
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

echo "Allow policies applied: frontend->backend, backend->database"
```

### Step 8: Verify the Complete Policy Set

Test both allowed and blocked traffic paths:

```bash
echo "=== Testing ALLOWED paths ==="

# Frontend -> Backend (should work)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://backend:8080
echo "Frontend -> Backend: ALLOWED"

# Backend -> Database (should work)
kubectl exec -n three-tier $BACKEND_POD -- wget -qO- --timeout=3 http://database:5432
echo "Backend -> Database: ALLOWED"

echo ""
echo "=== Testing BLOCKED paths ==="

# Frontend -> Database (should be blocked)
kubectl exec -n three-tier $FRONTEND_POD -- wget -qO- --timeout=3 http://database:5432 2>&1
echo "Frontend -> Database: BLOCKED"

# Database -> Backend (should be blocked)
kubectl exec -n three-tier $DATABASE_POD -- wget -qO- --timeout=3 http://backend:8080 2>&1
echo "Database -> Backend: BLOCKED"
```

### Step 9: Create a Monitoring Namespace with Cross-Namespace Access

In production, monitoring tools need to scrape metrics from application namespaces. Create a monitoring namespace and allow its pods to access the three-tier namespace:

```bash
# Create monitoring namespace and deploy a monitoring pod
kubectl create namespace monitoring
kubectl label namespace monitoring purpose=monitoring

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: prometheus-sim
  namespace: monitoring
  labels:
    app: prometheus
    role: monitoring
spec:
  containers:
    - name: monitor
      image: nginx:alpine
      command: ["sleep", "3600"]
EOF

kubectl wait --for=condition=Ready pod/prometheus-sim -n monitoring --timeout=60s

# Without a policy, cross-namespace traffic is blocked by our default-deny
kubectl exec -n monitoring prometheus-sim -- wget -qO- --timeout=3 http://frontend.three-tier.svc.cluster.local:80 2>&1
echo "Monitoring -> Frontend: Expected timeout (blocked by default-deny)"

# Create a policy to allow ingress from the monitoring namespace
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring-ingress
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

# Also allow egress from the monitoring namespace to three-tier
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-three-tier
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      role: monitoring
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
        - protocol: TCP
          port: 53
EOF

# Verify monitoring can now reach the frontend
kubectl exec -n monitoring prometheus-sim -- wget -qO- --timeout=3 http://frontend.three-tier.svc.cluster.local:80
echo "Monitoring -> Frontend: ALLOWED (cross-namespace policy)"

# Verify monitoring can reach the backend
kubectl exec -n monitoring prometheus-sim -- wget -qO- --timeout=3 http://backend.three-tier.svc.cluster.local:8080
echo "Monitoring -> Backend: ALLOWED (cross-namespace policy)"
```

### Step 10: List and Inspect All Policies in the Namespace

Audit the full set of NetworkPolicies to understand the security posture:

```bash
# List all NetworkPolicies in the three-tier namespace
echo "=== NetworkPolicies in three-tier namespace ==="
kubectl get networkpolicies -n three-tier

# Inspect each policy in detail
echo ""
echo "=== Policy Details ==="
kubectl get networkpolicies -n three-tier -o json | jq '.items[] | {name: .metadata.name, podSelector: .spec.podSelector, policyTypes: .spec.policyTypes, ingressRuleCount: (.spec.ingress // [] | length), egressRuleCount: (.spec.egress // [] | length)}'

# Check which pods are affected by each policy
echo ""
echo "=== Pods matched by each policy ==="
for POLICY in $(kubectl get networkpolicies -n three-tier -o jsonpath='{.items[*].metadata.name}'); do
  SELECTOR=$(kubectl get networkpolicy "$POLICY" -n three-tier -o jsonpath='{.spec.podSelector.matchLabels}')
  echo "Policy: $POLICY  |  Selector: $SELECTOR"
done

# List policies in monitoring namespace too
echo ""
echo "=== NetworkPolicies in monitoring namespace ==="
kubectl get networkpolicies -n monitoring
```

### Step 11: Cleanup

```bash
kubectl delete namespace three-tier monitoring

# Delete the cluster
kind delete cluster --name netpol-lab
```

## Summary

- Without NetworkPolicies, all pod-to-pod traffic is allowed by default
- Default-deny ingress AND egress policies establish a complete zero-trust baseline
- Targeted allow policies restore only the intended traffic flows (frontend to backend, backend to database)
- Always include a DNS egress policy so pods can resolve service names
- Cross-namespace policies use namespaceSelector to grant access to monitoring or other infrastructure namespaces
