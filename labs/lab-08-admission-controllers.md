# Lab 8: Admission Controllers

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Install and configure Kyverno as a policy engine
- Create validate, mutate, and generate policies
- Test policy enforcement with compliant and non-compliant resources
- Use Kyverno policy reports for compliance visibility

## Prerequisites

- Running kind cluster (or create a new one with default config)
- `kubectl` and `helm` CLI configured

## Lab Environment Setup

### Step 1: Create Lab Cluster

```bash
# Create cluster if needed
kind create cluster --name security-lab --config labs/setup/kind-config-default.yaml

# Create lab namespace
kubectl create namespace policy-lab
```

### Step 2: Install Kyverno

```bash
# Add Kyverno Helm repo
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

# Install Kyverno
helm install kyverno kyverno/kyverno \
  -n kyverno --create-namespace \
  --set resources.requests.cpu=100m \
  --set resources.requests.memory=128Mi

# Wait for Kyverno to be ready
kubectl wait --for=condition=Ready pods --all -n kyverno --timeout=180s

echo "Kyverno installed and running"
kubectl get pods -n kyverno
```

## Part 1: Validation Policies

### Step 3: Require Labels on All Pods

```bash
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-app-label
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - policy-lab
      validate:
        message: "The label 'app' is required on all pods."
        pattern:
          metadata:
            labels:
              app: "?*"
    - name: require-team-label
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - policy-lab
      validate:
        message: "The label 'team' is required on all pods."
        pattern:
          metadata:
            labels:
              team: "?*"
EOF

echo "Policy 'require-labels' created in Enforce mode"
```

### Step 4: Test Label Requirement

```bash
# Try to create a pod without labels (should FAIL)
kubectl run unlabeled --image=nginx:alpine -n policy-lab 2>&1
echo "Expected: Blocked by require-labels policy"

# Create a pod with required labels (should SUCCEED)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: labeled-pod
  namespace: policy-lab
  labels:
    app: web-server
    team: platform
spec:
  containers:
    - name: web
      image: nginx:alpine
EOF
echo "Expected: Created successfully"

# Verify
kubectl get pods -n policy-lab --show-labels
```

### Step 5: Block `latest` Tag

```bash
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-image-tag
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - policy-lab
      validate:
        message: "Using 'latest' tag is not allowed. Specify a specific version tag."
        pattern:
          spec:
            containers:
              - image: "!*:latest"
    - name: require-tag-not-empty
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - policy-lab
      validate:
        message: "An image tag is required (images without tags default to 'latest')."
        pattern:
          spec:
            containers:
              - image: "*:*"
EOF
```

### Step 6: Test Latest Tag Blocking

```bash
# Try using :latest tag (should FAIL)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: latest-tag
  namespace: policy-lab
  labels:
    app: test
    team: test
spec:
  containers:
    - name: web
      image: nginx:latest
EOF
echo "Expected: Blocked - latest tag not allowed"

# Try without a tag (should FAIL - defaults to latest)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-tag
  namespace: policy-lab
  labels:
    app: test
    team: test
spec:
  containers:
    - name: web
      image: nginx
EOF
echo "Expected: Blocked - no tag specified"

# Use a specific tag (should SUCCEED)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: versioned-pod
  namespace: policy-lab
  labels:
    app: test
    team: test
spec:
  containers:
    - name: web
      image: nginx:1.25-alpine
EOF
echo "Expected: Created successfully"
```

### Step 7: Enforce Resource Limits

```bash
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-limits
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - policy-lab
      validate:
        message: "CPU and memory limits are required for all containers."
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    memory: "?*"
                    cpu: "?*"
EOF
```

### Step 8: Test Resource Limits Policy

```bash
# Pod without limits (should FAIL)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-limits
  namespace: policy-lab
  labels:
    app: test
    team: test
spec:
  containers:
    - name: web
      image: nginx:1.25-alpine
EOF
echo "Expected: Blocked - no resource limits"

# Pod with limits (should SUCCEED)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: with-limits
  namespace: policy-lab
  labels:
    app: test
    team: test
spec:
  containers:
    - name: web
      image: nginx:1.25-alpine
      resources:
        limits:
          cpu: 200m
          memory: 128Mi
        requests:
          cpu: 100m
          memory: 64Mi
EOF
echo "Expected: Created successfully"
```

## Part 2: Mutation Policies

### Step 9: Auto-Add Security Defaults

```bash
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-default-securitycontext
spec:
  background: false
  rules:
    - name: add-run-as-non-root
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - policy-lab
      mutate:
        patchStrategicMerge:
          spec:
            securityContext:
              runAsNonRoot: true
              seccompProfile:
                type: RuntimeDefault
            containers:
              - (name): "*"
                securityContext:
                  allowPrivilegeEscalation: false
                  capabilities:
                    drop:
                      - ALL
EOF
```

### Step 10: Test Mutation

```bash
# Create a pod without security context
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: mutated-pod
  namespace: policy-lab
  labels:
    app: test
    team: test
spec:
  containers:
    - name: web
      image: nginx:1.25-alpine
      resources:
        limits:
          cpu: 200m
          memory: 128Mi
EOF

# Check that security context was automatically added
kubectl get pod mutated-pod -n policy-lab -o jsonpath='{.spec.securityContext}' | python3 -m json.tool
kubectl get pod mutated-pod -n policy-lab -o jsonpath='{.spec.containers[0].securityContext}' | python3 -m json.tool
```

## Part 3: Generate Policies

### Step 11: Auto-Generate NetworkPolicies

```bash
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: generate-default-deny
spec:
  background: false
  rules:
    - name: default-deny-ingress
      match:
        any:
          - resources:
              kinds:
                - Namespace
              selector:
                matchLabels:
                  security-policies: enabled
      generate:
        synchronize: true
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        name: default-deny-ingress
        namespace: "{{request.object.metadata.name}}"
        data:
          metadata:
            labels:
              generated-by: kyverno
          spec:
            podSelector: {}
            policyTypes:
              - Ingress
    - name: default-deny-egress
      match:
        any:
          - resources:
              kinds:
                - Namespace
              selector:
                matchLabels:
                  security-policies: enabled
      generate:
        synchronize: true
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        name: default-deny-egress
        namespace: "{{request.object.metadata.name}}"
        data:
          metadata:
            labels:
              generated-by: kyverno
          spec:
            podSelector: {}
            policyTypes:
              - Egress
EOF
```

### Step 12: Test Generate Policy

```bash
# Create a namespace with the label
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: auto-secured
  labels:
    security-policies: enabled
EOF

# Check that network policies were auto-generated
sleep 5
kubectl get networkpolicies -n auto-secured
echo "Expected: default-deny-ingress and default-deny-egress"
```

## Part 4: Policy Reports

### Step 13: View Policy Reports

```bash
# List policy reports
kubectl get policyreport -A 2>/dev/null || kubectl get polr -A

# Get detailed report for our namespace
kubectl get policyreport -n policy-lab -o yaml 2>/dev/null | head -50

# Check cluster-level reports
kubectl get clusterpolicyreport -o yaml 2>/dev/null | head -50
```

### Step 14: Create a Compliance Dashboard View

```bash
# List all policies and their status
echo "=== Active Kyverno Policies ==="
kubectl get clusterpolicies

echo ""
echo "=== Policy Compliance Summary ==="
for policy in $(kubectl get clusterpolicies -o jsonpath='{.items[*].metadata.name}'); do
  echo "Policy: $policy"
  action=$(kubectl get clusterpolicy $policy -o jsonpath='{.spec.validationFailureAction}')
  echo "  Action: $action"
  rules=$(kubectl get clusterpolicy $policy -o jsonpath='{.spec.rules[*].name}')
  echo "  Rules: $rules"
  echo ""
done
```

## Part 5: Advanced — Block Privileged Pods

### Step 15: Create a Comprehensive Security Policy

```bash
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: pod-security-hardening
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: deny-privileged
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - policy-lab
      validate:
        message: "Privileged containers are not allowed."
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): false
    - name: deny-host-namespaces
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - policy-lab
      validate:
        message: "Host namespaces (hostPID, hostIPC, hostNetwork) are not allowed."
        pattern:
          spec:
            =(hostPID): false
            =(hostIPC): false
            =(hostNetwork): false
EOF
```

### Step 16: Test Security Policy

```bash
# Try privileged pod (should FAIL)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged-test
  namespace: policy-lab
  labels:
    app: test
    team: test
spec:
  containers:
    - name: web
      image: nginx:1.25-alpine
      securityContext:
        privileged: true
      resources:
        limits:
          cpu: 200m
          memory: 128Mi
EOF
echo "Expected: Blocked - privileged not allowed"

# Try hostNetwork (should FAIL)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hostnet-test
  namespace: policy-lab
  labels:
    app: test
    team: test
spec:
  hostNetwork: true
  containers:
    - name: web
      image: nginx:1.25-alpine
      resources:
        limits:
          cpu: 200m
          memory: 128Mi
EOF
echo "Expected: Blocked - hostNetwork not allowed"
```

## Cleanup

```bash
# Delete lab resources
kubectl delete namespace policy-lab auto-secured

# Delete Kyverno policies
kubectl delete clusterpolicy require-labels disallow-latest-tag require-resource-limits add-default-securitycontext generate-default-deny pod-security-hardening

# Uninstall Kyverno
helm uninstall kyverno -n kyverno
kubectl delete namespace kyverno

# (Optional) Delete the cluster
# kind delete cluster --name security-lab
```

## Summary

In this lab, you:
- Installed Kyverno as a policy engine
- Created validation policies to require labels, block `latest` tags, and enforce resource limits
- Used mutation policies to auto-inject security contexts
- Created generate policies to auto-create NetworkPolicies for labeled namespaces
- Viewed policy reports for compliance visibility
- Blocked privileged containers and host namespace access

Key takeaway: Admission controllers are the enforcement point between "what you ask for" and "what you get." Use them to codify security policies and prevent misconfigurations before they reach the cluster.
