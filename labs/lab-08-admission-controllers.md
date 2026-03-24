# Lab 8: Admission Controllers

**Duration:** 40 minutes

## Objectives

By the end of this lab, you will be able to:

- Install and configure Kyverno as a policy engine
- Create validation policies to enforce labeling and image tag standards
- Create mutation policies to auto-inject security contexts
- Create generate policies to auto-create resources when namespaces are created
- View Kyverno policy reports to assess cluster compliance
- Test policy enforcement with compliant and non-compliant resources

## Prerequisites

- Cloud9 environment from Lab 1 (m5.large, us-east-1)
- Tools installed from Lab 1 (`kind`, `kubectl`)
- `helm` CLI installed (from Lab 6, or run: see install commands in Lab 6 Step 6)

---

### Step 1: Install Kyverno via Helm

```bash
# Create lab namespace
kubectl create namespace policy-lab

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

### Step 2: Create Policy — Require Labels on All Pods

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

### Step 3: Test Enforcement — Labels

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

### Step 4: Create Policy — Block Latest Tag

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

# Test: latest tag (should FAIL)
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

# Test: specific tag (should SUCCEED)
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

### Step 5: Create Mutation Policy — Add Default Security Context

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

echo "Mutation policy created"
```

### Step 6: Test Mutation — Verify Security Context Injection

```bash
# Create a pod without any security context
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
      image: nginxinc/nginx-unprivileged:1.25-alpine
      resources:
        limits:
          cpu: 200m
          memory: 128Mi
EOF

# Verify that pod-level security context was injected
echo "=== Pod Security Context ==="
kubectl get pod mutated-pod -n policy-lab -o jsonpath='{.spec.securityContext}' | jq .

# Verify that container-level security context was injected
echo "=== Container Security Context ==="
kubectl get pod mutated-pod -n policy-lab -o jsonpath='{.spec.containers[0].securityContext}' | jq .
```

### Step 7: Create Generate Policy — Auto-Create NetworkPolicy for New Namespaces

```bash
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: generate-default-networkpolicy
spec:
  background: false
  rules:
    - name: default-deny-ingress
      match:
        any:
          - resources:
              kinds:
                - Namespace
      exclude:
        any:
          - resources:
              names:
                - kube-system
                - kyverno
                - falco
      generate:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        name: default-deny-ingress
        namespace: "{{request.object.metadata.name}}"
        synchronize: true
        data:
          spec:
            podSelector: {}
            policyTypes:
              - Ingress
EOF

echo "Generate policy created: new namespaces will automatically get a default-deny ingress NetworkPolicy"
```

### Step 8: Test the Generate Policy

```bash
# Create a new namespace — the NetworkPolicy should be auto-generated
kubectl create namespace test-generated

# Wait a moment for Kyverno to generate the resource
sleep 5

# Verify the NetworkPolicy was auto-created
echo "=== NetworkPolicies in test-generated namespace ==="
kubectl get networkpolicy -n test-generated

# Inspect the generated NetworkPolicy
echo ""
echo "=== NetworkPolicy Details ==="
kubectl get networkpolicy default-deny-ingress -n test-generated -o yaml

# Create another namespace to confirm it works consistently
kubectl create namespace test-generated-2
sleep 5
echo ""
echo "=== NetworkPolicies in test-generated-2 namespace ==="
kubectl get networkpolicy -n test-generated-2

echo ""
echo "Every new namespace now starts with a default-deny ingress policy"
```

### Step 9: View Kyverno Policy Reports

```bash
# List all cluster-level policy reports
echo "=== Cluster Policy Reports ==="
kubectl get clusterpolicyreport

# View detailed results from policy reports
echo ""
echo "=== Policy Report Results ==="
kubectl get clusterpolicyreport -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .results[*]}  Rule: {.rule} | Result: {.result} | Resource: {.resources[0].name}{"\n"}{end}{end}'

# Check namespace-level policy reports
echo ""
echo "=== Namespace Policy Reports ==="
kubectl get policyreport --all-namespaces

# Summarize compliance status
echo ""
echo "=== Compliance Summary ==="
kubectl get policyreport --all-namespaces -o json | jq -r '
  [.items[].results[]?.result // empty] |
  group_by(.) |
  map({status: .[0], count: length}) |
  sort_by(-.count) |
  .[] | "\(.count)\t\(.status)"
'

echo ""
echo "Policy reports provide an audit trail of which resources pass or fail policy checks"
```

### Step 10: Cleanup

```bash
# Delete lab resources
kubectl delete namespace policy-lab
kubectl delete namespace test-generated
kubectl delete namespace test-generated-2

# Delete Kyverno policies
kubectl delete clusterpolicy require-labels disallow-latest-tag add-default-securitycontext generate-default-networkpolicy

# Uninstall Kyverno
helm uninstall kyverno -n kyverno
kubectl delete namespace kyverno
```

## Summary

- Kyverno validation policies enforce standards (required labels, banned image tags) at admission time
- Mutation policies automatically inject security defaults so developers do not need to remember every setting
- Generate policies auto-create resources like default-deny NetworkPolicies when new namespaces are provisioned
- Policy reports provide a compliance dashboard showing which resources pass or fail each policy rule
- Enforce mode blocks non-compliant resources immediately, preventing misconfigurations from reaching the cluster
