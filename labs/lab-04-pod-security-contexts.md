# Lab 4: Pod Security Contexts

**Duration:** 40 minutes

## Objectives

By the end of this lab, you will be able to:

- Enforce Pod Security Standards using Pod Security Admission (PSA)
- Configure SecurityContext settings for hardened pods
- Explore and manage Linux capabilities on containers
- Apply seccomp profiles for syscall filtering
- Set default resource limits and quotas for namespaces

## Prerequisites

- Cloud9 environment (Amazon Linux) with Docker
- `kubectl` and `kind` installed

---

### Step 1: Create Namespaces with PSA Labels

Create two namespaces with different Pod Security Standards enforced via labels:

```bash
# Create cluster if needed
kind create cluster --name security-lab --config labs/setup/kind-config-default.yaml

# Create namespaces with PSA enforcement
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: psa-baseline
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: baseline
    pod-security.kubernetes.io/warn: baseline
---
apiVersion: v1
kind: Namespace
metadata:
  name: psa-restricted
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
EOF

# Verify namespace labels
kubectl get namespace psa-baseline --show-labels
kubectl get namespace psa-restricted --show-labels
```

### Step 2: Test PSA Enforcement in the Baseline Namespace

Try deploying a privileged pod to the baseline namespace. The baseline standard blocks privileged containers:

```bash
# Attempt to deploy a privileged pod (should be REJECTED)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: psa-baseline
spec:
  containers:
    - name: shell
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
EOF
# Expected: DENIED — baseline does not allow privileged containers

# A simple pod without privileged settings should succeed
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: simple-pod
  namespace: psa-baseline
spec:
  containers:
    - name: shell
      image: ubuntu:22.04
      command: ["sleep", "3600"]
EOF
# Expected: Created

kubectl wait --for=condition=Ready pod/simple-pod -n psa-baseline --timeout=60s
```

### Step 3: Explore Default Capabilities on an Unprivileged Container

Before dropping capabilities, examine what a default unprivileged container receives:

```bash
# Check the default capabilities on the simple pod
kubectl exec -n psa-baseline simple-pod -- cat /proc/1/status | grep -i cap

# Decode the capability bitmask — CapEff shows effective capabilities
# On a default container you will see capabilities like:
# CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID, SETPCAP,
# NET_BIND_SERVICE, NET_RAW, SYS_CHOWN, MKNOD, AUDIT_WRITE, SETFCAP
CAPEFF=$(kubectl exec -n psa-baseline simple-pod -- cat /proc/1/status | grep CapEff | awk '{print $2}')
echo "Effective capabilities bitmask: $CAPEFF"

# If capsh is available, decode the bitmask
kubectl exec -n psa-baseline simple-pod -- sh -c "apt-get update -qq && apt-get install -qq -y libcap2-bin > /dev/null 2>&1 && capsh --decode=$CAPEFF" 2>/dev/null || echo "(capsh not available — use the bitmask above for reference)"

# Key takeaway: default containers get a broad set of capabilities
# Many of these are unnecessary for typical application workloads
```

### Step 4: Deploy a Pod with Proper SecurityContext

Deploy a hardened pod with read-only root filesystem, non-root user, and all capabilities dropped:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
  namespace: psa-baseline
spec:
  containers:
    - name: app
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 3000
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir: {}
EOF

kubectl wait --for=condition=Ready pod/hardened-pod -n psa-baseline --timeout=60s
```

### Step 5: Verify the Security Context Is Applied

Exec into the hardened pod and confirm the security settings are in effect:

```bash
# Check the running user
kubectl exec -n psa-baseline hardened-pod -- id
# Expected: uid=1000 gid=3000

# Try to write to the root filesystem (should fail)
kubectl exec -n psa-baseline hardened-pod -- touch /test-write 2>&1
# Expected: Read-only file system

# Confirm /tmp is writable (emptyDir mount)
kubectl exec -n psa-baseline hardened-pod -- touch /tmp/test-write && echo "/tmp is writable"

# Check capabilities (should be empty — all dropped)
kubectl exec -n psa-baseline hardened-pod -- cat /proc/1/status | grep -i capeff
# Expected: CapEff value of 0000000000000000
```

### Step 6: Drop All Capabilities and Add Back Only Specific Ones

In practice, you drop ALL capabilities and selectively add back only what the application requires. Here we add NET_BIND_SERVICE so the container can bind to ports below 1024:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: netbind-pod
  namespace: psa-baseline
spec:
  containers:
    - name: app
      image: nginx:alpine
      ports:
        - containerPort: 80
      securityContext:
        runAsUser: 0
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
          add:
            - NET_BIND_SERVICE
EOF

kubectl wait --for=condition=Ready pod/netbind-pod -n psa-baseline --timeout=60s

# Verify the pod is running — nginx needs NET_BIND_SERVICE to bind port 80
kubectl exec -n psa-baseline netbind-pod -- wget -qO- --timeout=3 http://127.0.0.1:80 | head -5
echo "nginx is serving on port 80 with only NET_BIND_SERVICE capability"

# Confirm that only NET_BIND_SERVICE is in the effective set
kubectl exec -n psa-baseline netbind-pod -- cat /proc/1/status | grep -i cap

# Now deploy a pod that drops ALL capabilities with no add-backs, running nginx
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-caps-nginx
  namespace: psa-baseline
spec:
  containers:
    - name: app
      image: nginx:alpine
      ports:
        - containerPort: 80
      securityContext:
        runAsUser: 0
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
EOF

# Wait briefly and check the pod status — it should fail because
# nginx cannot bind to port 80 without NET_BIND_SERVICE
sleep 10
kubectl get pod no-caps-nginx -n psa-baseline
kubectl logs no-caps-nginx -n psa-baseline 2>&1 | tail -5
echo "Without NET_BIND_SERVICE, nginx cannot bind to port 80"
```

### Step 7: Test Restricted Namespace Enforcement

The restricted standard requires runAsNonRoot, drop ALL capabilities, seccomp profile, and more:

```bash
# A simple pod will be REJECTED in the restricted namespace
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: simple-pod
  namespace: psa-restricted
spec:
  containers:
    - name: shell
      image: ubuntu:22.04
      command: ["sleep", "3600"]
EOF
# Expected: DENIED — restricted requires runAsNonRoot, drop ALL, seccomp, etc.

# Deploy a pod that meets all restricted requirements
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
  namespace: psa-restricted
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir: {}
EOF
# Expected: Created

kubectl wait --for=condition=Ready pod/restricted-pod -n psa-restricted --timeout=60s
kubectl get pods -n psa-restricted
```

### Step 8: Apply Seccomp Profile and Verify

Deploy a pod with an explicit RuntimeDefault seccomp profile in the baseline namespace and verify it works:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-pod
  namespace: psa-baseline
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: shell
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
EOF

kubectl wait --for=condition=Ready pod/seccomp-pod -n psa-baseline --timeout=60s

# Verify the seccomp profile is set
kubectl get pod seccomp-pod -n psa-baseline -o jsonpath='{.spec.securityContext.seccompProfile}' | jq .

# The RuntimeDefault profile blocks dangerous syscalls like unshare
kubectl exec -n psa-baseline seccomp-pod -- unshare --user 2>&1
# Expected: Operation not permitted (blocked by seccomp)
```

### Step 9: Create a LimitRange and ResourceQuota

Enforce resource governance at the namespace level with default limits and quotas:

```bash
# Create a LimitRange — sets default CPU/memory requests and limits for
# any pod that does not specify them
kubectl apply -f - <<EOF
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: psa-baseline
spec:
  limits:
    - default:
        cpu: "500m"
        memory: "256Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
      max:
        cpu: "1"
        memory: "512Mi"
      min:
        cpu: "50m"
        memory: "64Mi"
      type: Container
EOF

# Verify the LimitRange
kubectl describe limitrange default-limits -n psa-baseline

# Create a ResourceQuota — caps the total resources the namespace can consume
kubectl apply -f - <<EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: namespace-quota
  namespace: psa-baseline
spec:
  hard:
    requests.cpu: "2"
    requests.memory: "1Gi"
    limits.cpu: "4"
    limits.memory: "2Gi"
    pods: "10"
    secrets: "10"
    configmaps: "10"
EOF

# Verify the ResourceQuota
kubectl describe resourcequota namespace-quota -n psa-baseline

# Deploy a pod to see the LimitRange defaults applied automatically
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: auto-limits-pod
  namespace: psa-baseline
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
EOF

kubectl wait --for=condition=Ready pod/auto-limits-pod -n psa-baseline --timeout=60s

# Check that default resource requests/limits were injected
kubectl get pod auto-limits-pod -n psa-baseline -o jsonpath='{.spec.containers[0].resources}' | jq .
# Expected: requests and limits populated by the LimitRange

# Verify the quota usage updated
kubectl describe resourcequota namespace-quota -n psa-baseline

# Try to exceed the quota by requesting too much memory
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: over-quota-pod
  namespace: psa-baseline
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
      resources:
        requests:
          memory: "2Gi"
        limits:
          memory: "3Gi"
EOF
# Expected: DENIED — exceeds the LimitRange per-container maximum of 512Mi memory
```

### Step 10: Cleanup

```bash
kubectl delete namespace psa-baseline psa-restricted

# (Optional) Delete the cluster
# kind delete cluster --name security-lab
```

## Summary

- PSA labels on namespaces enforce Pod Security Standards (baseline, restricted) at admission time
- Default unprivileged containers receive a broad set of Linux capabilities that should be reduced
- Drop ALL capabilities and selectively add back only what the application needs (e.g., NET_BIND_SERVICE)
- Seccomp profiles filter dangerous syscalls at the kernel level
- LimitRanges and ResourceQuotas enforce resource governance, preventing pods from consuming unbounded resources
