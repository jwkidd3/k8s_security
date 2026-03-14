# Lab 4: Pod Security Contexts

**Duration:** 45-60 minutes

## Objectives

By the end of this lab, you will be able to:

- Configure pod-level and container-level SecurityContext settings
- Enforce Pod Security Standards using Pod Security Admission (PSA)
- Drop Linux capabilities and apply seccomp profiles
- Use LimitRange and ResourceQuota for resource-based security

## Prerequisites

- Running kind cluster (or create a new one with default config)
- `kubectl` CLI configured

## Lab Environment Setup

### Step 1: Create Lab Cluster and Namespaces

```bash
# Create cluster if needed
kind create cluster --name security-lab --config labs/setup/kind-config-default.yaml

# Create namespaces with different Pod Security Standards
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: psa-privileged
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
---
apiVersion: v1
kind: Namespace
metadata:
  name: psa-baseline
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
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
```

## Part 1: SecurityContext Basics

### Step 2: Run a Pod Without SecurityContext

```bash
# Deploy a pod with no security settings
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-security
  namespace: psa-privileged
spec:
  containers:
    - name: shell
      image: ubuntu:22.04
      command: ["sleep", "3600"]
EOF

# Check what user it runs as
kubectl exec -n psa-privileged no-security -- id
# Likely: uid=0(root) gid=0(root) groups=0(root)

# Check capabilities
kubectl exec -n psa-privileged no-security -- cat /proc/1/status | grep -i cap

# Check if filesystem is writable
kubectl exec -n psa-privileged no-security -- touch /test-write && echo "writable" || echo "read-only"
kubectl exec -n psa-privileged no-security -- rm /test-write
```

### Step 3: Apply Container-Level SecurityContext

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hardened-container
  namespace: psa-privileged
spec:
  containers:
    - name: shell
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
EOF

# Check the user
kubectl exec -n psa-privileged hardened-container -- id
# Expected: uid=1000 gid=3000

# Try to write to the filesystem
kubectl exec -n psa-privileged hardened-container -- touch /test-write 2>&1
# Expected: Read-only file system

# Check capabilities (should be empty)
kubectl exec -n psa-privileged hardened-container -- cat /proc/1/status | grep -i capeff
```

### Step 4: Add Writable Volumes

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hardened-with-volumes
  namespace: psa-privileged
spec:
  containers:
    - name: app
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /var/cache
  volumes:
    - name: tmp
      emptyDir: {}
    - name: cache
      emptyDir:
        sizeLimit: 100Mi
EOF

# Verify: root filesystem is read-only but /tmp is writable
kubectl exec -n psa-privileged hardened-with-volumes -- touch /test 2>&1
kubectl exec -n psa-privileged hardened-with-volumes -- touch /tmp/test && echo "tmp is writable"
```

## Part 2: Pod Security Admission (PSA)

### Step 5: Test Baseline Enforcement

```bash
# Try to create a privileged pod in the baseline namespace
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

# Try hostNetwork (also blocked by baseline)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hostnetwork-pod
  namespace: psa-baseline
spec:
  hostNetwork: true
  containers:
    - name: shell
      image: ubuntu:22.04
      command: ["sleep", "3600"]
EOF
# Expected: DENIED

# A simple pod should work in baseline
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
# Expected: Created (baseline allows running as root, etc.)
```

### Step 6: Test Restricted Enforcement

```bash
# Try the simple pod in restricted namespace
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

# Create a pod that passes restricted
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
```

### Step 7: Observe PSA Warnings and Audit Annotations

```bash
# The baseline namespace is set to warn on restricted violations
# Deploy a pod that passes baseline but violates restricted
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: warning-test
  namespace: psa-baseline
spec:
  containers:
    - name: shell
      image: ubuntu:22.04
      command: ["sleep", "3600"]
EOF
# Observe: You should see warnings about restricted standard violations
```

## Part 3: Linux Capabilities

### Step 8: Explore Default Capabilities

```bash
# See the default capabilities of a container
kubectl exec -n psa-privileged no-security -- grep Cap /proc/1/status

# Decode the capability bitmask
kubectl exec -n psa-privileged no-security -- sh -c 'apt-get update -qq && apt-get install -y -qq libcap2-bin > /dev/null 2>&1 && capsh --decode=$(grep CapEff /proc/1/status | awk "{print \$2}")'
```

### Step 9: Drop All and Add Specific Capabilities

```bash
# Pod that needs to bind to port 80 (needs NET_BIND_SERVICE)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: net-bind-pod
  namespace: psa-privileged
spec:
  containers:
    - name: web
      image: nginx:alpine
      securityContext:
        runAsUser: 0
        capabilities:
          drop:
            - ALL
          add:
            - NET_BIND_SERVICE
EOF

kubectl wait --for=condition=Ready pod/net-bind-pod -n psa-privileged --timeout=60s

# Verify only NET_BIND_SERVICE is available
kubectl exec -n psa-privileged net-bind-pod -- cat /proc/1/status | grep -i cap
```

## Part 4: Seccomp Profiles

### Step 10: Apply RuntimeDefault Seccomp Profile

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-default
  namespace: psa-privileged
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: shell
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      securityContext:
        allowPrivilegeEscalation: false
EOF

# The RuntimeDefault profile blocks dangerous syscalls
# Try operations that should be blocked
kubectl exec -n psa-privileged seccomp-default -- unshare --user 2>&1
# May be blocked depending on the runtime's default seccomp profile
```

## Part 5: Resource Limits as Security

### Step 11: Create ResourceQuota and LimitRange

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: security-quota
  namespace: psa-baseline
spec:
  hard:
    pods: "10"
    requests.cpu: "4"
    requests.memory: 4Gi
    limits.cpu: "8"
    limits.memory: 8Gi
---
apiVersion: v1
kind: LimitRange
metadata:
  name: security-limits
  namespace: psa-baseline
spec:
  limits:
    - default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
      min:
        cpu: 50m
        memory: 64Mi
      type: Container
EOF
```

### Step 12: Test Resource Limits

```bash
# Deploy without resource requests (LimitRange will inject defaults)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: default-resources
  namespace: psa-baseline
spec:
  containers:
    - name: app
      image: ubuntu:22.04
      command: ["sleep", "3600"]
EOF

# Check the injected resource limits
kubectl get pod default-resources -n psa-baseline -o jsonpath='{.spec.containers[0].resources}' | python3 -m json.tool

# Try to exceed limits
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: excessive-resources
  namespace: psa-baseline
spec:
  containers:
    - name: app
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      resources:
        requests:
          cpu: "4"
          memory: 4Gi
        limits:
          cpu: "4"
          memory: 4Gi
EOF
# Expected: Denied by LimitRange (max is 2 CPU / 1Gi)
```

### Step 13: View ResourceQuota Usage

```bash
kubectl describe resourcequota security-quota -n psa-baseline
```

## Cleanup

```bash
kubectl delete namespace psa-privileged psa-baseline psa-restricted

# (Optional) Delete the cluster
# kind delete cluster --name security-lab
```

## Summary

In this lab, you:
- Configured SecurityContext at both pod and container levels
- Enforced Pod Security Standards (Privileged, Baseline, Restricted) using PSA labels
- Dropped all Linux capabilities and selectively added required ones
- Applied seccomp profiles for syscall filtering
- Used ResourceQuota and LimitRange to prevent resource-based attacks

Key takeaway: Defense in depth — combine SecurityContext, PSA, capabilities, seccomp, and resource limits for comprehensive pod security.
