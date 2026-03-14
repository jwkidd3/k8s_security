# Lab 7: Secure Container Images

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Scan container images for vulnerabilities using Trivy
- Sign and verify container images using cosign
- Generate and analyze Software Bills of Materials (SBOMs) with Syft
- Lint Dockerfiles with hadolint for security best practices
- Set up a local container registry for testing

## Prerequisites

- Running kind cluster (or create a new one with default config)
- Docker installed
- `kubectl` CLI configured

## Lab Environment Setup

### Step 1: Create Lab Cluster and Install Tools

```bash
# Create cluster if needed
kind create cluster --name security-lab --config labs/setup/kind-config-default.yaml
```

### Step 2: Install Required Tools

```bash
# Install Trivy (if not already installed)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin

# Install cosign
curl -LO https://github.com/sigstore/cosign/releases/download/v2.2.2/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Install hadolint
curl -LO https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64
chmod +x hadolint-Linux-x86_64
sudo mv hadolint-Linux-x86_64 /usr/local/bin/hadolint
```

### Step 3: Set Up a Local Registry

```bash
# Create a local registry container
docker run -d --restart=always -p 5001:5000 --name local-registry registry:2

# Connect the registry to kind network (if using kind)
docker network connect kind local-registry 2>/dev/null || true

echo "Local registry running at localhost:5001"
```

## Part 1: Dockerfile Security Best Practices

### Step 4: Create an Insecure Dockerfile

```bash
mkdir -p /tmp/image-lab
cat > /tmp/image-lab/Dockerfile.insecure <<'EOF'
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl wget netcat python3
COPY . /app
WORKDIR /app
RUN echo "SECRET_KEY=hardcoded123" >> /app/.env
EXPOSE 8080
USER root
CMD ["python3", "-m", "http.server", "8080"]
EOF

# Create a simple app file
echo "print('Hello from insecure app')" > /tmp/image-lab/app.py
```

### Step 5: Lint the Insecure Dockerfile

```bash
hadolint /tmp/image-lab/Dockerfile.insecure
```

**Expected issues:**
- Using `latest` tag
- Running as root
- Not pinning package versions
- Multiple `RUN` commands that should be combined

### Step 6: Create a Secure Dockerfile

```bash
cat > /tmp/image-lab/Dockerfile.secure <<'EOF'
# Use a specific, minimal base image
FROM python:3.12-slim-bookworm AS builder

# Install only necessary packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      tini=0.19.* && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy application files
WORKDIR /app
COPY app.py .

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Use tini as init
ENTRYPOINT ["tini", "--"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080')" || exit 1

EXPOSE 8080
CMD ["python3", "-m", "http.server", "8080"]
EOF

# Lint the secure Dockerfile
hadolint /tmp/image-lab/Dockerfile.secure
```

### Step 7: Build Both Images

```bash
cd /tmp/image-lab

# Build insecure image
docker build -t localhost:5001/insecure-app:v1 -f Dockerfile.insecure .

# Build secure image
docker build -t localhost:5001/secure-app:v1 -f Dockerfile.secure .

# Compare image sizes
docker images | grep -E "insecure-app|secure-app"
```

## Part 2: Vulnerability Scanning with Trivy

### Step 8: Scan the Insecure Image

```bash
# Full vulnerability scan
trivy image --severity HIGH,CRITICAL localhost:5001/insecure-app:v1

# Count vulnerabilities by severity
echo ""
echo "=== Vulnerability Summary ==="
trivy image --severity CRITICAL localhost:5001/insecure-app:v1 --quiet 2>/dev/null | tail -5
```

### Step 9: Scan the Secure Image

```bash
trivy image --severity HIGH,CRITICAL localhost:5001/secure-app:v1

echo ""
echo "Compare: The secure image should have significantly fewer vulnerabilities"
```

### Step 10: Scan for Misconfigurations

```bash
# Trivy can also scan Dockerfiles for misconfigurations
trivy config /tmp/image-lab/Dockerfile.insecure
echo ""
trivy config /tmp/image-lab/Dockerfile.secure
```

### Step 11: Scan for Secrets in Images

```bash
# Scan for hardcoded secrets
trivy image --scanners secret localhost:5001/insecure-app:v1

echo ""
echo "The insecure image contains hardcoded secrets in .env file"
```

## Part 3: SBOM Generation with Syft

### Step 12: Generate an SBOM

```bash
# Generate SBOM in CycloneDX format
syft localhost:5001/secure-app:v1 -o cyclonedx-json > /tmp/image-lab/sbom-secure.json

# Generate SBOM in SPDX format
syft localhost:5001/secure-app:v1 -o spdx-json > /tmp/image-lab/sbom-secure-spdx.json

# View SBOM summary
echo "=== SBOM Package Count ==="
cat /tmp/image-lab/sbom-secure.json | python3 -c "import json,sys; data=json.load(sys.stdin); print(f'Components: {len(data.get(\"components\", []))}')"

# List packages in the image
syft localhost:5001/secure-app:v1 --output table | head -30
```

### Step 13: Scan SBOM for Vulnerabilities

```bash
# Use Grype to scan the SBOM
grype sbom:/tmp/image-lab/sbom-secure.json

echo ""
echo "Grype can scan SBOMs without needing the original image"
echo "This enables offline vulnerability scanning"
```

## Part 4: Image Signing with cosign

### Step 14: Generate a Signing Key Pair

```bash
# Generate a cosign key pair
cd /tmp/image-lab
COSIGN_PASSWORD="" cosign generate-key-pair

# This creates cosign.key (private) and cosign.pub (public)
ls -la cosign.*
```

### Step 15: Push and Sign an Image

```bash
# Push the secure image to the local registry
docker push localhost:5001/secure-app:v1

# Sign the image
COSIGN_PASSWORD="" cosign sign --key /tmp/image-lab/cosign.key --tlog-upload=false localhost:5001/secure-app:v1

echo "Image signed successfully"
```

### Step 16: Verify the Image Signature

```bash
# Verify the signature
cosign verify --key /tmp/image-lab/cosign.pub --insecure-ignore-tlog localhost:5001/secure-app:v1

echo ""
echo "Image signature verified successfully"

# Try to verify an unsigned image
cosign verify --key /tmp/image-lab/cosign.pub --insecure-ignore-tlog localhost:5001/insecure-app:v1 2>&1 || echo "Unsigned image: verification failed (expected)"
```

## Part 5: Image Digest Pinning

### Step 17: Use Image Digests Instead of Tags

```bash
# Get the image digest
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' localhost:5001/secure-app:v1 2>/dev/null || \
  crane digest localhost:5001/secure-app:v1 2>/dev/null || \
  echo "sha256:unknown")

echo "Image digest: $DIGEST"

# Deploy using digest instead of tag
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: digest-pinned
  namespace: default
spec:
  containers:
    - name: app
      image: localhost:5001/secure-app@${DIGEST}
      ports:
        - containerPort: 8080
EOF

echo ""
echo "Using digests prevents tag mutation attacks"
echo "Tags can be overwritten, but digests are immutable"
```

## Part 6: Putting It All Together

### Step 18: Secure Image Pipeline Summary

```bash
echo "=== Secure Container Image Pipeline ==="
echo ""
echo "1. WRITE: Use hadolint to lint Dockerfiles"
echo "   hadolint Dockerfile"
echo ""
echo "2. BUILD: Use multi-stage builds with minimal base images"
echo "   docker build -t myapp:v1 ."
echo ""
echo "3. SCAN: Use Trivy for vulnerability and secret scanning"
echo "   trivy image --severity HIGH,CRITICAL myapp:v1"
echo ""
echo "4. GENERATE SBOM: Use Syft for software inventory"
echo "   syft myapp:v1 -o cyclonedx-json > sbom.json"
echo ""
echo "5. SIGN: Use cosign to sign verified images"
echo "   cosign sign --key cosign.key myregistry/myapp:v1"
echo ""
echo "6. DEPLOY: Use digest pinning in Kubernetes manifests"
echo "   image: myregistry/myapp@sha256:abc123..."
echo ""
echo "7. ENFORCE: Use admission controllers to require signatures"
echo "   (Covered in Lab 8)"
```

## Cleanup

```bash
# Remove lab resources
kubectl delete pod digest-pinned --ignore-not-found
docker rm -f local-registry
rm -rf /tmp/image-lab

# (Optional) Delete the cluster
# kind delete cluster --name security-lab
```

## Summary

In this lab, you:
- Compared insecure vs secure Dockerfiles and linted them with hadolint
- Scanned images for vulnerabilities, misconfigurations, and secrets with Trivy
- Generated SBOMs with Syft and scanned them with Grype
- Signed and verified container images with cosign
- Used image digest pinning for immutable deployments

Key takeaway: Secure images require a pipeline approach — lint, build, scan, sign, pin. Each step catches different classes of issues.
