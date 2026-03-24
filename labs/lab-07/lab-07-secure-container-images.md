# Lab 7: Secure Container Images

**Duration:** 60 minutes

## Objectives

By the end of this lab, you will be able to:

- Scan container images for vulnerabilities using Trivy
- Scan images for embedded secrets using Trivy's secret scanner
- Lint Dockerfiles with hadolint for security best practices
- Generate Software Bills of Materials (SBOMs) with Syft
- Scan SBOMs for vulnerabilities using Grype
- Sign and verify container images using cosign
- Use image digest pinning for immutable deployments

## Prerequisites

- Cloud9 environment from Lab 1 (m5.large, us-east-1)
- Tools installed from Lab 1 (`kind`, `kubectl`)

---

### Step 1: Install Tools

```bash
# Install Trivy
TRIVY_VERSION=0.69.3
curl -LO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
tar xzf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz trivy
sudo mv trivy /usr/local/bin/
rm -f trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz

# Install cosign
COSIGN_VERSION=v2.2.2
curl -LO "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# Install Syft
SYFT_VERSION=1.4.1
curl -LO "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"
tar xzf syft_${SYFT_VERSION}_linux_amd64.tar.gz syft
sudo mv syft /usr/local/bin/
rm -f syft_${SYFT_VERSION}_linux_amd64.tar.gz

# Install hadolint
HADOLINT_VERSION=v2.12.0
curl -LO "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-x86_64"
chmod +x hadolint-Linux-x86_64
sudo mv hadolint-Linux-x86_64 /usr/local/bin/hadolint

# Install Grype
GRYPE_VERSION=0.82.0
curl -LO "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz"
tar xzf grype_${GRYPE_VERSION}_linux_amd64.tar.gz grype
sudo mv grype /usr/local/bin/
rm -f grype_${GRYPE_VERSION}_linux_amd64.tar.gz

# Verify all tools
trivy version && cosign version && syft version && hadolint --version && grype version
```

### Step 2: Set Up a Local Registry

```bash
# Run a local registry container
docker run -d --restart=always -p 5001:5000 --name local-registry registry:2

# Connect to kind network
docker network connect kind local-registry 2>/dev/null || true

echo "Local registry running at localhost:5001"
```

### Step 3: Create and Lint an Insecure Dockerfile

```bash
mkdir -p /tmp/image-lab
echo "print('Hello from insecure app')" > /tmp/image-lab/app.py

cat > /tmp/image-lab/Dockerfile.insecure <<'EOF'
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl wget netcat-openbsd python3
COPY . /app
WORKDIR /app
RUN echo "SECRET_KEY=hardcoded123" >> /app/.env
RUN echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" >> /app/.env
RUN echo "DB_PASSWORD=supersecret" >> /app/config.txt
EXPOSE 8080
USER root
CMD ["python3", "-m", "http.server", "8080"]
EOF

# Lint the insecure Dockerfile
hadolint /tmp/image-lab/Dockerfile.insecure
```

**Expected issues:** using `latest` tag, running as root, unpinned package versions.

### Step 4: Create a Secure Dockerfile, Lint It, and Build Both Images

```bash
cat > /tmp/image-lab/Dockerfile.secure <<'EOF'
FROM python:3.12-slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      tini=0.19.* && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app
COPY app.py .
RUN chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["tini", "--"]
EXPOSE 8080
CMD ["python3", "-m", "http.server", "8080"]
EOF

# Lint the secure Dockerfile
hadolint /tmp/image-lab/Dockerfile.secure

# Build both images
cd /tmp/image-lab
docker build -t localhost:5001/insecure-app:v1 -f Dockerfile.insecure .
docker build -t localhost:5001/secure-app:v1 -f Dockerfile.secure .

# Compare image sizes
docker images | grep -E "insecure-app|secure-app"
```

### Step 5: Scan Both Images with Trivy for Vulnerabilities

```bash
# Scan the insecure image
echo "=== Insecure Image Scan ==="
trivy image --severity HIGH,CRITICAL localhost:5001/insecure-app:v1

# Scan the secure image
echo ""
echo "=== Secure Image Scan ==="
trivy image --severity HIGH,CRITICAL localhost:5001/secure-app:v1

echo ""
echo "Compare: The secure image should have significantly fewer vulnerabilities"
```

### Step 6: Scan for Secrets in the Insecure Image

```bash
# Scan the insecure image specifically for embedded secrets
echo "=== Secret Scan: Insecure Image ==="
trivy image --scanners secret localhost:5001/insecure-app:v1

echo ""
echo "=== Secret Scan: Secure Image ==="
trivy image --scanners secret localhost:5001/secure-app:v1

echo ""
echo "The insecure image should show hardcoded secrets (API keys, passwords)"
echo "The secure image should be clean of embedded secrets"
```

### Step 7: Generate SBOM with Syft

```bash
# Generate SBOM in CycloneDX format
syft localhost:5001/secure-app:v1 -o cyclonedx-json > /tmp/image-lab/sbom-secure.json

# View SBOM summary
echo "=== SBOM Package Count ==="
jq '.components | length' /tmp/image-lab/sbom-secure.json

# Show top 10 packages by type
echo ""
echo "=== Packages by Type ==="
jq -r '[.components[].type] | group_by(.) | map({type: .[0], count: length}) | sort_by(-.count) | .[] | "\(.count)\t\(.type)"' /tmp/image-lab/sbom-secure.json

# List packages in the image
syft localhost:5001/secure-app:v1 --output table | head -30
```

### Step 8: Scan SBOM with Grype for Vulnerabilities

```bash
# Use Grype to scan the SBOM for known vulnerabilities
echo "=== Grype SBOM Vulnerability Scan ==="
grype sbom:/tmp/image-lab/sbom-secure.json

# Show only HIGH and CRITICAL vulnerabilities
echo ""
echo "=== HIGH and CRITICAL Only ==="
grype sbom:/tmp/image-lab/sbom-secure.json --only-fixed --fail-on critical 2>&1 || true

echo ""
echo "Grype can scan SBOMs offline — useful for auditing images in air-gapped environments"
```

### Step 9: Sign and Verify Image with cosign

```bash
# Generate a cosign key pair
cd /tmp/image-lab
COSIGN_PASSWORD="" cosign generate-key-pair
ls -la cosign.*

# Push the secure image to the local registry
docker push localhost:5001/secure-app:v1

# Sign the image
COSIGN_PASSWORD="" cosign sign --key /tmp/image-lab/cosign.key --tlog-upload=false localhost:5001/secure-app:v1
echo "Image signed successfully"

# Verify the signature
cosign verify --key /tmp/image-lab/cosign.pub --insecure-ignore-tlog localhost:5001/secure-app:v1
echo "Image signature verified successfully"

# Try to verify an unsigned image (should fail)
docker push localhost:5001/insecure-app:v1
cosign verify --key /tmp/image-lab/cosign.pub --insecure-ignore-tlog localhost:5001/insecure-app:v1 2>&1 || echo "Unsigned image: verification failed (expected)"
```

### Step 10: Deploy with Image Digest Pinning

```bash
# Get the image digest for the signed secure image
IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' localhost:5001/secure-app:v1)
echo "Image digest reference: ${IMAGE_DIGEST}"

# Deploy a pod using the digest-pinned image reference
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: digest-pinned-pod
  namespace: default
  labels:
    app: digest-demo
spec:
  containers:
    - name: app
      image: ${IMAGE_DIGEST}
      resources:
        limits:
          cpu: 200m
          memory: 128Mi
EOF

kubectl wait --for=condition=Ready pod/digest-pinned-pod --timeout=60s

# Verify the pod is running with the digest-pinned image
echo ""
echo "=== Pod Image Reference ==="
kubectl get pod digest-pinned-pod -o jsonpath='{.spec.containers[0].image}'
echo ""
echo ""
echo "Digest pinning ensures the exact image bytes are used, preventing tag mutation attacks"

# Compare: tag-based vs digest-based
echo ""
echo "Tag-based:   localhost:5001/secure-app:v1 (mutable — tag can be moved)"
echo "Digest-based: ${IMAGE_DIGEST} (immutable — always the same image)"

# Clean up the demo pod
kubectl delete pod digest-pinned-pod
```

### Step 11: Cleanup

```bash
# Remove lab resources
docker rm -f local-registry
rm -rf /tmp/image-lab
```

## Summary

- Hadolint catches Dockerfile anti-patterns like running as root and using unpinned tags
- Trivy's secret scanner detects hardcoded credentials and API keys embedded in image layers
- Minimal base images dramatically reduce the vulnerability surface compared to full OS images
- SBOMs provide a complete software inventory, and Grype can scan them offline for vulnerabilities
- Cosign image signing combined with digest pinning ensures only verified, immutable images are deployed
