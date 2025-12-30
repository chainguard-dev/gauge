# Use Chainguard's Python base image (private, includes extras repo for chainctl)
# Note: Building this image requires authentication to cgr.dev/chainguard-private
# Run: chainctl auth login && chainctl auth configure-docker
FROM cgr.dev/chainguard-private/python:latest-dev AS builder

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Multi-stage build: use runtime image with Docker CLI and scanning tools
FROM cgr.dev/chainguard-private/python:latest-dev

WORKDIR /app

USER root

# Install Docker CLI, syft, grype for vulnerability scanning, and chainctl for registry auth
# chainctl provides docker-credential-cgr which is required for pulling private images
# Versions pinned per infosec recommendation
RUN apk add --no-cache \
    docker-cli=29.1.3-r0 \
    syft=1.39.0-r0 \
    grype=0.104.3-r0 \
    chainctl=0.2.187-r0

# Copy installed packages from builder to root's local directory
COPY --from=builder /home/nonroot/.local /root/.local

# Copy application code
COPY src/ ./src/

# Set PATH to include user-installed packages and PYTHONPATH for module imports
ENV PATH="/root/.local/bin:${PATH}"
ENV PYTHONPATH="/app/src"

# Mount point for Docker socket (needed for CHPS scanning)
VOLUME /var/run/docker.sock

# Default entrypoint
ENTRYPOINT ["python", "-m", "cli"]
