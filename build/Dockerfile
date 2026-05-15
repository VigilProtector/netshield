# Dockerfile for NetShield service
# Multi-stage build for smaller final image

# Build stage
FROM golang:1.26.0 AS builder

# Set environment variables
ARG version=development
ARG GITHUB_TOKEN

WORKDIR /workspace

# Copy source files
COPY cmd/ cmd/
COPY internal/ internal/
COPY go.mod go.sum ./
COPY Makefile ./

# Set GOPRIVATE to avoid Go module proxy issues
ENV GOPRIVATE="github.com,vigilprotector.io"

# Configure git to use token for private repos
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"

# Download dependencies
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-X 'main.version=${version}'" \
    -o /workspace/netshield \
    vigilprotector.io/netshield/cmd/netshield

RUN chmod u+x /workspace/netshield

# Final stage
FROM gcr.io/distroless/static:nonroot

WORKDIR /

# Copy binary from builder with correct permissions
# distroless image has no shell, so we cannot use RUN commands
# Instead, we copy the binary with the correct user/permissions from builder
COPY --from=builder --chown=65532:65532 /workspace/netshield .

# Switch to non-root user (UID 65532 is the default nonroot user in distroless)
USER 65532:65532

# Expose API HTTP port (8900) and Metrics/Health port (9090).
# Docker rejects inline comments on EXPOSE — the trailing "# ..."
# is parsed as part of the port literal ("invalid containerPort: #").
EXPOSE 8900
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# Entrypoint
ENTRYPOINT ["/netshield"]
