# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o scheduler .

# Runtime stage
FROM alpine:latest

# Install required tools
RUN apk add --no-cache \
    docker-cli \
    python3 \
    py3-pip \
    py3-psycopg2 \
    bash \
    curl \
    wget \
    tar

# Install Trivy
RUN wget -qO - https://github.com/aquasecurity/trivy/releases/download/v0.48.3/trivy_0.48.3_Linux-64bit.tar.gz | tar -xz -C /usr/local/bin trivy

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Create directories
RUN mkdir -p /scripts /reports

# Copy the scheduler binary from builder
COPY --from=builder /build/scheduler /usr/local/bin/scheduler

# Set working directory
WORKDIR /app

# Default environment variables
ENV SCAN_SCHEDULE="0 2 * * *"
ENV RUN_IMMEDIATELY="false"

# Run the scheduler
CMD ["/usr/local/bin/scheduler"]
