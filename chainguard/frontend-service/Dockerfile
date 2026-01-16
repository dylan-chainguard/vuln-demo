# Chainguard Node.js image (minimal, hardened base)
FROM cgr.dev/dylans-donuts.com/node:latest-dev AS builder

WORKDIR /app

# Chainguard runs as non-root by default
USER root

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application code
COPY server.js .

# Switch back to non-root user
USER nonroot

# Runtime stage - minimal Node image
FROM cgr.dev/dylans-donuts.com/node:latest

WORKDIR /app

# Copy node_modules from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy package.json for metadata
COPY package*.json ./

# Copy application code
COPY server.js ./

EXPOSE 3000

# Use node directly instead of npm (npm not available in runtime image)
CMD ["server.js"]
