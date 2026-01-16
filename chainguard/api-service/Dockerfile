# Chainguard Python 3.12 dev image (minimal, hardened base with build tools)
FROM cgr.dev/dylans-donuts.com/python:3.12-dev AS builder

WORKDIR /app

# Chainguard images use apk and glibc
# They run as non-root by default
USER root

# Install PostgreSQL dev package for psycopg2
RUN apk add --no-cache postgresql-18-dev

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

USER nonroot

# Runtime stage - minimal Python image
FROM cgr.dev/dylans-donuts.com/python:3.12

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /usr/lib/python3.12/site-packages /usr/lib/python3.12/site-packages

# Copy application code
COPY app.py ./

EXPOSE 5000

CMD ["app.py"]
