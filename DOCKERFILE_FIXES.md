# Chainguard Multi-Stage Dockerfile Fixes

## Summary of Issues Found and Fixed

### Common Issues with Both Dockerfiles

1. **Duplicate file copy syntax**: `COPY app.py app.py ./` creates a file named "app.py" and tries to copy it, resulting in incorrect behavior
2. **Missing dependencies in runtime stage**: Multi-stage builds weren't copying dependencies from builder to runtime
3. **Incorrect CMD with ENTRYPOINT**: Chainguard images have ENTRYPOINT set to `/usr/bin/python` or `/usr/bin/node`, so CMD shouldn't repeat the command

## API Service (Python) Fixes

### Original Issues:
```dockerfile
# Line 24 - Incorrect file copy (duplicate "app.py")
COPY app.py app.py ./

# Line 25 - Overwrites everything copied before
COPY --from=builder /app /app

# Missing: Python packages from builder stage
# Wrong CMD: CMD ["python", "app.py"] becomes /usr/bin/python python app.py
```

### Fixed Version:
```dockerfile
# Copy installed Python packages from builder
COPY --from=builder /usr/lib/python3.12/site-packages /usr/lib/python3.12/site-packages

# Copy application code (no duplication)
COPY app.py ./

# CMD only provides arguments to ENTRYPOINT
CMD ["app.py"]
```

### Key Changes:
- ✅ Copy Python packages from `/usr/lib/python3.12/site-packages` in builder
- ✅ Fixed file copy syntax (removed duplicate "app.py")
- ✅ Changed CMD to only pass arguments (ENTRYPOINT already has `/usr/bin/python`)
- ✅ Removed unnecessary `/home/nonroot/.local` copy (packages install to system location)

## Frontend Service (Node.js) Fixes

### Original Issues:
```dockerfile
# Line 25 - Incorrect file copy (duplicate "server.js")
COPY server.js server.js ./

# Missing: node_modules from builder stage
# Wrong CMD: CMD ["npm", "start"] won't work (npm not in runtime image)
# Wrong CMD: CMD ["node", "server.js"] becomes /usr/bin/node node server.js
```

### Fixed Version:
```dockerfile
# Copy node_modules from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy package.json for metadata
COPY package*.json ./

# Copy application code (no duplication)
COPY server.js ./

# Use node directly (npm not available in runtime image)
# CMD only provides arguments to ENTRYPOINT
CMD ["server.js"]
```

### Key Changes:
- ✅ Copy `node_modules` from builder stage
- ✅ Fixed file copy syntax (removed duplicate "server.js")
- ✅ Changed from `npm start` to direct node execution
- ✅ Changed CMD to only pass arguments (ENTRYPOINT already has `/usr/bin/node`)

## Understanding Chainguard Image ENTRYPOINT

Chainguard images use ENTRYPOINT instead of CMD for better security:

```dockerfile
# Python image has:
ENTRYPOINT ["/usr/bin/python"]

# Node image has:
ENTRYPOINT ["/usr/bin/node"]
```

This means:
- ❌ Wrong: `CMD ["python", "app.py"]` → Executes: `/usr/bin/python python app.py` (looks for file "python")
- ✅ Correct: `CMD ["app.py"]` → Executes: `/usr/bin/python app.py`

## Testing the Fixes

### Test API Service:
```bash
# Build
docker build -t vuln-demo/api-service:chainguard ./chainguard/api-service

# Test dependencies
docker run --rm --entrypoint /usr/bin/python vuln-demo/api-service:chainguard \
  -c "import flask; import psycopg2; print('✅ Dependencies OK')"

# Test startup
docker run --rm -e DB_HOST=test vuln-demo/api-service:chainguard
```

### Test Frontend Service:
```bash
# Build
docker build -t vuln-demo/frontend-service:chainguard ./chainguard/frontend-service

# Test node
docker run --rm --entrypoint /usr/bin/node vuln-demo/frontend-service:chainguard \
  -e "console.log('✅ Node OK')"

# Test startup
docker run --rm vuln-demo/frontend-service:chainguard
```

## Benefits of Multi-Stage Builds with Chainguard

### Before (Single Stage with -dev image):
- **Larger image size**: Includes build tools (apk, npm, pip, compilers)
- **More vulnerabilities**: Build tools add attack surface
- **More packages**: Development dependencies included

### After (Multi-Stage with Runtime image):
- **Smaller image size**: Only runtime dependencies
- **Fewer vulnerabilities**: Minimal runtime image
- **Better security**: No build tools in production

### Example Size Comparison:
```
# API Service
chainguard-dev:   ~200 MB (with build tools)
chainguard:       ~80 MB  (runtime only)
Reduction:        60%

# Frontend Service
chainguard-dev:   ~350 MB (with npm, build tools)
chainguard:       ~120 MB (runtime only)
Reduction:        66%
```

## Common Pitfalls to Avoid

1. **Don't copy entire /app directory from builder** - Be selective about what you copy
2. **Don't assume shell exists** - Chainguard images don't include shell (`/bin/sh`)
3. **Don't use npm in runtime** - npm is only in `-dev` images, use `node` directly
4. **Don't forget to copy dependencies** - Python site-packages, Node node_modules, etc.
5. **Don't repeat command in CMD** - ENTRYPOINT already specifies python/node

## Updated File Locations

- API Service Dockerfile: `/chainguard/api-service/Dockerfile`
- Frontend Service Dockerfile: `/chainguard/frontend-service/Dockerfile`
