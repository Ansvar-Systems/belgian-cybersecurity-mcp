# ─────────────────────────────────────────────────────────────────────────────
# belgian-cybersecurity-mcp — multi-stage Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
# Build:  docker build -t belgian-cybersecurity-mcp .
# Run:    docker run --rm -p 3000:3000 belgian-cybersecurity-mcp
#
# The image expects a pre-built database at /app/data/ccb.db.
# Override with CCB_DB_PATH for a custom location.
# ─────────────────────────────────────────────────────────────────────────────

# --- Stage 1: Build TypeScript + native modules ---
FROM node:20-slim AS builder

WORKDIR /app

# Install build deps for the better-sqlite3 native binding
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
# Run postinstall scripts so the better-sqlite3 native binding is built
RUN npm ci
COPY tsconfig.json ./
COPY src/ src/
RUN npm run build

# Strip dev deps so node_modules can be copied straight into the runtime stage
RUN npm prune --omit=dev

# --- Stage 2: Production ---
FROM node:20-slim AS production

WORKDIR /app
ENV NODE_ENV=production
ENV CCB_DB_PATH=/app/data/ccb.db

# Copy pre-built node_modules (with native better-sqlite3 binding) from builder
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app/package.json /app/package.json
COPY --from=builder /app/dist/ dist/

# Bake the database into the image. CI's "Provision database" step downloads
# database.db.gz from the GitHub Release and gunzips it to data/database.db.
COPY data/database.db data/ccb.db

# Non-root user for security
RUN addgroup --system --gid 1001 mcp && \
    adduser --system --uid 1001 --ingroup mcp mcp && \
    chown -R mcp:mcp /app
USER mcp

# Health check: verify HTTP server responds
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "dist/src/http-server.js"]
