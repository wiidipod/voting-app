# ── Stage 1: build (minify frontend) ──────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /build

# Install all deps (including devDependencies for the minifier)
COPY package*.json ./
RUN npm ci

# Copy source and run the minifier
COPY build.js ./
COPY public/ ./public/
RUN node build.js


# ── Stage 2: production image ──────────────────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# Install only production dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy server
COPY server.js ./

# Copy minified frontend from builder stage
COPY --from=builder /build/dist/ ./public/

# Persistent volume for the SQLite database
VOLUME ["/app/data"]

EXPOSE 3000

# SESSION_SECRET should be overridden at runtime via -e or docker-compose
ENV SESSION_SECRET=change-me-in-production

CMD ["node", "server.js"]

