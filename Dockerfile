# syntax=docker/dockerfile:1.7

###############################################################################
# Stage 1 — builder: install production dependencies (incl. native modules).
# Uses node:22-bookworm-slim (Debian 12 / glibc) so the better-sqlite3 native
# module is built against the same libc the runtime stage uses.
###############################################################################
FROM node:22-bookworm-slim AS builder

ENV NODE_ENV=production \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

# Build deps for better-sqlite3 (node-gyp). These never reach the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        python3 \
        make \
        g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Production-only install (includes tsx and better-sqlite3, both runtime deps).
# The source uses extensionless ESM imports, so we run TS at runtime via tsx
# rather than compiling — matching the project's `npm start` script.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# App source.
COPY tsconfig.json ./
COPY src ./src

# Pre-create the data directory so Docker initializes named volumes mounted at
# /data with nonroot ownership. Without this, a fresh volume is owned by root
# and the unprivileged runtime user cannot open the SQLite database.
RUN mkdir -p /data && chown 65532:65532 /data


###############################################################################
# Stage 2 — runtime: distroless. No shell, no package manager, no apt.
# Uses the :nonroot tag (UID/GID 65532). Same Debian 12 base as builder.
###############################################################################
FROM gcr.io/distroless/nodejs22-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="meshcore-mqtt-broker" \
      org.opencontainers.image.description="MeshCore MQTT broker with public-key authentication and abuse detection" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/michaelhart/meshcore-mqtt-broker"

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /app/node_modules ./node_modules
COPY --from=builder --chown=nonroot:nonroot /app/src ./src
COPY --from=builder --chown=nonroot:nonroot /app/package.json ./package.json
COPY --from=builder --chown=nonroot:nonroot /app/tsconfig.json ./tsconfig.json
COPY --from=builder --chown=nonroot:nonroot /data /data
VOLUME ["/data"]

ENV NODE_ENV=production \
    MQTT_WS_PORT=8883 \
    MQTT_HOST=0.0.0.0 \
    ABUSE_PERSISTENCE_PATH=/data/abuse-detection.db

EXPOSE 8883

USER nonroot

# Pure-Node TCP probe — distroless has no curl/wget/nc.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/nodejs/bin/node", "-e", "require('net').createConnection(Number(process.env.MQTT_WS_PORT)||8883,'127.0.0.1').on('connect',function(){this.end();process.exit(0)}).on('error',function(){process.exit(1)})"]

# tsx registers its loader via Node's module.register API (Node >= 20.6).
ENTRYPOINT ["/nodejs/bin/node", "--import", "tsx", "src/server.ts"]
