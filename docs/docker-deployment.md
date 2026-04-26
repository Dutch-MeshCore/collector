# Docker deployment

This document records the design decisions behind the production Docker setup (`Dockerfile`, `.dockerignore`, `docker-compose.prod.yml`, `.github/workflows/docker-publish.yml`) and the reasoning behind each. It is meant for operators and future maintainers who need to change the image, the runtime, or the deployment topology.

## Goals

The brief was: produce a production-ready, hardened image. Concretely:

1. Read-only root filesystem at runtime.
2. Explicit volume(s) for any path the application writes to.
3. Non-root execution.
4. Minimal attack surface (no shell, no package manager, no compilers in the runtime image).
5. Reproducible multi-arch builds published to a registry.
6. Self-contained compose stack including TLS termination via Cloudflare Tunnel.

## Application facts that drove the design

A code audit of the repository surfaced the following constraints. Every decision below traces back to one of these.

| Concern | Finding |
|---|---|
| Runtime | Node.js 22 (`.node-version`), TypeScript ESM (`"type": "module"`), entry `src/server.ts`. |
| Native modules | One: `better-sqlite3`. Requires `python3 + make + g++` at build time. |
| Writable paths at runtime | Exactly one: the directory holding `ABUSE_PERSISTENCE_PATH` (default `/data/abuse-detection.db`). SQLite WAL mode also writes `*.db-wal` and `*.db-shm` siblings, so the entire `/data` directory must be writable. Verified at `src/abuse-detector.ts:215` and `.env.example:53`. |
| Logs | stdout/stderr only — no file logging anywhere. |
| In-memory state | Aedes uses in-memory persistence (no `PersistenceEngine` wired up). The rate-limiter is a `Map`. Both are intentionally lost on restart. |
| TLS | Not terminated in the app. The project's deployment guide is Cloudflare Tunnel (`docs/cloudflare-tunnels.md`), so the broker speaks plain WebSocket internally. |
| Listening port | `MQTT_WS_PORT` (default 8883). Above 1024, so no `CAP_NET_BIND_SERVICE` needed. |
| Health endpoint | None. The HTTP server only redirects non-WS requests to `analyzer.letsmesh.net`. |
| Source import style | Relative ESM imports without `.js` extensions (e.g. `import { RateLimiter } from './rate-limiter'`). |

That last row is critical and is the source of one of the bigger decisions below.

## Decisions

### D1. Multi-stage Dockerfile, glibc on both stages

**Choice:** `node:22-bookworm-slim` builder → `gcr.io/distroless/nodejs22-debian12:nonroot` runtime.

**Why:**
- `better-sqlite3` is a native node-gyp module. It is compiled in the builder stage and copied into the runtime stage. The two stages must share the same libc, otherwise the prebuilt `.node` binary either won't load or will misbehave at runtime. Both Bookworm-slim and the distroless `debian12` runtime use the same Debian 12 glibc, so the compiled artifact transfers cleanly.
- Distroless was chosen over `slim` for the runtime layer because it removes the shell, `apt`, `dpkg`, and ~all userland binaries. The image contains effectively only the Node.js runtime, our code, and the production `node_modules`. This is a meaningful drop in attack surface compared to `slim`.

**Rejected alternatives:**
- `node:22-alpine` (musl): `better-sqlite3` does ship musl prebuilds, but the project hasn't tested against musl and bug reports for this combo are common. Glibc was the safer default.
- Single-stage build: would leak the C++ toolchain (~200 MB of `g++`, `python3`, headers) into the production image.

### D2. Run TypeScript directly via `tsx`, do not run compiled JS

**Choice:** `ENTRYPOINT ["/nodejs/bin/node", "--import", "tsx", "src/server.ts"]`. The image ships `src/`, not `dist/`. There is no `tsc` step.

**Why:** the source uses extensionless ESM relative imports (`import { x } from './foo'`). Node's pure-ESM resolver requires explicit `.js` extensions. Running plain `node dist/server.js` after `tsc` produces:

```
ERR_MODULE_NOT_FOUND: Cannot find module '/app/dist/rate-limiter' imported from /app/dist/server.js
```

This was reproduced during build verification. The project's existing `npm start` uses `tsx src/server.ts` for the same reason — `tsx` resolves extensionless TypeScript imports the way the source assumes. We follow that convention. `tsx` is already a regular (not dev) dependency in `package.json`, so it's available at runtime without additional install.

The `--import tsx` form (Node 20.6+) registers tsx's loader via the stable `module.register` hook, so we never invoke the `tsx` shell wrapper — distroless has no shell, and we don't need one.

**Performance impact:** `tsx` is built on `esbuild`, so the on-the-fly transform is fast (~tens of ms at startup) and per-module results are cached in memory. There is no measurable steady-state runtime cost.

**If the source is ever reworked** to add `.js` extensions on imports (or migrate `tsconfig.json` to `"moduleResolution": "NodeNext"` and adjust source accordingly), this can switch to a compile-then-run model: add `npm run build` and `npm prune --omit=dev` in the builder, and copy `dist/` (not `src/`) to the runtime stage. That would shave ~30 MB off the image and remove `tsx` from runtime, but it's not currently a viable change without touching application source.

### D3. Pre-create `/data` in the image owned by `nonroot`

**Choice:** the builder stage runs `mkdir -p /data && chown 65532:65532 /data`, and the runtime stage `COPY --from=builder --chown=nonroot:nonroot /data /data`.

**Why:** when an empty named volume is mounted over a directory in the image, Docker initializes the volume by copying the *image's* version of that directory — including ownership and mode. Without a pre-existing `/data` in the image, Docker creates the bind point fresh as `root:root 0755`, and the unprivileged runtime user (UID 65532) cannot open the SQLite database. This was reproduced during verification:

```
SqliteError: unable to open database file
    code: 'SQLITE_CANTOPEN'
```

After adding the `mkdir`/`chown` step, the volume is initialized as `65532:65532 0755` and the broker writes cleanly:

```
$ ls -la /data
drwxr-xr-x  2 65532 65532 4096 ...
-rw-r--r--  1 65532 65532 16384 abuse-detection.db
```

**Rejected alternatives:**
- An entrypoint shim that `chown`s `/data` at startup. Would require either running as root and dropping privileges (extra moving part, and distroless has no `chown`), or an init container in compose (more services to maintain).
- Forcing operators to manually `chown` host bind mounts. Brittle and easy to forget.

### D4. Read-only root filesystem with a tmpfs `/tmp`

**Choice:** in compose, `read_only: true` plus `tmpfs: /tmp:size=16M,mode=1777`.

**Why:** the audit found no runtime writes outside `/data`, so `read_only` is safe. `/tmp` is mounted as a small tmpfs as a belt-and-suspenders measure for any transitive dependency that might touch `os.tmpdir()` (e.g. some npm packages cache on first call). 16 MB is plenty for that and small enough that a memory-pressure attack against tmpfs has bounded blast radius.

### D5. Drop all capabilities and set `no-new-privileges`

**Choice:** `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`.

**Why:** the broker listens on port 8883 (>1024), so it needs no `CAP_NET_BIND_SERVICE`. It does not raw-socket, does not read packet sockets, does not chown anything. With nothing to lose, dropping all capabilities is the right default. `no-new-privileges` blocks the classic SUID-binary escalation vector — moot in distroless since there are no SUID binaries, but cheap and consistent.

### D6. TCP healthcheck via inline `node -e`, not `curl`/`wget`/`nc`

**Choice:**

```
HEALTHCHECK CMD ["/nodejs/bin/node", "-e",
  "require('net').createConnection(...).on('connect',...).on('error',...)"]
```

**Why:** distroless has no shell and no networking utilities, so the standard `curl -f http://localhost:.../health` pattern is unavailable. It also wouldn't work even if shipped, because the app has no HTTP `/health` endpoint — the existing HTTP listener only 301-redirects non-WebSocket requests, which would falsely "pass" any HTTP probe.

The Node one-liner opens a TCP socket to `MQTT_WS_PORT` on `127.0.0.1`, exits 0 on `connect`, exits 1 on `error`. This is a true liveness check (the listener is accepting connections) without depending on application-level handlers. Adding a real `/health` endpoint would be a small change in `src/server.ts` (the existing HTTP listener), but it's a code change beyond the scope of dockerization and the TCP probe is sufficient for now.

### D7. Cloudflared as a sidecar, not a built-in

**Choice:** the broker container runs plain WebSocket on port 8883 with no host port published. A second `cloudflare/cloudflared` service in the same compose file, on the same private bridge network, terminates TLS and exposes the broker to the public internet via a Cloudflare-managed hostname. The tunnel uses token mode (`TUNNEL_TOKEN` from `.env`), so no certs/keys are mounted.

**Why:**
- Matches the project's existing deployment guide (`docs/cloudflare-tunnels.md`).
- Keeps the broker image free of TLS code, certificate handling, or proxy concerns.
- The broker has no published ports — it is reachable *only* from `cloudflared` over the internal Docker network. Stops port-scanners cold.
- `depends_on: { broker: { condition: service_healthy } }` ensures the tunnel doesn't advertise the upstream until the broker is actually accepting connections.

**Rejected alternatives:**
- Embed `cloudflared` in the broker image. Couples two unrelated lifecycles (broker upgrades vs. tunnel client upgrades) and means TLS goes down whenever the broker restarts.
- Use the host network and expose 8883 directly. Forces operators to handle TLS themselves at L7 (nginx, caddy) and drops the existing Cloudflare-tunnel deployment story.
- Use a volume-based tunnel credentials file instead of `TUNNEL_TOKEN`. Token mode is simpler — operators can rotate via the Cloudflare dashboard without touching the host filesystem.

### D8. Resource limits and log rotation

**Choice:** broker capped at 256M memory / 1.0 CPU; cloudflared at 128M / 0.5 CPU. Both use `json-file` driver with `max-size: 10m, max-file: 3`.

**Why:**
- Memory: The broker is mostly in-memory state (rate-limiter Map, abuse-detection working set). 64M reservation, 256M ceiling is comfortable for thousands of clients without permitting runaway leaks.
- CPU: The broker is I/O-bound (WebSocket frames, JWT verify). 1 CPU is generous; the limit is there to prevent any one container from saturating the host under attack.
- Logs: the app logs heavily on auth and abuse events. Without rotation, a busy broker fills the host disk with `*-json.log` files. 30 MB rotated retention keeps recent events around without being a footgun.

### D9. Secrets via `env_file: .env`, not Docker secrets

**Choice:** `docker-compose.prod.yml` uses `env_file: .env`. Subscriber credentials (`SUBSCRIBER_N=user:pass:role:max`), `AUTH_EXPECTED_AUDIENCE`, and `TUNNEL_TOKEN` all live in that file.

**Why:** Docker Swarm secrets (file-based, mounted at `/run/secrets/<name>`) would be a stronger story — they keep secrets off process env, off `docker inspect` output, and out of `/proc/<pid>/environ`. But the application reads everything via `process.env` and `dotenv.config()`. Switching to Docker secrets would require code changes (read each secret from a file path, fall back to env). That's beyond the current scope. `.env` with `chmod 600` is the practical choice — match the project's existing configuration model and document it.

### D10. GitHub Actions: multi-arch, attested, built only on push

**Choice:** `.github/workflows/docker-publish.yml` builds on `push` to `main` and on `v*.*.*` tags, runs on `pull_request` for build verification (no push), publishes to `ghcr.io/${{ github.repository }}` with `linux/amd64` + `linux/arm64`, and attaches SBOM + provenance attestations via `docker/build-push-action@v6` plus `actions/attest-build-provenance@v2`.

**Why:**
- arm64 covers Raspberry Pi / Ampere / Graviton deployments, which is a common shape for a self-hosted MQTT broker.
- SBOM (Software Bill of Materials) lets operators audit what's inside a published image without re-pulling and inspecting it. Provenance is GitHub's signed attestation that "this image came from this commit on this workflow run" — useful for supply-chain verification.
- Building on PRs (without pushing) catches Dockerfile regressions before merge.
- GHA cache (`type=gha,mode=max`) keeps subsequent builds fast without paying for an external cache backend.

## Verification

The setup was verified end-to-end during implementation:

1. **Build:** `docker build -t meshcore-mqtt-broker:test .` — multi-stage build completes; final image ~207 MB.
2. **Image hardening:**
   - `User=nonroot` (UID/GID 65532) confirmed via `docker image inspect`.
   - No shell or coreutils — `docker run --rm meshcore-mqtt-broker:test` is the only sensible invocation; the image cannot be used to drop into a debug shell (intentional).
3. **Runtime under hardened flags:** the image was started with `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, a fresh named volume at `/data`, and the example env. Output:

   ```
   [ABUSE] Initialized with persistence at: /data/abuse-detection.db
   WebSocket MQTT listening on: ws://0.0.0.0:8883
   Ready to accept connections...
   ```
4. **Healthcheck:** transitions from `starting` to `healthy` after the first probe (verified at t≈25s).
5. **Volume initialization:** the named volume is populated with `/data` owned by `65532:65532 0755`, and the broker creates `abuse-detection.db` (mode `0644`, same owner). Persistence survives container restart (volume is detached from container lifetime).
6. **Compose validation:** `docker compose -f docker-compose.prod.yml config` resolves cleanly with both services, the internal network, and the named volume.

## Operator notes

### First-time deploy

```bash
cp .env.example .env
chmod 600 .env
$EDITOR .env   # set SUBSCRIBER_*, AUTH_EXPECTED_AUDIENCE, TUNNEL_TOKEN, ABUSE_*

docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml logs -f broker
```

In the Cloudflare Zero Trust dashboard, configure the tunnel's public hostname to forward to `http://broker:8883`. Docker DNS resolves the service name `broker` on the internal bridge network shared with `cloudflared`.

### Updating the image

The compose file currently references `ghcr.io/greentown0/meshcore-mqtt-broker:latest`. To deploy a new tag:

```bash
docker compose -f docker-compose.prod.yml pull broker
docker compose -f docker-compose.prod.yml up -d broker
```

For production it is preferable to pin to an immutable tag (e.g. `:v1.2.3` or `:sha-abcdef0`) rather than `:latest`. The publish workflow emits both.

### Inspecting persistent state

The image has no shell, so `docker compose exec broker ls /data` will not work. To inspect the volume, mount it into a throwaway shell-bearing container:

```bash
docker run --rm -v meshcore-mqtt-broker_broker_data:/data alpine ls -la /data
```

(The volume's full name is `<project>_broker_data`; `docker volume ls` will show the correct prefix.)

### Backups

A live SQLite DB with WAL files cannot be safely copied with plain `cp`. Use SQLite's online backup API or stop the broker before copying. A simple periodic backup looks like:

```bash
docker run --rm \
  -v meshcore-mqtt-broker_broker_data:/data \
  -v "$(pwd)":/backup \
  alpine sh -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /data/abuse-detection.db ".backup /backup/abuse-$(date +%Y%m%d-%H%M%S).db"'
```

### Resource tuning

If the broker hits the 256M memory ceiling under load, expect to tune two things in tandem:

1. `deploy.resources.limits.memory` in compose.
2. The abuse-detector working set: `ABUSE_TOPIC_HISTORY_SIZE`, `ABUSE_DUPLICATE_WINDOW_SIZE`, and the per-client trust state retention. These all scale with active client count.

The healthcheck and `restart: unless-stopped` together mean the container will be recycled automatically on OOM kill, but data in `/data` is preserved across restarts.

## Known limitations

- **No HTTP `/health` endpoint.** The TCP probe is sufficient for liveness, but a real readiness probe (e.g. for Kubernetes) would need an HTTP endpoint. Adding one is ~5 lines in the existing HTTP listener at `src/server.ts:817`.
- **Subscriber credentials in env vars.** They appear in `docker inspect` and `/proc/<pid>/environ`. Migrating to Docker/Swarm secrets requires application changes (read from `/run/secrets/...` files).
- **Aedes persistence is in-memory only.** Retained messages and subscriptions are lost on restart. This is application behavior, not a docker concern, but worth knowing operationally.
- **`cloudflare/cloudflared:latest`.** Pinning to a digest is recommended; the compose file uses `:latest` for simplicity. Operators should pin once they've chosen a tested version.
- **Single replica.** This stack assumes one broker instance. Aedes does not natively cluster, and the abuse-detection state is per-instance. Horizontal scaling requires either a sticky-session frontend (so a publisher always lands on the same broker) or moving abuse state to a shared backend — neither is wired up.

## Files

| Path | Purpose |
|---|---|
| `Dockerfile` | Multi-stage build: glibc builder + distroless runtime, non-root, tsx-at-runtime, TCP healthcheck. |
| `.dockerignore` | Keeps `.env`, `dist/`, `node_modules`, secrets, and docs out of the build context. |
| `docker-compose.prod.yml` | Two-service stack: hardened broker + `cloudflared` sidecar on a private bridge. |
| `.env.example` | Template for runtime configuration; includes `TUNNEL_TOKEN` for the sidecar. |
| `.github/workflows/docker-publish.yml` | Multi-arch build + push to GHCR with SBOM and provenance. |
| `docs/cloudflare-tunnels.md` | Existing operator guide for setting up the tunnel side. |
| `docs/docker-deployment.md` | This document. |
