# Updating the collector container

For operators running a collector (e.g. collector1, collector2) from this repo's
published image. Updating pulls a newer broker image and recreates the container.
Your data is preserved.

## TL;DR

From the directory that holds your `docker-compose.yml` and `.env`:

```bash
docker compose pull broker
docker compose up -d broker
docker compose logs -f broker   # Ctrl-C once you see it healthy
```

The `broker_data` named volume (the abuse-detection SQLite DB) carries over across
updates, so no state is lost. `autoheal` and `cloudflared` are left untouched.

## Where the image comes from

The broker image is published to GHCR as
`ghcr.io/dutch-meshcore/collector:latest` and is rebuilt automatically when
changes merge to `main` (also tagged `sha-<commit>` and, for releases, `vX.Y.Z`).
`docker compose pull` fetches whatever your `docker-compose.yml` `image:` line
points at — `:latest` by default.

If you pin a specific tag instead of `:latest`, edit the `image:` line to the new
tag before pulling, e.g.:

```yaml
    image: ghcr.io/dutch-meshcore/collector:v1.4.0
```

## Step by step

1. **Pull the new image.**

   ```bash
   docker compose pull broker
   ```

2. **Recreate the broker with it.** Compose recreates only the broker; the other
   services stay up.

   ```bash
   docker compose up -d broker
   ```

3. **Verify it came back healthy.**

   ```bash
   docker compose ps
   docker compose logs --tail=50 broker
   ```

   The healthcheck should report `healthy` within ~20-30s. If a wardrive/hunter
   publisher connects, the log shows `[AUTHZ] ✓ Using stream region -> meshcore/hunter/...`
   rather than `✗ Publish denied`.

## Configuration for the wardriver/hunter streams

These settings live in your `.env`. Only `AUTH_EXPECTED_AUDIENCE` usually needs
attention; the rest have working defaults.

- **`PUBLISH_EXTRA_REGIONS`** (optional) — non-IATA stream-region labels accepted
  on publish, alongside real IATA codes and `test`. **Defaults to
  `wardriver,hunter` when unset**, so you do not need to set anything to accept
  those labels. To restrict it, set it explicitly; an empty value
  (`PUBLISH_EXTRA_REGIONS=`) accepts only IATA codes and `test`.

- **`AUTH_EXPECTED_AUDIENCE`** (important) — a JWT publisher sets the token
  audience to the hostname it connects to, and the broker requires it to equal
  this value, or every such publisher is rejected while the broker still looks
  healthy. If wardrive/hunter clients connect to the same hostname your existing
  observer publishers use, no change is needed.

- **Subscriber roles** — `/wardriver/*` topics are delivered only to
  `full_access` (role 2) and `admin` (role 1) subscribers; `limited` (role 3)
  never receives them. An ingestor that must read the wardrive stream needs role
  `2` or higher in its `SUBSCRIBER_N` entry.

- **`HTTP_REDIRECT_URL`** (optional) — where a plain, non-WebSocket browser
  request to the broker is redirected. Defaults to
  `https://observers.dutchmeshcore.nl/`.

After changing `.env`, re-run `docker compose up -d broker` to apply it.

## Rolling back

GHCR keeps prior tags. To go back to a known-good build, point the `image:` line
at a specific tag (a `vX.Y.Z` release or a `sha-<commit>`), then:

```bash
docker compose pull broker
docker compose up -d broker
```

The data volume is unaffected by a rollback.
