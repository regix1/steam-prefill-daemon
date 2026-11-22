# SteamPrefill

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Platform: Steam](https://img.shields.io/badge/Steam-171a21?style=for-the-badge&logo=steam&logoColor=white)](https://store.steampowered.com/)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/invite/BKnBS4u)
[![LANCache Manager](https://img.shields.io/badge/LANCache-Manager-9af?style=for-the-badge)](https://github.com/regix1/lancache-manager)

Steam prefill daemon for [LANCache](https://lancache.net/) — a companion to
[**LANCache Manager**](https://github.com/regix1/lancache-manager), which
coordinates the prefill providers.

It downloads your owned Steam game content through your lancache *before* you
install, so the real install — and every other machine on your LAN — pulls from
the cache at full LAN speed instead of the internet. Nothing is written to disk:
bytes stream through the cache and are discarded.

## Why use it

- **Cache warm before you install** — pre-download titles overnight, install instantly later.
- **LAN speed for every machine after the first** — the second install of the same version is served from cache.
- **No disk writes, no free space needed** — bytes stream through and are discarded, sparing your SSD.
- **Incremental** — optionally fetch only chunks introduced by a new depot manifest, while retaining full-prefill and repair modes.
- **Account login** — sign in with your Steam account; supports Steam Guard and the Steam Guard Mobile Authenticator.
- **Headless daemon** — driven by LANCache Manager or any socket client.

## Quick start

**Recommended — run it through [LANCache Manager](https://github.com/regix1/lancache-manager).**
LANCache Manager installs, configures, and drives this daemon alongside the other
prefill providers, so you never touch the socket protocol by hand. This is the
supported path for almost everyone.

**Standalone (.NET 8 SDK)** — build and run from source:

```bash
dotnet build SteamPrefill/SteamPrefill.csproj -c Release
dotnet run  --project SteamPrefill/SteamPrefill.csproj -c Release
```

Sign in once before prefilling — every command runs after login.

> A prebuilt container image is published at `ghcr.io/regix1/steam-prefill-daemon`
> for advanced/manual setups. It is a socket-driven daemon (volumes `/commands`,
> `/responses`, `/app/Config`, `/app/.cache`), so see
> [LANCache Manager](https://github.com/regix1/lancache-manager) and the repo docs
> for the full container configuration rather than running it ad hoc.

## How it works

1. **Authenticate** — log in with your Steam account (Steam Guard / Mobile Authenticator supported).
2. **Select titles** — choose which owned apps to prefill from an interactive menu.
3. **Resolve** — each app's manifest and CDN URLs are looked up from Steam's content system.
4. **Prefill** — each app's content is fetched through the lancache and discarded, warming the cache.

## DLC and incomplete depots

Owned DLC is included with the parent game. Manifests are requested under the
DLC's own AppID unless Steam points the depot at a shared app. Depots with no
downloadable content are skipped. If one depot fails, the rest of the game still
prefills, and the app is not treated as up to date until every depot succeeds.

## Chunk-level incremental prefill

SteamPrefill normally downloads every chunk when a depot manifest changes. This
is the safest behavior because a LANCache may evict content independently of
SteamPrefill. Operators with persistent caches can opt into chunk-level
incremental prefill to request only chunks that were not present in the last
successfully completed manifest:

```yaml
environment:
  PREFILL_MODE: incremental
  PREFILL_CACHE_GENERATION: primary-cache-v1
volumes:
  - ./config:/app/Config
```

`/app/Config` must be persistent. The daemon stores one compact manifest per
depot under `Config/incremental/depots`; no game payload is stored there. A new
baseline is committed only after every queued chunk for the app has transferred
successfully. Failed or cancelled runs leave the previous baseline intact.

The available modes are:

| `PREFILL_MODE` | Behavior |
| --- | --- |
| `full` | Download every chunk for a changed manifest. This is the default and preserves existing behavior. |
| `incremental` | Compare the current and last successful manifests and request only newly introduced chunks. A depot without a baseline receives a full prefill. |
| `repair` | Request every chunk regardless of the baseline, then replace the baseline after success. |
| `dry-run` | Calculate and report the incremental plan without downloading or changing a baseline. |
| `bootstrap` | Seed baselines from successful legacy history, recovering an older manifest when possible, without downloading content. |

The existing `--force` option always selects full mode for that run. This makes
it suitable for an immediate cache repair without changing container settings.

### Safe rollout and maintenance

1. Keep `PREFILL_MODE=full` for the first successful prefill, or use
   `PREFILL_MODE=bootstrap` to migrate existing successful-history data without
   a download. Bootstrap may need Steam to retain the historical manifest; if
   it cannot recover one, it reports the full gap and does not invent a
   baseline.
2. Switch to `PREFILL_MODE=incremental` for scheduled update checks.
3. Schedule an occasional `repair` or `--force` run to re-request content that
   LANCache may have evicted. The appropriate interval depends on the cache's
   retention and available storage.
4. Change `PREFILL_CACHE_GENERATION` after clearing, replacing, or materially
   migrating the LANCache. A generation mismatch invalidates all old baselines;
   the next incremental run safely performs a full prefill per depot.

Incremental state records what SteamPrefill successfully requested; it cannot
prove that LANCache still retains every recorded chunk. Do not use incremental
mode without a repair schedule and a cache-generation policy. To roll back,
set `PREFILL_MODE=full`; the legacy success history remains compatible and no
database migration is required.

## Requirements

- A running [LANCache](https://lancache.net/) with the **`steam`** cache-domain
  group enabled (from [uklans/cache-domains](https://github.com/uklans/cache-domains)).
- A Steam account that owns the games you want to prefill.
- Docker, or the [.NET 8 SDK](https://dotnet.microsoft.com/) to build from source.

## Concurrent runs

The daemon keeps one persistent Steam login and callback pump while accepting
independent prefill runs. Each run processes its apps in order; different runs
may transfer disjoint apps concurrently. It never creates another account
session or container for a schedule.

`PREFILL_MAX_RUNS` defaults to `4` and accepts `1` through `16`.
`PREFILL_MAX_REQUESTS` defaults to `30` and independently caps all content
requests in the process. The existing `--max-threads` option remains
authoritative when supplied. These values are read at startup, so a change
requires a restart. Use a run limit of `1` as the conservative fallback.

Managers that do not negotiate the complete protocol-v2 feature set use the
legacy exclusive single-run behavior. Existing selection, status, and cancel
commands remain available during mixed-version rollout.

Steam cache-status clients can also negotiate the Steam-local
`cacheStatusAppIds` feature. A manager that sees this feature sends requested
app IDs separately from the complete physical depot/manifest snapshot. This
keeps shared depots independent from the app that first recorded them. The
feature does not change the common protocol version or other prefill providers.

During a mixed-version rollout, use these compatibility rules:

- A new manager with an old daemon reports the requested Steam apps as unknown
  and does not send the unsupported cache-status command.
- An old manager with a new daemon uses the legacy inferred-app request. It can
  conservatively report an app as outdated when the manager omitted shared rows.
- A new manager with a new daemon uses explicit app IDs and the global physical
  snapshot.
- An old manager with an old daemon keeps the legacy behavior.

You can upgrade or roll back either component without a database migration.

## Support

Questions or issues? [Open an issue](https://github.com/regix1/steam-prefill-daemon/issues),
or find the LANCache community on the
[LanCache.NET Discord](https://discord.com/invite/BKnBS4u).

If these tools have been useful, support the original author on
[ko-fi](https://ko-fi.com/Y8Y5DWGZN), or this fork via
[buy me a coffee](https://www.buymeacoffee.com/regix). Thanks!

## License

Licensed under the MIT License (see [LICENSE](LICENSE)); a fork of the
lancache-prefill tools by Tim Pilius ([@tpill90](https://github.com/tpill90)).
