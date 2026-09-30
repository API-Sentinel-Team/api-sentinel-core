# api-sentinel-core

Shared core for API Sentinel. Installed by every backend service as `sentinel-core`.

**Owns**: database models (`sentinel_core.models`), the **only** set of Alembic migrations, settings
(`sentinel_core.config`), tenancy/RLS, audit, redaction, RBAC/auth, pentest safety policy (target guard,
auth scope, kill switch), scan planning and the run-queue contract, finding parsers and the
vulnerability store, integrations, dashboard events, and the bundled security-test template library
(`sentinel_core/tests_library`).

**Does not** contain any service: no FastAPI app, no scanner execution, no schedulers. It must never
import `server`, `sentinel_worker`, `sentinel_scheduler` or `sentinel_archiver`.

## Consumers

| Repo | Package | Runs |
|---|---|---|
| [api-sentinel-api](https://github.com/API-Sentinel-Team/api-sentinel-api) | `server` | FastAPI; validates and *queues* scans |
| [api-sentinel-scan-worker](https://github.com/API-Sentinel-Team/api-sentinel-scan-worker) | `sentinel_worker` | executes queued scans |
| [api-sentinel-scheduler](https://github.com/API-Sentinel-Team/api-sentinel-scheduler) | `sentinel_scheduler` | enqueues scheduled scans |
| [api-sentinel-archiver](https://github.com/API-Sentinel-Team/api-sentinel-archiver) | `sentinel_archiver` | evidence retention/archiving |

## Migrations

```bash
sentinel-migrate upgrade head      # DATABASE_URL from the environment
```

## Releasing

Services pin a tag (`sentinel-core @ git+https://github.com/API-Sentinel-Team/api-sentinel-core.git@vX.Y.Z`).
A schema or shared-contract change is released here first; services then bump their pin.

## Develop

```bash
pip install -e ".[test]"
DEBUG=true pytest -q
```
