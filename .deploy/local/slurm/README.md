# Local Dockerized Slurm for Clustron

A self-contained Slurm cluster in Docker so the backend's `internal/slurm`
functions (account/user/association management and job submission) can be
exercised against a **real `slurmrestd`** during local development.

> **"Slurm can't run in a container" — only half true.** Production *compute
> nodes* are awkward to containerize (they want cgroups, GPUs, MPI, privileged
> host access). But a single-host **dev/test** cluster — `slurmctld` +
> `slurmdbd` + `slurmrestd` + a dynamic compute node — runs in Docker just fine.
> This stack is built on the well-maintained
> [giovtorres/slurm-docker-cluster](https://github.com/giovtorres/slurm-docker-cluster)
> image and needs **no source compile** (it pulls a prebuilt image).

## What you get

| Container | Role | Port |
| --- | --- | --- |
| `mysql` (MariaDB) | slurmdbd accounting storage | internal |
| `slurmdbd` | accounting daemon; generates the shared `jwt_hs256.key` | internal `6819` |
| `slurmctld` | controller; mints JWTs via `scontrol token` | internal `6817` |
| `slurmrestd` | **REST API with JWT auth** (`X-SLURM-USER-TOKEN`) | **host `6820`** |
| `cpu-worker` | one dynamic compute node so a partition exists | internal `6818` |

The backend talks to `slurmrestd` exactly as it does in dev/stage:
`POST /slurmdb/<ver>/accounts_association`, `GET /slurm/<ver>/jobs`, etc., authenticating
with a JWT in the `X-SLURM-USER-TOKEN` header.

## Prerequisites

- Docker + Docker Compose (v2). On Windows, run these from your **WSL** shell.
- Outbound network on first run (to pull `giovtorres/slurm-docker-cluster` and
  `mariadb`).

## Quick start

From `clustron-backend/`:

```bash
make slurm-up          # == ./.deploy/local/slurm/deploy.sh
make slurm-token       # prints a root JWT  (== ./.deploy/local/slurm/mint-token.sh root)
```

`make slurm-up` waits for every daemon to become healthy and then prints which
REST API versions the running image serves, e.g.:

```
/slurm/v0.0.43
/slurm/v0.0.44
/slurmdb/v0.0.43
/slurmdb/v0.0.44
```

### Point the backend at it

Copy the `slurm:` block from [`config.slurm-local.yaml`](./config.slurm-local.yaml)
into your `clustron-backend/config.yaml`, then paste the `make slurm-token`
output into `slurm_root_token`:

```yaml
slurm:                                       # MUST be nested under `slurm:`
  slurm_restful_base_url: "http://localhost:6820"
  slurm_restful_version:  "v0.0.44"          # pick one from the deploy.sh output
  slurm_root_token:       "eyJhbGciOi..."    # from `make slurm-token`
```

> **Gotcha:** these keys only load when nested under a top-level `slurm:` key.
> Placed flat, they are silently ignored and you get
> `Post "/slurmdb//accounts": unsupported protocol scheme ""` (empty base URL +
> version). Also don't mix YAML and `SLURM_*` env vars — setting one env var
> replaces the whole slurm struct, blanking the rest.

Now `make run` the backend. Creating a group will create a matching Slurm
account (see below).

## The group → account flow

`group.Service.Create` runs a saga: **DB group → LDAP base group → LDAP admin
group → Slurm account**. The Slurm step calls `slurm.CreateAccountAssociation`
(the `sacctmgr add account` equivalent — `POST /slurmdb/<ver>/accounts_association`)
with the group's LDAP CN as the account name, so the account is created **with**
its cluster association and is usable for jobs. (The bare `/accounts` endpoint
creates an account with no association.) If it fails, the saga compensates the
earlier steps (LDAP groups deleted) and the DB transaction rolls back.

Verify the REST path the backend uses, without the backend, with:

```bash
./smoke-test.sh                       # create + delete "clustron-smoke", asserting both
# override the API version if needed:
SLURM_RESTFUL_VERSION=v0.0.44 ./smoke-test.sh myaccount
```

Inspect accounts and their associations directly inside the cluster:

```bash
docker compose exec slurmctld sacctmgr -i show account
docker compose exec slurmctld sacctmgr -i show assoc account=clustron-smoke
```

> **Heads-up — group creation now depends on Slurm.** Because the account step
> is part of the saga, group creation will **fail** if `slurmrestd` is
> unreachable or `slurm_root_token` is missing/expired. Keep this stack up (and
> the token fresh) while working on groups, or expect group creation to error.

## Per-user job tokens (out of scope here)

The backend's *job* endpoints need a per-user JWT from an external
[slurm-token-helper](https://github.com/NYCU-SDC/slurm-token-helper)
(`GET /api/token/{username}`). That integration is deferred to a separate task —
this stack is scoped to the group → Slurm-account flow, which uses
`slurm_root_token` and needs no helper. For ad-hoc job testing you can mint a
per-user token straight from `scontrol`:

```bash
./mint-token.sh alice 3600
curl -H "X-SLURM-USER-TOKEN: $(./mint-token.sh alice)" http://localhost:6820/slurm/v0.0.44/jobs
```

## Slurm version / REST API version

`SLURM_VERSION` (default `25.11.4`) selects the image tag and therefore which
OpenAPI plugins `slurmrestd` exposes. The backend's `slurm_restful_version`
**must** match one of them. The project uses **`v0.0.44`**, which Slurm 25.11
serves. SchedMD removes old plugin versions over time, so if you need a specific
version, confirm it in the `make slurm-up` output and pin `SLURM_VERSION`
accordingly:

```bash
SLURM_VERSION=25.05.6 make slurm-up   # if you specifically need an older API
```

## Teardown

```bash
make slurm-down        # == ./cleanup.sh ; stops everything and wipes volumes
```

This removes the MariaDB and Slurm state volumes, resetting all accounts.

## Files

| File | Purpose |
| --- | --- |
| `compose.yaml` | the cluster definition (prebuilt image, no build) |
| `deploy.sh` / `cleanup.sh` | bring up (with version probe) / tear down |
| `mint-token.sh` | mint a root or per-user JWT via `scontrol token` |
| `smoke-test.sh` | create, read, and delete an account via the backend's REST paths (asserts deletion) |
| `config.slurm-local.yaml` | the `slurm_*` block to paste into `config.yaml` |

## Troubleshooting

**`sinfo` shows the node `down` / jobs stay `PENDING` ("Required node not
available") after a host or Docker restart.** The compute node is dynamic
(`slurmd -Z`); when its container restarts, slurmctld marks it
`down` ("Node unexpectedly rebooted") and the image's `ReturnToService=1` only
auto-returns *non-responsive* nodes. Just re-run:

```bash
make slurm-up        # resumes any down nodes and sets ReturnToService=2
```

or fix it by hand:

```bash
docker exec clustron-slurm-slurmctld scontrol update nodename=c1 state=resume
```

**`srun` fails / hangs when run as root.** Slurm refuses to run jobs as root or
SlurmUser. Submit as a normal user inside the cluster:

```bash
docker exec clustron-slurm-slurmctld su slurm -s /bin/bash -c "srun -N1 hostname"
```

## Notes / caveats

- Compute is minimal: one dynamic node, jobs may sit `PENDING`. Accounting and
  job *submission/listing* work; this stack is not for running real workloads.
- `slurmctld`, `slurmrestd` and the worker run `privileged: true` (Slurm needs
  it). Fine for local dev; do not copy this layout to production.
- The cluster is independent of the core `.deploy/local` stack (separate Compose
  project `clustron-slurm-local`), so `make prepare`/`make run` are unaffected.
