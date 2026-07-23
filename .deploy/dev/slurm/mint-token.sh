#!/usr/bin/env bash
# Mint a Slurm JWT via `scontrol token` inside the running slurmctld container.
#   ./mint-token.sh [username] [lifespan-seconds|infinite]
# Default: username=root lifespan=3600. deploy.sh uses this to fetch an
# "infinite" root token and passes it to the backend as SLURM_ROOT_TOKEN.
set -euo pipefail
cd "$(dirname "$0")"
USERNAME="${1:-root}"
LIFESPAN="${2:-3600}"
docker compose exec -T slurmctld scontrol token "username=${USERNAME}" "lifespan=${LIFESPAN}" \
  | tr -d '\r' | sed 's/^SLURM_JWT=//'
