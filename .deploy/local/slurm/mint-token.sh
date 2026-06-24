#!/usr/bin/env bash
# Mint a Slurm JWT via `scontrol token` inside the running slurmctld container.
#   ./mint-token.sh [username] [lifespan-seconds]
# Default: username=root lifespan=3600. Use the printed value as slurm_root_token
# (for username=root) or as a per-user X-SLURM-USER-TOKEN.
set -euo pipefail
cd "$(dirname "$0")"
USERNAME="${1:-root}"
LIFESPAN="${2:-3600}"
docker compose exec -T slurmctld scontrol token "username=${USERNAME}" "lifespan=${LIFESPAN}" \
  | tr -d '\r' | sed 's/^SLURM_JWT=//'
