#!/usr/bin/env bash
# Stop the dev Slurm cluster. Volumes are kept so accounting data survives
# redeploys, matching the rest of the dev environment's cleanup.sh.
set -euo pipefail
cd "$(dirname "$0")"
docker compose down
