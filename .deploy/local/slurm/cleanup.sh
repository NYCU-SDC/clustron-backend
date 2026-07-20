#!/usr/bin/env bash
# Stop the cluster and wipe its volumes (resets the slurmdbd accounting database).
set -euo pipefail
cd "$(dirname "$0")"
echo ":: Removing Clustron local Slurm cluster and volumes ..."
docker compose down -v
