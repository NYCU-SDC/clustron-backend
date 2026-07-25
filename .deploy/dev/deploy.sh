# echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Deploying Start" >> ./deploy.log

set -e

# Shared network so the backend can reach slurmrestd by service name instead
# of a host-published port. Created here (not owned by either compose file)
# so neither project's `down` tries to remove a network the other is still
# attached to.
NETWORK="clustron-dev-slurm-net"
docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK"

echo ":: Starting Slurm cluster..."
docker compose -f slurm/compose.yaml down
docker compose -f slurm/compose.yaml pull
docker compose -f slurm/compose.yaml up -d --wait

echo ":: Minting Slurm root token..."
TOKEN=$(./slurm/mint-token.sh root infinite)

echo ":: Deploying backend..."
docker compose down
docker compose pull
SLURM_ROOT_TOKEN="$TOKEN" docker compose up -d --wait

echo "finish"