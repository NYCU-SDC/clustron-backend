# echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Deploying Start" >> ./deploy.log

set -e

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