# echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Deploying Start" >> ./deploy.log

set -e
docker compose down
docker compose -f slurm/compose.yaml down
docker network rm clustron-dev-slurm-net 2>/dev/null || true