# echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Deploying Start" >> ./deploy.log

set -e

docker compose down  -v
docker compose pull
docker compose up -d --wait

echo "finish"