
set -e
mkdir -p migrations
cp -r ../../internal/database/migrations/ ./migrations
cp -r ./seed_migrations/ ./migrations
cd ../..
export GOOS=linux
make build