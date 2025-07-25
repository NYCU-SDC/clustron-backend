# echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Deploying Start" >> ./deploy.log

DB_NAME="clustron-local-postgres-1"
LDAP_NAME="clustron-local-ldap-1"

if ! docker compose ps ${DB_NAME} | grep -q "running"; then
    echo "Database not running. Starting..."
    docker start ${DB_NAME}
else
    echo "Database already running."
fi

if ! docker compose ps ${LDAP_NAME} | grep -q "running"; then
    echo "LDAP not running. Starting..."
    docker start ${LDAP_NAME}
else
    echo "LDAP already running."
fi