#!/usr/bin/env bash
# Verify that the services needed by the backend are running with the image
# version pinned in compose.yaml, and start the ones that are not.
# Keep this list in sync with compose.yaml.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# <compose service> <expected image>, ldap_admin is optional so it is skipped.
SERVICES=(
    "postgres postgres:18"
    "ldap osixia/openldap:1.5.0"
    "redis redis:8.6.4"
)

pending=()
for entry in "${SERVICES[@]}"; do
    read -r service image <<< "$entry"

    # State and image of the container, empty when it was never created.
    status="$(docker compose ps -a --format '{{.State}} {{.Image}}' "$service")"

    if [ "$status" = "running $image" ]; then
        echo "  -> ${service} is running (${image})."
    else
        echo "  -> ${service} is not running as ${image} (got: ${status:-no container}), starting..."
        pending+=("$service")
    fi
done

if [ "${#pending[@]}" -eq 0 ]; then
    exit 0
fi

# 'up' creates what is missing, starts what is stopped and recreates whatever
# no longer matches compose.yaml; '--wait' blocks until they report healthy.
docker compose up -d --wait "${pending[@]}"