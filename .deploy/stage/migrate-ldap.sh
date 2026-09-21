#!/usr/bin/env bash
#
# One-time migration of LDAP data from osixia/openldap:1.5.0 (OpenLDAP 2.4)
# to osixia/openldap:2.6.10-alpha (OpenLDAP 2.6).
#
# The old config directory cannot be reused by the new image, so the data
# database is exported with slapcat from the OLD container and imported into
# a freshly bootstrapped NEW container with the image's own openldap-ctl.
#
# Usage (run from this directory, in order):
#
#   1. ./migrate-ldap.sh export          # old ldap container still running
#   2. git pull                          # compose.yaml now uses the 2.6 image
#   3. docker compose up -d --wait ldap  # bootstrap new config + MAY schema
#   4. ./migrate-ldap.sh import backups/ldap-<timestamp>-data.gz
#   5. docker compose up -d --wait       # start the rest (backend, ...)
#
# `export` also tars the old named volumes into backups/ for rollback.
#
# Overridable environment variables (must match the compose.yaml of the
# deployment being migrated):
#
#   LDAP_BASE_DN   suffix of the data database
#                  (default: dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club)
#   LDAP_BIND_PWD  admin password, for both cn=config and the data admin
#                  (default: password)

set -euo pipefail

cd "$(dirname "$0")"

BASE_DN="${LDAP_BASE_DN:-dc=example,dc=com}"
ADMIN_DN="cn=admin,${BASE_DN}"
ADMIN_PWD="${LDAP_BIND_PWD:-password}"
BACKUP_DIR="backups"

OLD_IMAGE="osixia/openldap:1.5.0"
NEW_IMAGE="osixia/openldap:2.6.10-alpha"
NEW_BACKUP_DIR="/var/lib/openldap/openldap-backups"

log() { echo ":: $*"; }
die() { echo "!! $*" >&2; exit 1; }

ldap_container() {
    local id
    id=$(docker compose ps -q ldap)
    [ -n "${id}" ] || die "ldap container is not running"
    echo "${id}"
}

require_image() {
    local cid="$1" want="$2" have
    have=$(docker inspect --format '{{.Config.Image}}' "${cid}")
    [ "${have}" = "${want}" ] || die "ldap container runs ${have}, expected ${want}"
}

count_dn() { grep -c '^dn:' || true; }

cmd_export() {
    local cid ts data_file project
    cid=$(ldap_container)
    require_image "${cid}" "${OLD_IMAGE}"

    mkdir -p "${BACKUP_DIR}"
    ts=$(date +%Y%m%d-%H%M%S)
    data_file="${BACKUP_DIR}/ldap-${ts}-data.gz"

    log "Exporting data database with slapcat ..."
    docker exec "${cid}" slapcat -n 1 | gzip > "${data_file}"
    log "$(gzip -dc "${data_file}" | count_dn) entries -> ${data_file}"

    project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "${cid}")
    for vol in ldap-data ldap-config; do
        log "Archiving volume ${project}_${vol} ..."
        docker run --rm \
            -v "${project}_${vol}:/src:ro" \
            -v "$(pwd)/${BACKUP_DIR}:/dst" \
            alpine tar czf "/dst/${vol}-${ts}.tgz" -C /src .
    done

    log "Done. Next: git pull, docker compose up -d --wait ldap, then:"
    log "  ./migrate-ldap.sh import ${data_file}"
}

cmd_import() {
    local data_file="$1" cid expected actual schema
    [ -f "${data_file}" ] || die "backup file not found: ${data_file}"

    cid=$(ldap_container)
    require_image "${cid}" "${NEW_IMAGE}"

    schema=$(docker exec "${cid}" ldapsearch -x -LLL -H ldap://localhost:3890 \
        -D cn=admin,cn=config -w "${ADMIN_PWD}" \
        -b cn=schema,cn=config "(cn=*openssh-lpk)" olcObjectClasses | tr -d '\n ')
    [[ "${schema}" == *"AUXILIARYMAY(sshPublicKey"* ]] \
        || die "ldapPublicKey schema is not the MAY variant; check ./schema/openssh-lpk.ldif is mounted"

    expected=$(gzip -dc "${data_file}" | count_dn)
    log "Importing ${expected} entries from ${data_file} ..."
    log "This replaces everything currently in the data database."

    docker cp "${data_file}" "${cid}:${NEW_BACKUP_DIR}/migrate-data.gz"
    if ! docker exec "${cid}" container run -- openldap-ctl restore migrate --data --force > "${BACKUP_DIR}/import.log" 2>&1; then
        cat "${BACKUP_DIR}/import.log"
        die "restore failed; see ${BACKUP_DIR}/import.log"
    fi
    grep -E 'WARNING|ERROR|FATAL' "${BACKUP_DIR}/import.log" || true

    log "Verifying ..."
    for _ in $(seq 1 30); do
        docker exec "${cid}" ldapwhoami -x -H ldap://localhost:3890 >/dev/null 2>&1 && break
        sleep 1
    done
    actual=$(docker exec "${cid}" slapcat -F /etc/openldap/slapd.d -n 1 | count_dn)
    [ "${actual}" = "${expected}" ] \
        || die "entry count mismatch: exported ${expected}, imported ${actual}"
    docker exec "${cid}" ldapsearch -x -LLL -H ldap://localhost:3890 \
        -D "${ADMIN_DN}" -w "${ADMIN_PWD}" -b "${BASE_DN}" -s base dn >/dev/null \
        || die "admin bind failed after import"

    log "Imported ${actual} entries. Next: docker compose up -d --wait"
}

case "${1:-}" in
    export) cmd_export ;;
    import) [ $# -eq 2 ] || die "usage: $0 import <backups/ldap-<timestamp>-data.gz>"; cmd_import "$2" ;;
    *) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
