#!/usr/bin/env bash
# Prove the backend's Slurm account-hierarchy path works end-to-end against
# slurmrestd. Mirrors the group sagas' exact call sequence:
#   1. create the top-level account              (CreateSlurmTopAccount)
#   2. create -base/-admin children under it     (CreateSlurmChildAccounts)
#   3. verify the parent/child tree via sacctmgr
#   4. delete admin -> base -> top               (the Delete saga's order)
# using the SAME REST calls the backend's slurm.CreateAccountAssociation
# (POST /slurmdb/<ver>/accounts_association) and slurm.DeleteAccount
# (DELETE /slurmdb/<ver>/account/<name>) use.
#   ./smoke-test.sh [account-name]
set -euo pipefail
cd "$(dirname "$0")"

VER="${SLURM_RESTFUL_VERSION:-v0.0.44}"
TOP="${1:-clustron-smoke}"
BASE_ACCT="${TOP}-base"
ADMIN_ACCT="${TOP}-admin"
BASE="http://localhost:6820/slurmdb/${VER}"

echo ":: Minting root token ..."
TOKEN="$(./mint-token.sh root 600)"

echo ":: POST ${BASE}/accounts_association  (top-level: ${TOP})"
curl -fsS -X POST "${BASE}/accounts_association" \
  -H "X-SLURM-USER-TOKEN: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"association_condition\":{\"accounts\":[\"${TOP}\"],\"association\":{}},\"account\":{}}"
echo

echo ":: POST ${BASE}/accounts_association  (children of ${TOP}: ${BASE_ACCT}, ${ADMIN_ACCT})"
curl -fsS -X POST "${BASE}/accounts_association" \
  -H "X-SLURM-USER-TOKEN: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"association_condition\":{\"accounts\":[\"${BASE_ACCT}\",\"${ADMIN_ACCT}\"],\"association\":{\"parent\":\"${TOP}\"}},\"account\":{}}"
echo

echo ":: Account tree (expect ${BASE_ACCT} and ${ADMIN_ACCT} parented under ${TOP}):"
TREE="$(docker compose exec -T slurmctld sacctmgr -i -n show assoc \
  format=Account%-24,ParentName%-24,Cluster%-12 2>/dev/null | grep "${TOP}" || true)"
echo "${TREE}"
for CHILD in "${BASE_ACCT}" "${ADMIN_ACCT}"; do
  if ! echo "${TREE}" | grep -q "${CHILD}[[:space:]]\{1,\}${TOP}"; then
    echo ":: FAIL — ${CHILD} is not parented under ${TOP}." >&2
    exit 1
  fi
done
echo ":: OK — hierarchy in place."
echo

echo ":: Deleting children then top (the group Delete saga's order)"
for ACCT in "${ADMIN_ACCT}" "${BASE_ACCT}" "${TOP}"; do
  echo ":: DELETE ${BASE}/account/${ACCT}"
  curl -fsS -X DELETE "${BASE}/account/${ACCT}" -H "X-SLURM-USER-TOKEN: ${TOKEN}"
  echo
done

echo ":: GET after delete (expect all three gone):"
for ACCT in "${TOP}" "${BASE_ACCT}" "${ADMIN_ACCT}"; do
  GET_AFTER_DELETE="$(curl -fsS "${BASE}/account/${ACCT}" -H "X-SLURM-USER-TOKEN: ${TOKEN}")"
  if echo "${GET_AFTER_DELETE}" | grep -q "\"name\": \"${ACCT}\""; then
    echo ":: FAIL — account ${ACCT} still present after delete." >&2
    exit 1
  fi
done
echo ":: OK — all three accounts deleted successfully."
