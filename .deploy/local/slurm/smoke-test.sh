#!/usr/bin/env bash
# Prove the backend's Slurm account + membership paths work end-to-end against
# slurmrestd. Mirrors the group and membership sagas' exact call sequence:
#   1. create the top-level account              (CreateSlurmTopAccount)
#   2. create -base/-admin children under it     (CreateSlurmChildAccounts)
#   3. verify the parent/child tree via sacctmgr
#   4. associate a user with both children       (Join: CreateSlurmUserAssociations)
#   5. delete the admin association explicitly    (Remove: DeleteSlurmAdminAssociation)
#   6. delete admin -> base -> top accounts       (the group Delete saga's order)
#   7. verify deleting the accounts cascaded the remaining user association
# using the SAME REST calls the backend uses: slurm.CreateAccountAssociation
# (POST /slurmdb/<ver>/accounts_association), slurm.CreateUserAssociation
# (POST /slurmdb/<ver>/users_association), slurm.DeleteAssociation
# (DELETE /slurmdb/<ver>/associations/?user=&account=) and slurm.DeleteAccount
# (DELETE /slurmdb/<ver>/account/<name>).
#   ./smoke-test.sh [account-name]
set -euo pipefail
cd "$(dirname "$0")"

VER="${SLURM_RESTFUL_VERSION:-v0.0.44}"
TOP="${1:-clustron-smoke}"
BASE_ACCT="${TOP}-base"
ADMIN_ACCT="${TOP}-admin"
USER_NAME="${SLURM_SMOKE_USER:-root}"
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

echo ":: POST ${BASE}/users_association  (associate ${USER_NAME} with ${BASE_ACCT} and ${ADMIN_ACCT})"
curl -fsS -X POST "${BASE}/users_association" \
  -H "X-SLURM-USER-TOKEN: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"association_condition\":{\"users\":[\"${USER_NAME}\"],\"accounts\":[\"${BASE_ACCT}\",\"${ADMIN_ACCT}\"],\"association\":{}},\"user\":{}}"
echo

echo ":: User associations (expect ${USER_NAME} on both ${BASE_ACCT} and ${ADMIN_ACCT}):"
USER_ASSOC="$(docker compose exec -T slurmctld sacctmgr -i -n show assoc user="${USER_NAME}" \
  format=Account%-24,User%-16 2>/dev/null | grep "${USER_NAME}" || true)"
echo "${USER_ASSOC}"
for ACCT in "${BASE_ACCT}" "${ADMIN_ACCT}"; do
  if ! echo "${USER_ASSOC}" | grep -q "${ACCT}"; then
    echo ":: FAIL — ${USER_NAME} not associated with ${ACCT}." >&2
    exit 1
  fi
done
echo ":: OK — user associations in place."
echo

echo ":: DELETE ${BASE}/associations/?user=${USER_NAME}&account=${ADMIN_ACCT}  (== the Remove saga's admin step)"
curl -fsS -X DELETE "${BASE}/associations/?user=${USER_NAME}&account=${ADMIN_ACCT}" \
  -H "X-SLURM-USER-TOKEN: ${TOKEN}"
echo
if docker compose exec -T slurmctld sacctmgr -i -n show assoc user="${USER_NAME}" account="${ADMIN_ACCT}" \
  format=Account%-24,User%-16 2>/dev/null | grep -q "${ADMIN_ACCT}"; then
  echo ":: FAIL — ${USER_NAME}'s ${ADMIN_ACCT} association still present after delete." >&2
  exit 1
fi
echo ":: OK — explicit association delete works. Leaving the ${BASE_ACCT} association to prove account deletion cascades it."
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
echo

echo ":: Post-teardown: user associations to the deleted accounts must be gone (cascade):"
for ACCT in "${BASE_ACCT}" "${ADMIN_ACCT}" "${TOP}"; do
  if docker compose exec -T slurmctld sacctmgr -i -n show assoc user="${USER_NAME}" account="${ACCT}" \
    format=Account%-24,User%-16 2>/dev/null | grep -q "${ACCT}"; then
    echo ":: FAIL — ${USER_NAME} still associated with deleted account ${ACCT}." >&2
    exit 1
  fi
done
echo ":: OK — deleting the accounts cascaded the user associations."
