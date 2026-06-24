#!/usr/bin/env bash
# Prove the backend's Slurm account path works end-to-end against slurmrestd:
# mints a root token and creates an account via the SAME REST call the backend's
# slurm.CreateAccountAssociation uses (POST /slurmdb/<ver>/accounts_association,
# the `sacctmgr add account` equivalent), then confirms the account AND its
# cluster association exist.
#   ./smoke-test.sh [account-name]
set -euo pipefail
cd "$(dirname "$0")"

VER="${SLURM_RESTFUL_VERSION:-v0.0.44}"
ACCT="${1:-clustron-smoke}"
BASE="http://localhost:6820/slurmdb/${VER}"

echo ":: Minting root token ..."
TOKEN="$(./mint-token.sh root 600)"

echo ":: POST ${BASE}/accounts_association  (name=${ACCT})"
curl -fsS -X POST "${BASE}/accounts_association" \
  -H "X-SLURM-USER-TOKEN: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"association_condition\":{\"accounts\":[\"${ACCT}\"],\"association\":{}},\"account\":{}}"
echo

echo ":: GET ${BASE}/account/${ACCT}"
curl -fsS "${BASE}/account/${ACCT}" -H "X-SLURM-USER-TOKEN: ${TOKEN}" | head -c 1500
echo
echo ":: association (proves the account is usable, not just a bare record):"
docker compose exec -T slurmctld sacctmgr -i -n show assoc account="${ACCT}" \
  format=Account%-20,Cluster%-12,User%-12 2>/dev/null | sed "/^$/d"
echo ":: OK if the account shows an association on a cluster above."
