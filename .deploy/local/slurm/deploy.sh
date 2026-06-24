#!/usr/bin/env bash
# Bring up the local Slurm cluster and report the REST API version(s) it serves.
set -euo pipefail
cd "$(dirname "$0")"

echo ":: Starting Clustron local Slurm cluster (project: clustron-slurm-local) ..."
docker compose up -d --wait mysql slurmdbd slurmctld slurmrestd cpu-worker

echo ":: Probing slurmrestd on http://localhost:6820 ..."
TOKEN="$(./mint-token.sh root 600 2>/dev/null || true)"
if [ -n "${TOKEN}" ]; then
  echo ":: REST API versions served (set slurm_restful_version to one of these):"
  for v in v0.0.42 v0.0.43 v0.0.44 v0.0.45 v0.0.46; do
    code="$(curl -s -o /dev/null -w '%{http_code}' -H "X-SLURM-USER-TOKEN: ${TOKEN}" "http://localhost:6820/slurm/${v}/ping")"
    [ "${code}" = "200" ] && echo "   ${v}"
  done
fi

# Resilience: after a host/Docker restart, the dynamic compute node returns DOWN
# ("Node unexpectedly rebooted") because the image ships ReturnToService=1, which
# only auto-returns *non-responsive* nodes. Flip it to 2 (auto-return on any
# registration) and clear anything currently down so `make slurm-up` self-heals.
echo ":: Ensuring compute nodes are in service ..."
docker compose exec -T slurmctld bash -lc '
  sed -i "s/^ReturnToService=.*/ReturnToService=2/" /etc/slurm/slurm.conf 2>/dev/null || true
  scontrol reconfigure 2>/dev/null || true
  for n in $(sinfo -hN -t down,drain,drained,fail -o "%N" 2>/dev/null | sort -u); do
    scontrol update nodename="$n" state=resume reason="clustron deploy" 2>/dev/null || true
  done
' >/dev/null 2>&1 || true

cat <<'TXT'

:: Cluster is up. Next steps:
   1. Mint a root token:   ./mint-token.sh root            (or: make slurm-token)
   2. Put it in clustron-backend/config.yaml as slurm_root_token
      (see ./config.slurm-local.yaml for the full slurm block)
   3. Smoke-test account creation:  ./smoke-test.sh
   4. Tear down:           ./cleanup.sh                     (or: make slurm-down)
TXT
