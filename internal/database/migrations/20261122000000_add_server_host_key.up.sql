BEGIN;

-- Pinned SSH host key for the server, captured during the pre-flight connection
-- health check and rendered into the Ansible known_hosts file so deploys verify
-- the host instead of blocking on an interactive host-key prompt. Stored in
-- authorized-key form, e.g. "ssh-ed25519 AAAAC3Nza...".
ALTER TABLE servers ADD COLUMN host_key TEXT;

COMMIT;
