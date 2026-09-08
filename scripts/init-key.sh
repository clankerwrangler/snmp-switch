#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets
chmod 700 secrets
if [ -e secrets/config.key ]; then
  echo 'Preserved existing encryption key.'
  exit 0
fi
openssl rand -base64 32 | tr '+/' '-_' > secrets/config.key
# The host directory is owner-only. File readability permits the nonroot
# container UID to read the individual Docker secret mount.
chmod 444 secrets/config.key
echo 'Created secrets/config.key. Back up this key separately from the data volume.'
