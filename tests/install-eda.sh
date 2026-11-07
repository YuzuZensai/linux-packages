#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "$0")/.." && pwd)
if ! compgen -G "$repository_root/dist/packages/apt/eda_*_amd64.deb" >/dev/null; then
  echo "No x86_64 Eda package in this build; skipping its installation check."
  exit 0
fi

for distribution in ubuntu:24.04 debian:13-slim; do
  echo "Checking Eda installation on $distribution"
  docker run --rm --interactive \
    --mount "type=bind,src=$repository_root,dst=/workspace,readonly" \
    "$distribution" bash -se <<'CONTAINER'
set -euo pipefail
apt-get update -qq
if ! DEBIAN_FRONTEND=noninteractive apt-get install --yes --quiet \
    /workspace/dist/packages/apt/eda_*_amd64.deb nodejs >/tmp/eda-install.log 2>&1; then
  cat /tmp/eda-install.log
  exit 1
fi
/opt/eda/resources/git/bin/git --version
test "$(stat -c '%u:%g:%a' /opt/eda/chrome-sandbox)" = '0:0:4755'
useradd --create-home eda-smoke
runuser --user eda-smoke -- node /workspace/tests/eda-startup.cjs
CONTAINER
done
