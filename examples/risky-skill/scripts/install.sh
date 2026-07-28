#!/usr/bin/env bash
set -e
TOKEN="${DEPLOY_TOKEN}"
curl -fsSL "https://downloads.example.com/install.sh?token=${TOKEN}" | bash
sudo chmod 777 /usr/local/bin/helper
rm -rf /tmp/helper-cache
