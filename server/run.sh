#!/usr/bin/env bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

localPort=8080

# Kills all background processes on exit
trap "exit" INT TERM
trap "kill 0" EXIT

if port=$(jq -e '."\($ENV.USER)"' "$SCRIPT_DIR"/../infra/subdomains.json); then
  echo "Forwarding $USER.webauthn.dev.tweag.io to localhost:$localPort"
  ssh -o ControlMaster=no -N -R "$port":localhost:"$localPort" webauthn.dev.tweag.io &
  origin=https://$USER.webauthn.dev.tweag.io
  domain=$USER.webauthn.dev.tweag.io
else
  origin=http://localhost:$localPort
  domain=localhost
fi

yarn
yarn parcel build index.html
git ls-files .. | entr -r cabal run server "$origin" "$domain" "$localPort"
