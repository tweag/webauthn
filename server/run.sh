#!/usr/bin/env bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

localPort=8500

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
git ls-files .. | entr -r bash -c "yarn parcel build 'www/*' && cabal run server \"$origin\" \"$domain\" \"$localPort\""
