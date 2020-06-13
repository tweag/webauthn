#!/bin/bash

# NB: We don't use `nix-shell` as a shebang, because that implicitly
# depends on NIX_PATH which is local to the users machine. Just run
# this under normal bash and make the user start a shell.

set -eufo pipefail

ormolu \
    --mode inplace \
    --ghc-opt -XTypeApplications \
    $(fd -e 'hs')
