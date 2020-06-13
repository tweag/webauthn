#!/usr/bin/env bash
yarn
yarn parcel index.html &
git ls-files .. | entr -r cabal run server
