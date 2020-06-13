#!/usr/bin/env bash
yarn
yarn parcel build index.html
git ls-files .. | entr -r cabal run server
