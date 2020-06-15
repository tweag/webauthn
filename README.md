# Haskell FIDO2 Library

## How to update nix files after touching cabal file
```
nix-shell
cabal2nix . > ./fido2.nix
```

## How to run interactive demo
```
nix-shell
cd server
./run.sh
```

## How to autoformat all Haskell code
```
nix-shell
./bin/autoformat.sh
```

## Using the binary cache

A binary cache for both MacOS and Linux is maintained by CI and served by
https://cachix.org

```
$ cachix use haskell-fido2
```

## Using VSCode + GHCIDE

1. Install https://marketplace.visualstudio.com/items?itemName=arrterian.nix-env-selector
2. Install https://marketplace.visualstudio.com/items?itemName=DigitalAssetHoldingsLLC.ghcide
3. Done!
