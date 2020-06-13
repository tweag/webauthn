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

