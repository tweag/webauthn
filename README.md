# Haskell FIDO2 Library

This library implements FIDO2's WebAuthn specification. We intend to bring
passwordless authentication using security keys or your platforms TPM chip to
Haskell web applications.

 - Read https://webauthn.guide/ for an overview of the problems that are solved
   by the specification.
 - Go to https://webauthn.io/ for a demo of the WebAuthn specification. You can
   use a security key which supports WebAuthn (like a Yubikey) or your platform's
   TPM chip (if you don't have a Yubikey but do have an Android phone).

We're working on a demo of our own.

## Status

This library is experimental and currently does some untested funky stuff.
Especially the crypto things are in flux and need to be verified by someone
competent.

We're also changing things left and right and make no guarantees about backwards
compatibility. Do not depend on this yet.

## How to's

### Sync Nix files with the Cabal files

```console
$ nix-shell
$ cabal2nix . > ./fido2.nix
```

### Run the interactive demo

```console
$ nix-shell
$ cd server
$ ./run.sh
```

### Autoformat all Haskell code

```console
$ nix-shell
$ ./bin/autoformat.sh
```

### Using the binary cache

A binary cache for both MacOS and Linux is maintained by CI and served by
https://cachix.org

```console
$ cachix use haskell-fido2
```

### Using VSCode + GHCIDE

1. Install [Nix Environment Selector][nix-env-selector]
2. Install [ghcide][ghcide]

[ghcide]:https://marketplace.visualstudio.com/items?itemName=DigitalAssetHoldingsLLC.ghcide
[nix-env-selector]:https://marketplace.visualstudio.com/items?itemName=arrterian.nix-env-selector
