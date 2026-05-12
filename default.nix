{ isShell ? false, system ? builtins.currentSystem }:
let
  # Read in the Niv sources
  sources = import ./nix/sources.nix { };

  pkgs = import sources.nixpkgs {
    overlays = [ ];
    config = { problems.handlers = {
             connection.broken = "warn"; # or "ignore"
           }; };
    inherit system;
  };

  inherit (pkgs) lib;
  inherit (import sources."gitignore.nix" { inherit lib; }) gitignoreSource;

  src = gitignoreSource ./.;

  # Keep this in sync with the `tested-with` field in `webauthn.cabal`
  expectedGhcVersion = "9.10.3";

  hpkgs = pkgs.haskellPackages.extend
    (hself: hsuper: {
      ghc =
        if hsuper.ghc.version != expectedGhcVersion then
          throw
            ("We expect the default nixpkgs GHC version to be ${expectedGhcVersion}, "
              + "but it is ${hsuper.ghc.version} instead. Update the `expectedGhcVersion` "
              + "variable in `default.nix` and update the `tested-with` field in "
              + "`webauthn.cabal` at the same time.")
        else hsuper.ghc;

      webauthn = hself.buildFromCabalSdist
        (pkgs.haskell.lib.disableLibraryProfiling
          (hself.callCabal2nix "webauthn" src { }));

      server = hself.callCabal2nix "server" (src + "/server") { };

      jose = hself.callHackageDirect {
        pkg = "jose";
        ver = "0.11";
        sha256 = "sha256-41u6RvbrtZwlccv2d94LsnTygvMXkex/jxWrz7Dngx8=";
      } {};

      crypton-x509-store = hself.callHackageDirect {
        pkg = "crypton-x509-store";
        ver = "1.8.0";
        sha256 = "sha256-U6DH5Ke3JXAzZuqxLM6mPKDxqj4HTf5kjoBXaerLOcc=";
      } {};

      crypton-x509-system = hself.callHackageDirect {
        pkg = "crypton-x509-system";
        ver = "1.8.0";
        sha256 = "sha256-uUNhwQnTPuVd1feZLUZJYKHIk/5v6t7nHpf1jqrMGTQ=";
      } {};

      crypton-x509 = hself.callHackageDirect {
        pkg = "crypton-x509";
        ver = "1.8.0";
        sha256 = "sha256-wxU8Ou52UCuCT2gbxqPKssteIVGUyg5WEbv1xRIyZTg=";
      } {};

      crypton-x509-validation = hself.callHackageDirect {
        pkg = "crypton-x509-validation";
        ver = "1.8.0";
        sha256 = "sha256-CyRqTUOcUzzVlQfTd3yylwDVtOaumBbBg9hMyvtcu7c=";
      } {};

      tls = hself.callHackageDirect {
        pkg = "tls";
        ver = "2.2.2";
        sha256 = "sha256-lbroDPZiOa2YH1jqEzxzNgBGcPZDP6WJEeD0odDgNqs=";
      } {};

    });

  deploy = pkgs.writeShellScriptBin "deploy" ''
    ${pkgs.nixos-rebuild}/bin/nixos-rebuild switch --build-host localhost --target-host webauthn.dev.tweag.io \
      --use-remote-sudo --no-build-nix \
      -I nixpkgs=${toString sources.nixpkgs} \
      -I nixos-config=${toString infra/configuration.nix}
  '';

  shell = hpkgs.shellFor {
    packages = p: [ p.webauthn p.server ];
    withHoogle = true;
    nativeBuildInputs = [
      pkgs.haskellPackages.cabal-install
      pkgs.haskellPackages.haskell-language-server
      pkgs.haskellPackages.hlint
      pkgs.haskellPackages.ormolu

      pkgs.entr
      pkgs.gitMinimal
      pkgs.niv
      pkgs.python3
      pkgs.yarn
      pkgs.nodejs
      pkgs.jq
      pkgs.zlib
      pkgs.pkg-config

      pkgs.haskellPackages.cabal-plan

      deploy
    ];
    shellHook = ''
      export NIX_PATH=nixpkgs=${toString sources.nixpkgs}
    '';
  };

in
if isShell then shell else {
  inherit (hpkgs) webauthn server;
  inherit pkgs hpkgs;
}
