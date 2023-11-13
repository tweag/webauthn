{ isShell ? false, system ? builtins.currentSystem }:
let
  # Read in the Niv sources
  sources = import ./nix/sources.nix { };

  pkgs = import sources.nixpkgs {
    overlays = [ ];
    config = { };
    inherit system;
  };

  inherit (pkgs) lib;
  inherit (import sources."gitignore.nix" { inherit lib; }) gitignoreSource;

  src = gitignoreSource ./.;

  # Keep this in sync with the `tested-with` field in `webauthn.cabal`
  expectedGhcVersion = "9.4.7";

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
