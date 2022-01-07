{ isShell ? false, system ? builtins.currentSystem }:
let
  # Read in the Niv sources
  sources = import ./nix/sources.nix {};

  pkgs = import sources.nixpkgs {
    overlays = [];
    config = {};
    inherit system;
  };

  inherit (pkgs) lib;
  inherit (import sources."gitignore.nix" { inherit lib; }) gitignoreSource;

  src = gitignoreSource ./.;

  hpkgs = pkgs.haskellPackages.extend (hself: hsuper: {
    webauthn = hself.callCabal2nix "webauthn" src {};

    jose = hself.callHackage "jose" "0.8.5" {};

    base64-bytestring = hself.base64-bytestring_1_2_1_0;

    # Note: Keep this synchronized with cabal.project!
    x509-validation =
      let
        src = fetchTarball {
          url = "https://github.com/vincenthz/hs-certificate/archive/824cca5fba0c7c243c3561727ba16834e33fd32d.tar.gz";
          sha256 = "1ppvzjv35mqvy8jhyi35awg0y59ixqa42rglvb5jdnb3c6svv0i5";
        } + "/x509-validation";
      in hself.callCabal2nix "x509-validation" src {};
  });

  deploy = pkgs.writeShellScriptBin "deploy" ''
    ${pkgs.nixos-rebuild}/bin/nixos-rebuild switch --build-host localhost --target-host webauthn.dev.tweag.io \
      --use-remote-sudo --no-build-nix \
      -I nixpkgs=${toString sources.nixpkgs} \
      -I nixos-config=${toString infra/configuration.nix}
  '';

  shell = hpkgs.shellFor {
    packages = p: [ p.webauthn ];
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
    inherit (hpkgs) webauthn;
    inherit pkgs hpkgs;
  }
