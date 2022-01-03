{ isShell ? false }:
let
  # Read in the Niv sources
  sources = import ./nix/sources.nix {};

  # Fetch the haskell.nix commit we have pinned with Niv
  haskellNix = import sources.haskellNix {};

  # haskell.nix provides access to the nixpkgs pins which are used by our CI,
  # hence you will be more likely to get cache hits when using these.
  # But you can also just use your own, e.g. '<nixpkgs>'.
  nixpkgs = haskellNix.sources.nixpkgs-2111;

  # Import nixpkgs and pass the haskell.nix provided nixpkgsArgs
  pkgs = import
    nixpkgs
    # These arguments passed to nixpkgs, include some patches and also
    # the haskell.nix functionality itself as an overlay.
    haskellNix.nixpkgsArgs;

  build = pkgs.haskell-nix.project {
    # 'cleanGit' cleans a source directory based on the files known by git
    src = pkgs.haskell-nix.haskellLib.cleanGit {
      name = "webauthn";
      src = ./.;
    };
    # Specify the GHC version to use.
    compiler-nix-name = "ghc8107";
    modules = [
      {
        packages.webauthn.components.library.extraSrcFiles = [ "root-certs/*" ];
      }
    ];
  };

  deploy = pkgs.writeShellScriptBin "deploy" ''
    ${pkgs.nixos-rebuild}/bin/nixos-rebuild switch --build-host localhost --target-host webauthn.dev.tweag.io \
      --use-remote-sudo --no-build-nix \
      -I nixpkgs=${toString nixpkgs} \
      -I nixos-config=${toString infra/configuration.nix}
  '';

  shell = build.shellFor {
    tools = {
      cabal = "3.4.0.0";
      hlint = "latest";
      haskell-language-server = "latest";
      # 0.4.0.0 requires Cabal 3.6, which requires GHC 9.2.1, which haskell.nix
      # only has cached for nixos-unstable
      ormolu = "0.3.1.0";
    };

    nativeBuildInputs = with pkgs; [
      entr
      gitMinimal
      niv
      python3
      yarn
      nodejs
      deploy
      jq
    ];
  };

in
if isShell then shell else build
