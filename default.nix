{ isShell ? false }:
let
  # Read in the Niv sources
  sources = import ./nix/sources.nix {};

  # Fetch the haskell.nix commit we have pinned with Niv
  haskellNix = import sources.haskellNix {};

  # Import nixpkgs and pass the haskell.nix provided nixpkgsArgs
  pkgs = import
    # haskell.nix provides access to the nixpkgs pins which are used by our CI,
    # hence you will be more likely to get cache hits when using these.
    # But you can also just use your own, e.g. '<nixpkgs>'.
    haskellNix.sources.nixpkgs-2105
    # These arguments passed to nixpkgs, include some patches and also
    # the haskell.nix functionality itself as an overlay.
    haskellNix.nixpkgsArgs;

  build = pkgs.haskell-nix.project {
    # 'cleanGit' cleans a source directory based on the files known by git
    src = pkgs.haskell-nix.haskellLib.cleanGit {
      name = "fido2";
      src = ./.;
    };
    # Specify the GHC version to use.
    compiler-nix-name = "ghc8106";
  };

  shell = build.shellFor {
    tools = {
      cabal = "3.4.0.0";
      hlint = "latest";
      haskell-language-server = "latest";
      ormolu = "latest";
    };

    nativeBuildInputs = [
      pkgs.niv
    ];
  };

in
if isShell then shell else build
