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

  hpkgs = pkgs.haskellPackages.extend (hself: hsuper: {
    webauthn = hself.callCabal2nix "webauthn" (lib.sourceByRegex ./. [
      "^src.*"
      ".*\\.cabal$"
    ]) {};

    jose = hself.callHackage "jose" "0.9" {};

    aeson = hself.aeson_2_0_2_0;

    OneTuple = hself.OneTuple_0_3_1;

    hashable = hself.hashable_1_4_0_1;

    quickcheck-instances = hself.quickcheck-instances_0_3_27;

    # Not disabling checks causes infinite recursion due to test dependencies
    text-short = pkgs.haskell.lib.dontCheck hself.text-short_0_1_4;

    # Needed for aeson >= 2.0
    http2 = pkgs.haskell.lib.appendPatch hsuper.http2 (pkgs.fetchpatch {
      url = "https://github.com/kazu-yamamoto/http2/commit/0a1f64cb7cd2042554cd2d4e96da850a8940f08d.patch";
      sha256 = "0kbbd7dv49m6slcfw61kzy21v4d2ingnbygg4i3spn91v3dyh87y";
    });

    hspec-expectations-json = pkgs.haskell.lib.dontCheck hself.hspec-expectations-json_1_0_0_5;

    time-compat = hself.time-compat_1_9_6_1;

    semialign = hself.semialign_1_2_0_1;

    base64-bytestring = hself.base64-bytestring_1_2_1_0;
  });

  build = hpkgs.webauthn;

  #build = pkgs.haskell-nix.project {
  #  # 'cleanGit' cleans a source directory based on the files known by git
  #  src = pkgs.haskell-nix.haskellLib.cleanGit {
  #    name = "webauthn";
  #    src = ./.;
  #  };
  #  # Specify the GHC version to use.
  #  compiler-nix-name = "ghc8107";
  #  modules = [
  #    {
  #      packages.webauthn.components.library.extraSrcFiles = [ "root-certs/*" ];
  #    }
  #  ];
  #};

  deploy = pkgs.writeShellScriptBin "deploy" ''
    ${pkgs.nixos-rebuild}/bin/nixos-rebuild switch --build-host localhost --target-host webauthn.dev.tweag.io \
      --use-remote-sudo --no-build-nix \
      -I nixpkgs=${toString sources.nixpkgs} \
      -I nixos-config=${toString infra/configuration.nix}
  '';

  shell = hpkgs.shellFor {
    packages = p: [ p.webauthn ];
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

  #shell = build.shellFor {
  #  tools = {
  #    cabal = "3.4.0.0";
  #    hlint = "latest";
  #    haskell-language-server = "latest";
  #    # 0.4.0.0 requires Cabal 3.6, which requires GHC 9.2.1, which haskell.nix
  #    # only has cached for nixos-unstable
  #    ormolu = "0.3.1.0";
  #  };

  #  nativeBuildInputs = with pkgs; [
  #    entr
  #    gitMinimal
  #    niv
  #    python3
  #    yarn
  #    nodejs
  #    deploy
  #    jq
  #  ];
  #};

in
  if isShell then shell else {
    inherit hpkgs build;
  }
