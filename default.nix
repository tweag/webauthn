{ isShell ? false, system ? builtins.currentSystem }:
let

  nixpkgs = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/0432195a4b8d68faaa7d3d4b355260a3120aeeae.tar.gz";
    sha256 = "0izvjizdn0mil4qasdial3hbparzzpx61v0l9zb7bbwss428x1i9";
  };

  pkgs = import nixpkgs {
    overlays = [];
    config = {};
    inherit system;
  };

  inherit (pkgs) lib;
  hlib = pkgs.haskell.lib;

  hpkgs = pkgs.haskellPackages.extend (hself: hsuper: {
  
    repro_1 = hlib.dontHaddock (hlib.disableLibraryProfiling (
      hself.callCabal2nix "repro" (lib.sourceByRegex ./. [
        "src.*"
        "repro.cabal"
      ]) {}));

    repro_2 = hself.repro_1.overrideScope (hself: hsuper: {
      aeson = hself.aeson_2_0_2_0;

      hashable = hself.hashable_1_4_0_1;

      OneTuple = hself.OneTuple_0_3_1;

      semialign = hself.semialign_1_2_0_1;

      quickcheck-instances = hself.quickcheck-instances_0_3_27;

      ## Not disabling checks causes infinite recursion due to test dependencies
      text-short = pkgs.haskell.lib.dontCheck hself.text-short_0_1_4;

      time-compat = hself.time-compat_1_9_6_1;
    });

  });

in {
  inherit (hpkgs) repro_1 repro_2;
}
