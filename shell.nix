let
  pkgs = (import (import ./nix/sources.nix).nixpkgs) {};
  haskellPackages = pkgs.haskellPackages.override {
    overrides = self: super: {
      cborg = pkgs.haskell.lib.overrideCabal super.cborg {
        version = "0.2.3.0";
        sha256 = "14y7yckj1xzldadyq8g84dgsdaygf9ss0gd38vjfw62smdjq1in8";
      };
      base64-bytestring = pkgs.haskell.lib.overrideCabal super.base64-bytestring {
        version = "1.1.0.0";
        # sha256 = pkgs.lib.fakeSha256;
        sha256 = "1adcnkcx4nh3d59k94bkndj0wkgbvchz576qwlpaa7148a86q391";
      };
    };
  };
  ghc = haskellPackages.ghcWithPackages (import ./nix/haskell-deps.nix);
in
pkgs.mkShell rec {
  name = "fido2-devshell";
  buildInputs = [
    ghc
    pkgs.cabal-install
    pkgs.entr
    pkgs.pkg-config
    pkgs.yarn
  ];
  nativeBuildInputs = [
    pkgs.gmp
    pkgs.ncurses
    pkgs.zlib
  ];
  shellHook = ''
    export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath nativeBuildInputs}:$LD_LIBRARY_PATH
    export NIX_GHC="$(which ghc)"
    export NIX_GHCPKG="$(which ghc-pkg)"
    export NIX_GHC_DOCDIR="$NIX_GHC/../../share/doc/ghc/html"
    export NIX_GHC_LIBDIR="$(ghc --print-libdir)"
  '';
}
