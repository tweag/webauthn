let
  pkgs = (import (import ./nix/sources.nix).nixpkgs) {};
  ghc = pkgs.haskellPackages.ghcWithPackages (import ./nix/haskell-deps.nix);
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
