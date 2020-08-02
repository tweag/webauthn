let
  pkgs = (import (import ./nix/sources.nix).nixpkgs) {};
  haskellPackages = pkgs.haskellPackages.override {
    overrides = self: super: {
      fido2 = pkgs.haskell.lib.overrideCabal (super.callPackage ./fido2.nix {}) {
        doCoverage = true;
      };
      cborg = pkgs.haskell.lib.overrideCabal super.cborg {
        version = "0.2.3.0";
        # sha256 = pkgs.lib.fakeSha256;
        sha256 = "14y7yckj1xzldadyq8g84dgsdaygf9ss0gd38vjfw62smdjq1in8";
      };
      base64-bytestring = pkgs.haskell.lib.overrideCabal super.base64-bytestring {
        version = "1.1.0.0";
        # sha256 = pkgs.lib.fakeSha256;
        sha256 = "1adcnkcx4nh3d59k94bkndj0wkgbvchz576qwlpaa7148a86q391";
      };
      scotty = pkgs.haskell.lib.overrideCabal super.scotty {
        version = "0.12";
        # sha256 = pkgs.lib.fakeSha256;
        sha256 = "1lpggpdzgjk23mq7aa64yylds5dbm4ynhcvbarqihjxabvh7xmz1";
      };
    };
  };
in
if pkgs.lib.inNixShell
then haskellPackages.fido2.env.overrideAttrs (
  x: {
    buildInputs = x.buildInputs ++ [
      pkgs.entr
      pkgs.yarn
      pkgs.cabal-install
      pkgs.cabal2nix
      pkgs.fd
      pkgs.ormolu
      pkgs.ghcid
      pkgs.hlint
      haskellPackages.ghcide
    ];
  }
)
else haskellPackages.fido2
